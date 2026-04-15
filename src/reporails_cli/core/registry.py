"""Rule loading and resolution. Loads rules from directories, applies filters and overrides."""

from __future__ import annotations

import logging
from dataclasses import replace
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from reporails_cli.core.bootstrap import (
    get_agent_config,
    get_project_config,
    get_rules_path,
)
from reporails_cli.core.models import (
    AgentConfig,
    ProjectConfig,
    Rule,
    Severity,
)
from reporails_cli.core.rule_builder import (
    CORE_WEIGHT_THRESHOLD as CORE_WEIGHT_THRESHOLD,
)
from reporails_cli.core.rule_builder import (
    build_rule as build_rule,
)
from reporails_cli.core.rule_builder import (
    derive_tier as derive_tier,
)
from reporails_cli.core.rule_builder import (
    get_checks_paths as get_checks_paths,
)
from reporails_cli.core.rule_builder import (
    get_rules_by_category as get_rules_by_category,
)
from reporails_cli.core.rule_builder import (
    get_rules_by_type as get_rules_by_type,
)
from reporails_cli.core.utils import clear_yaml_cache, load_yaml_file, parse_frontmatter

logger = logging.getLogger(__name__)

# Module-level cache for loaded rules — framework rules don't change between
# MCP invocations (only ails update changes them).
_path_cache: dict[str, dict[str, Rule]] = {}


def clear_rule_cache() -> None:
    """Clear the rule loading cache. Called by --refresh and after ails update."""
    _path_cache.clear()
    clear_yaml_cache()


def get_rules_dir() -> Path:
    """Get rules directory (~/.reporails/rules/)."""
    return get_rules_path()


def _load_from_path(path: Path) -> dict[str, Rule]:
    """Load rules from a single directory, returning {id: Rule}.

    Results are cached per path string for MCP performance — framework
    rules don't change between invocations.
    """
    path_key = str(path)
    cached = _path_cache.get(path_key)
    if cached is not None:
        return dict(cached)  # shallow copy to prevent mutation

    rules: dict[str, Rule] = {}

    if not path.exists():
        return rules

    for md_path in path.rglob("rule.md"):
        # Skip test fixtures and deferred (not-yet-ready) rules
        if "tests" in md_path.parts or "_deferred" in md_path.parts:
            continue

        try:
            content = md_path.read_text(encoding="utf-8")
            frontmatter = parse_frontmatter(content)

            if not frontmatter:
                continue

            # Look for corresponding checks.yml file
            checks_yml = md_path.parent / "checks.yml"
            yml_path: Path | None = checks_yml if checks_yml.exists() else None

            # Pre-parse checks.yml so build_rule doesn't re-parse it
            if yml_path is not None and not frontmatter.get("checks"):
                try:
                    yml_data = load_yaml_file(yml_path)
                    frontmatter["checks"] = (yml_data or {}).get("checks", [])
                except Exception:  # rule building from YAML; skip broken rules
                    pass

            rule = build_rule(frontmatter, md_path, yml_path)
            rules[rule.id] = rule

        except (ValueError, KeyError):
            # Skip files without valid frontmatter
            continue

    _path_cache[path_key] = dict(rules)  # cache a copy
    return rules


def load_rules(  # pylint: disable=too-many-locals
    rules_paths: list[Path] | None = None,
    project_root: Path | None = None,
    agent: str = "",
    scan_root: Path | None = None,
) -> dict[str, Rule]:
    """Load rules from directories, filtered by agent and project config."""
    if not rules_paths:
        rules_paths = [get_rules_dir()]

    primary = rules_paths[0]
    extra_paths = rules_paths[1:]

    if not primary.exists():
        return {}

    rules: dict[str, Rule] = {}

    # 1. Load framework rules from primary path (core + selected agent)
    core_path = primary / "core"
    rules.update(_load_from_path(core_path))

    if agent:
        agent_rules_path = primary / agent
        rules.update(_load_from_path(agent_rules_path))

    # 2. Load additional rule sources
    for extra in extra_paths:
        if extra.exists():
            rules.update(_load_from_path(extra))

    # 3-4. Apply agent excludes and overrides
    agent_config = get_agent_config(agent) if agent else AgentConfig()
    if agent_config.excludes:
        rules = {k: v for k, v in rules.items() if not any(fnmatch(k, pat) for pat in agent_config.excludes)}
    if agent_config.overrides:
        rules = _apply_agent_overrides(rules, agent_config.overrides)

    # 4b. Filter rules by agent namespace
    if agent:
        agent_prefix = agent_config.prefix or agent.upper()
        rules = {k: v for k, v in rules.items() if not _is_other_agent_rule(k, agent_prefix)}

    # 5. Remove disabled rules (merge from project_root + scan_root configs)
    config = _load_project_config(project_root)
    disabled: set[str] = set(config.disabled_rules or [])
    if scan_root and scan_root != project_root:
        scan_config = _load_project_config(scan_root)
        disabled |= set(scan_config.disabled_rules or [])
    if disabled:
        rules = {k: v for k, v in rules.items() if k not in disabled}

    return rules


_AGNOSTIC_PREFIXES = frozenset({"CORE", "RRAILS"})


def infer_agent_from_rule_id(rule_id: str) -> str:
    """Infer agent name from a rule ID prefix.

    Returns lowercase agent name for agent-specific rules (e.g., "claude"
    for CLAUDE:S:0001), empty string for CORE/RRAILS rules.
    """
    prefix = rule_id.split(":")[0] if ":" in rule_id else ""
    if not prefix or prefix in _AGNOSTIC_PREFIXES:
        return ""
    return prefix.lower()


def _is_other_agent_rule(rule_id: str, agent_prefix: str) -> bool:
    """Check if a rule belongs to a different agent.

    Agent-agnostic namespaces (CORE, RRAILS) are always kept.
    Agent-specific namespaces (CLAUDE, CODEX, RRAILS_CLAUDE, etc.)
    are kept only if they contain the selected agent's prefix.
    """
    namespace = rule_id.split(":")[0]
    if namespace in ("CORE", "RRAILS"):
        return False
    return agent_prefix not in namespace


def _apply_agent_overrides(
    rules: dict[str, Rule],
    overrides: dict[str, dict[str, Any]],
) -> dict[str, Rule]:
    """Apply agent overrides: severity at rule level, disabled at check level."""
    result = {}
    for rule_id, rule in rules.items():
        # Rule-level severity override (keyed by rule_id)
        rule_override = overrides.get(rule_id)
        new_rule = rule
        if rule_override:
            new_severity = rule_override.get("severity")
            if new_severity:
                try:
                    parsed_severity = Severity(new_severity)
                    new_rule = replace(new_rule, severity=parsed_severity)
                except ValueError:
                    logger.warning("Invalid severity '%s' in override for %s, skipping", new_severity, rule_id)

        # Check-level overrides: only handle disabled
        new_checks = []
        for check in new_rule.checks:
            override = overrides.get(check.id)
            if override is not None and override.get("disabled", False):
                continue  # Drop this check
            # Legacy: check-level severity override → lift to rule
            if override and not rule_override:
                check_severity = override.get("severity")
                if check_severity:
                    try:
                        parsed_severity = Severity(check_severity)
                        new_rule = replace(new_rule, severity=parsed_severity)
                    except ValueError:
                        pass
            new_checks.append(check)
        result[rule_id] = replace(new_rule, checks=new_checks)
    return result


def _load_project_config(project_root: Path | None) -> ProjectConfig:
    """Load project config, returning defaults when project_root is None."""
    if project_root is None:
        return ProjectConfig()
    return get_project_config(project_root)
