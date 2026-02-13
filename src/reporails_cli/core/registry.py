"""Rule loading and resolution. Loads rules from directories, applies filters and overrides."""

from __future__ import annotations

import logging
from dataclasses import replace
from pathlib import Path
from typing import Any

from reporails_cli.core.bootstrap import (
    get_agent_config,
    get_project_config,
    get_rules_path,
)
from reporails_cli.core.models import (
    AgentConfig,
    Check,
    ProjectConfig,
    Rule,
    Severity,
    Tier,
)
from reporails_cli.core.rule_builder import (
    CORE_WEIGHT_THRESHOLD as CORE_WEIGHT_THRESHOLD,
)
from reporails_cli.core.rule_builder import (
    _load_source_weights,
)
from reporails_cli.core.rule_builder import (
    build_rule as build_rule,
)
from reporails_cli.core.rule_builder import (
    derive_tier as derive_tier,
)
from reporails_cli.core.rule_builder import (
    get_rule_yml_paths as get_rule_yml_paths,
)
from reporails_cli.core.rule_builder import (
    get_rules_by_category as get_rules_by_category,
)
from reporails_cli.core.rule_builder import (
    get_rules_by_type as get_rules_by_type,
)
from reporails_cli.core.utils import parse_frontmatter

logger = logging.getLogger(__name__)

# Module-level cache for loaded rules — framework rules don't change between
# MCP invocations (only ails update changes them).
_path_cache: dict[str, dict[str, Rule]] = {}


def clear_rule_cache() -> None:
    """Clear the rule loading cache. Called by --refresh and after ails update."""
    _path_cache.clear()


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
        # Skip test fixtures (tests/pass/, tests/fail/ directories)
        if "tests" in md_path.parts:
            continue

        try:
            content = md_path.read_text(encoding="utf-8")
            frontmatter = parse_frontmatter(content)

            if not frontmatter:
                continue

            # Look for corresponding .yml file
            yml_path_candidate = md_path.with_suffix(".yml")
            yml_path: Path | None = yml_path_candidate if yml_path_candidate.exists() else None

            rule = build_rule(frontmatter, md_path, yml_path)
            rules[rule.id] = rule

        except (ValueError, KeyError):
            # Skip files without valid frontmatter
            continue

    _path_cache[path_key] = dict(rules)  # cache a copy
    return rules


def load_rules(  # pylint: disable=too-many-locals
    rules_paths: list[Path] | None = None,
    include_experimental: bool = False,
    project_root: Path | None = None,
    agent: str = "",
    scan_root: Path | None = None,
) -> dict[str, Rule]:
    """Load rules from directories, filtered by tier, agent, and project config."""
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
        agent_rules_path = primary / "agents" / agent / "rules"
        rules.update(_load_from_path(agent_rules_path))
    else:
        agents_path = primary / "agents"
        rules.update(_load_from_path(agents_path))

    # 2. Load additional rule sources
    for extra in extra_paths:
        if extra.exists():
            rules.update(_load_from_path(extra))

    # 3-4. Apply agent excludes and overrides
    agent_config = get_agent_config(agent) if agent else AgentConfig()
    if agent_config.excludes:
        excluded = set(agent_config.excludes)
        rules = {k: v for k, v in rules.items() if k not in excluded}
    if agent_config.overrides:
        rules = _apply_agent_overrides(rules, agent_config.overrides)

    # 4b. Filter rules by agent namespace
    if agent:
        agent_prefix = agent.upper()
        rules = {k: v for k, v in rules.items() if not _is_other_agent_rule(k, agent_prefix)}

    # 5. Filter by tier if experimental not included
    if not include_experimental:
        weights = _load_source_weights(primary, extra_paths or None)
        rules = {k: v for k, v in rules.items() if derive_tier(v.backed_by, weights) == Tier.CORE}

    # 6. Remove disabled rules (merge from project_root + scan_root configs)
    config = _load_project_config(project_root)
    disabled: set[str] = set(config.disabled_rules)
    if scan_root and scan_root != project_root:
        scan_config = _load_project_config(scan_root)
        disabled |= set(scan_config.disabled_rules)
    if disabled:
        rules = {k: v for k, v in rules.items() if k not in disabled}

    return rules


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
    """Apply agent check-level overrides (severity, disabled)."""
    result = {}
    for rule_id, rule in rules.items():
        new_checks = []
        for check in rule.checks:
            override = overrides.get(check.id)
            if override is None:
                new_checks.append(check)
                continue
            if override.get("disabled", False):
                continue  # Drop this check
            new_severity = override.get("severity")
            if new_severity:
                try:
                    parsed_severity = Severity(new_severity)
                except ValueError:
                    logger.warning("Invalid severity '%s' in override for %s, skipping", new_severity, check.id)
                    new_checks.append(check)
                    continue
                new_checks.append(
                    Check(
                        id=check.id,
                        severity=parsed_severity,
                        type=check.type,
                        name=check.name,
                        check=check.check,
                        args=check.args,
                        negate=check.negate,
                    )
                )
            else:
                new_checks.append(check)
        result[rule_id] = replace(rule, checks=new_checks)
    return result


def _load_project_config(project_root: Path | None) -> ProjectConfig:
    """Load project config, returning defaults when project_root is None."""
    if project_root is None:
        return ProjectConfig()
    return get_project_config(project_root)


def get_experimental_rules(rules_dir: Path | None = None) -> dict[str, Rule]:
    """Get experimental-tier rules (skipped when experimental is disabled)."""
    if rules_dir is None:
        rules_dir = get_rules_dir()

    if not rules_dir.exists():
        return {}

    # Load all rules, then filter to experimental only
    all_rules: dict[str, Rule] = {}

    core_path = rules_dir / "core"
    all_rules.update(_load_from_path(core_path))

    agents_path = rules_dir / "agents"
    all_rules.update(_load_from_path(agents_path))

    weights = _load_source_weights(rules_dir)
    return {k: v for k, v in all_rules.items() if derive_tier(v.backed_by, weights) == Tier.EXPERIMENTAL}
