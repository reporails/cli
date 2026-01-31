"""Rule loading from markdown frontmatter. Pure functions where possible."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.bootstrap import get_agent_config, get_package_paths, get_project_config, get_rules_path
from reporails_cli.core.models import (
    AgentConfig,
    BackedByEntry,
    Category,
    Check,
    PatternConfidence,
    ProjectConfig,
    Rule,
    RuleType,
    Severity,
    Tier,
)
from reporails_cli.core.utils import parse_frontmatter

# Threshold for core tier (from sources.schema.yml tier_derivation)
CORE_WEIGHT_THRESHOLD = 0.8


def get_rules_dir() -> Path:
    """Get rules directory (~/.reporails/rules/).

    Returns:
        Path to rules directory
    """
    return get_rules_path()


@lru_cache(maxsize=1)
def _load_source_weights() -> dict[str, float]:
    """Load source weights from downloaded sources.yml.

    Returns:
        Dict mapping source ID to weight
    """
    sources_path = get_rules_path() / "docs" / "sources.yml"
    if not sources_path.exists():
        return {}

    content = sources_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content) or {}

    weights: dict[str, float] = {}
    for scope_sources in data.values():
        if isinstance(scope_sources, list):
            for src in scope_sources:
                if isinstance(src, dict) and "id" in src and "weight" in src:
                    weights[src["id"]] = src["weight"]

    return weights


def derive_tier(backed_by: list[BackedByEntry]) -> Tier:
    """Derive rule tier from its backing source weights.

    Core: max(backing_source_weights) >= 0.8
    Experimental: max(backing_source_weights) < 0.8 or no backing

    Args:
        backed_by: Rule's backed_by entries

    Returns:
        Tier.CORE or Tier.EXPERIMENTAL
    """
    if not backed_by:
        return Tier.EXPERIMENTAL

    source_weights = _load_source_weights()
    max_weight = max(
        (source_weights.get(entry.source, 0.0) for entry in backed_by),
        default=0.0,
    )

    return Tier.CORE if max_weight >= CORE_WEIGHT_THRESHOLD else Tier.EXPERIMENTAL


def _load_from_path(path: Path) -> dict[str, Rule]:
    """Load rules from a single path.

    Internal helper for load_rules.

    Args:
        path: Directory containing rules

    Returns:
        Dict mapping rule ID to Rule object
    """
    rules: dict[str, Rule] = {}

    if not path.exists():
        return rules

    for md_path in path.rglob("*.md"):
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

    return rules


def load_rules(
    rules_dir: Path | None = None,
    include_experimental: bool = False,
    project_root: Path | None = None,
    agent: str = "",
) -> dict[str, Rule]:
    """Load rules from framework, project packages, filtered by tier and config.

    Resolution order:
    1. Framework core/ and agents/ rules
    2. Agent excludes (remove rule IDs)
    3. Agent overrides (adjust check severity, disable checks)
    4. Project packages (.reporails/packages/<name>/) — override by rule ID
    5. Tier filter (core vs experimental)
    6. disabled_rules removal

    Args:
        rules_dir: Path to rules directory (default: ~/.reporails/rules/)
        include_experimental: If True, include experimental-tier rules
        project_root: Project root for loading project config and packages
        agent: Agent identifier for loading agent config (empty = no agent processing)

    Returns:
        Dict mapping rule ID to Rule object
    """
    if rules_dir is None:
        rules_dir = get_rules_dir()

    if not rules_dir.exists():
        return {}

    rules: dict[str, Rule] = {}

    # 1. Load framework rules (core + agents)
    core_path = rules_dir / "core"
    rules.update(_load_from_path(core_path))

    agents_path = rules_dir / "agents"
    rules.update(_load_from_path(agents_path))

    # 2-3. Apply agent excludes and overrides
    agent_config = get_agent_config(agent) if agent else AgentConfig()
    if agent_config.excludes:
        excluded = set(agent_config.excludes)
        rules = {k: v for k, v in rules.items() if k not in excluded}
    if agent_config.overrides:
        rules = _apply_agent_overrides(rules, agent_config.overrides)

    # 4. Load project packages (override framework rules by ID)
    config = _load_project_config(project_root)
    for pkg_path in get_package_paths(project_root or Path(), config.packages):
        rules.update(_load_from_path(pkg_path))

    # 5. Filter by tier if experimental not included
    if not include_experimental:
        rules = {k: v for k, v in rules.items() if derive_tier(v.backed_by) == Tier.CORE}

    # 6. Remove disabled rules
    if config.disabled_rules:
        disabled = set(config.disabled_rules)
        rules = {k: v for k, v in rules.items() if k not in disabled}

    return rules


def _apply_agent_overrides(
    rules: dict[str, Rule],
    overrides: dict[str, dict[str, Any]],
) -> dict[str, Rule]:
    """Apply agent check-level overrides (severity, disabled).

    Args:
        rules: Current rule set
        overrides: Map of check ID to override dict (severity, disabled)

    Returns:
        Modified rule set with overrides applied
    """
    for rule in rules.values():
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
                new_checks.append(Check(
                    id=check.id,
                    name=check.name,
                    severity=Severity(new_severity),
                ))
            else:
                new_checks.append(check)
        rule.checks = new_checks
    return rules


def _load_project_config(project_root: Path | None) -> ProjectConfig:
    """Load project config, returning defaults when project_root is None.

    Args:
        project_root: Project root path, or None

    Returns:
        ProjectConfig (defaults if project_root is None or config missing)
    """
    if project_root is None:
        return ProjectConfig()
    return get_project_config(project_root)


def get_experimental_rules(rules_dir: Path | None = None) -> dict[str, Rule]:
    """Get rules with experimental tier.

    Used to report which rules were skipped when experimental is disabled.

    Args:
        rules_dir: Path to rules directory (default: ~/.reporails/rules/)

    Returns:
        Dict mapping rule ID to Rule object (experimental tier only)
    """
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

    return {k: v for k, v in all_rules.items() if derive_tier(v.backed_by) == Tier.EXPERIMENTAL}


def build_rule(frontmatter: dict[str, Any], md_path: Path, yml_path: Path | None) -> Rule:
    """Build Rule object from parsed frontmatter.

    Pure function — validates and constructs.

    Args:
        frontmatter: Parsed YAML dict
        md_path: Path to source .md file
        yml_path: Path to .yml file (optional)

    Returns:
        Rule object

    Raises:
        KeyError: If required fields missing
        ValueError: If field values invalid
    """
    # Parse checks (formerly antipatterns)
    checks = []
    # Support both "checks" and legacy "antipatterns" field names
    check_data = frontmatter.get("checks", frontmatter.get("antipatterns", []))
    for item in check_data:
        check = Check(
            id=item.get("id", ""),
            name=item.get("name", ""),
            severity=Severity(item.get("severity", "medium")),
        )
        checks.append(check)

    # Parse backed_by entries
    backed_by = []
    for entry in frontmatter.get("backed_by", []):
        if isinstance(entry, dict) and "source" in entry and "claim" in entry:
            backed_by.append(BackedByEntry(source=entry["source"], claim=entry["claim"]))

    # Parse pattern_confidence
    raw_confidence = frontmatter.get("pattern_confidence")
    pattern_confidence = PatternConfidence(raw_confidence) if raw_confidence else None

    return Rule(
        id=frontmatter["id"],
        title=frontmatter["title"],
        category=Category(frontmatter["category"]),
        type=RuleType(frontmatter["type"]),
        level=frontmatter.get("level", "L2"),  # Default to L2 (Basic) if not specified
        checks=checks,
        detection=frontmatter.get("detection"),
        sources=frontmatter.get("sources", []),
        see_also=frontmatter.get("see_also", []),
        backed_by=backed_by,
        pattern_confidence=pattern_confidence,
        scoring=frontmatter.get("scoring", 0),
        validation=frontmatter.get("validation"),
        question=frontmatter.get("question"),
        criteria=frontmatter.get("criteria"),
        choices=frontmatter.get("choices"),
        pass_value=frontmatter.get("pass_value"),
        examples=frontmatter.get("examples"),
        md_path=md_path,
        yml_path=yml_path,
    )


def get_rules_by_type(rules: dict[str, Rule], rule_type: RuleType) -> dict[str, Rule]:
    """Filter rules by type.

    Pure function.

    Args:
        rules: Dict of rules
        rule_type: Type to filter by

    Returns:
        Filtered dict of rules
    """
    return {k: v for k, v in rules.items() if v.type == rule_type}


def get_rules_by_category(rules: dict[str, Rule], category: Category) -> dict[str, Rule]:
    """Filter rules by category.

    Pure function.

    Args:
        rules: Dict of rules
        category: Category to filter by

    Returns:
        Filtered dict of rules
    """
    return {k: v for k, v in rules.items() if v.category == category}


def get_rule_yml_paths(rules: dict[str, Rule]) -> list[Path]:
    """Get list of .yml paths for rules that have them.

    Pure function.

    Args:
        rules: Dict of rules

    Returns:
        List of paths to .yml files
    """
    return [r.yml_path for r in rules.values() if r.yml_path is not None]
