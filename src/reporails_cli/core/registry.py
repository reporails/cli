"""Rule loading from markdown frontmatter. Pure functions where possible."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.bootstrap import (
    get_agent_config,
    get_project_config,
    get_rules_path,
)
from reporails_cli.core.models import (
    AgentConfig,
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


def _parse_sources_yml(path: Path) -> dict[str, float]:
    """Parse a single sources.yml file into id→weight map."""
    if not path.exists():
        return {}
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not data:
        return {}

    weights: dict[str, float] = {}
    sources_list: list[dict[str, Any]] = []
    if isinstance(data, list):
        sources_list = data
    elif isinstance(data, dict):
        for scope_sources in data.values():
            if isinstance(scope_sources, list):
                sources_list.extend(scope_sources)

    for src in sources_list:
        if isinstance(src, dict) and "id" in src and "weight" in src:
            weights[src["id"]] = src["weight"]
    return weights


def _load_source_weights(
    rules_dir: Path | None = None,
    extra_source_dirs: list[Path] | None = None,
) -> dict[str, float]:
    """Load source weights from sources.yml files.

    Reads from the rules directory and any additional package directories.
    Each package may have its own docs/sources.yml with package-specific sources.

    Args:
        rules_dir: Rules directory (uses default if None)
        extra_source_dirs: Additional directories containing docs/sources.yml

    Returns:
        Dict mapping source ID to weight
    """
    base = rules_dir or get_rules_path()
    weights = _parse_sources_yml(base / "docs" / "sources.yml")

    if extra_source_dirs:
        for pkg_dir in extra_source_dirs:
            weights.update(_parse_sources_yml(pkg_dir / "docs" / "sources.yml"))

    return weights


def derive_tier(backed_by: list[str], source_weights: dict[str, float] | None = None) -> Tier:
    """Derive rule tier from its backing source weights.

    Core: max(backing_source_weights) >= 0.8
    Experimental: max(backing_source_weights) < 0.8 or no backing

    Args:
        backed_by: Source IDs from sources.yml
        source_weights: Pre-loaded weights (avoids repeated file reads)

    Returns:
        Tier.CORE or Tier.EXPERIMENTAL
    """
    if not backed_by:
        return Tier.EXPERIMENTAL

    if source_weights is None:
        source_weights = _load_source_weights()
    max_weight = max(
        (source_weights.get(source_id, 0.0) for source_id in backed_by),
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

    return rules


def load_rules(
    rules_paths: list[Path] | None = None,
    include_experimental: bool = False,
    project_root: Path | None = None,
    agent: str = "",
    scan_root: Path | None = None,
) -> dict[str, Rule]:
    """Load rules from one or more directories, filtered by tier and config.

    Resolution order:
    1. Primary path: core/ and agents/ rules
    2. Additional paths: loaded via _load_from_path (flat scan)
    3. Agent excludes (remove rule IDs)
    4. Agent overrides (adjust check severity, disable checks)
    5. Tier filter (core vs experimental)
    6. disabled_rules removal (merged from project_root + scan_root configs)

    Args:
        rules_paths: List of directories containing rules. First = primary
            framework (provides core/, agents/, docs/sources.yml). Subsequent
            paths = additional rule sources. Defaults to [~/.reporails/rules/].
        include_experimental: If True, include experimental-tier rules
        project_root: Project root for loading project config
        agent: Agent identifier for loading agent config (empty = no agent processing)
        scan_root: Directory being scanned (may differ from project_root in monorepos)

    Returns:
        Dict mapping rule ID to Rule object
    """
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
        rules = {
            k: v for k, v in rules.items()
            if not _is_other_agent_rule(k, agent_prefix)
        }

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
                    severity=Severity(new_severity),
                    type=check.type,
                    name=check.name,
                    check=check.check,
                    args=check.args,
                    negate=check.negate,
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

    weights = _load_source_weights(rules_dir)
    return {k: v for k, v in all_rules.items() if derive_tier(v.backed_by, weights) == Tier.EXPERIMENTAL}


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
    # Parse checks (enriched format with type, check, args)
    checks = []
    for item in frontmatter.get("checks", []):
        check = Check(
            id=item.get("id", ""),
            severity=Severity(item.get("severity", "medium")),
            type=item.get("type", "deterministic"),
            name=item.get("name", ""),
            check=item.get("check"),
            args=item.get("args"),
            negate=item.get("negate", False),
        )
        checks.append(check)

    # Parse backed_by — plain string list (source IDs)
    backed_by: list[str] = []
    for entry in frontmatter.get("backed_by", []):
        if isinstance(entry, str):
            backed_by.append(entry)

    # Parse pattern_confidence
    raw_confidence = frontmatter.get("pattern_confidence")
    pattern_confidence = PatternConfidence(raw_confidence) if raw_confidence else None

    return Rule(
        id=frontmatter["id"],
        title=frontmatter["title"],
        category=Category(frontmatter["category"]),
        type=RuleType(frontmatter["type"]),
        level=frontmatter.get("level", "L2"),
        slug=frontmatter.get("slug", ""),
        targets=frontmatter.get("targets", ""),
        supersedes=frontmatter.get("supersedes"),
        checks=checks,
        sources=frontmatter.get("sources", []),
        see_also=frontmatter.get("see_also", []),
        backed_by=backed_by,
        pattern_confidence=pattern_confidence,
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
