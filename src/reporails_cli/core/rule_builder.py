"""Rule construction from markdown frontmatter. Pure functions where possible."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.bootstrap import get_rules_path
from reporails_cli.core.models import (
    Category,
    Check,
    PatternConfidence,
    Rule,
    RuleType,
    Severity,
    Tier,
)

# Threshold for core tier (from sources.schema.yml tier_derivation)
CORE_WEIGHT_THRESHOLD = 0.8


def _parse_sources_yml(path: Path) -> dict[str, float]:
    """Parse a single sources.yml file into id->weight map."""
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
    """Load source weights from sources.yml in rules dir and extra packages."""
    base = rules_dir or get_rules_path()
    weights = _parse_sources_yml(base / "docs" / "sources.yml")

    if extra_source_dirs:
        for pkg_dir in extra_source_dirs:
            weights.update(_parse_sources_yml(pkg_dir / "docs" / "sources.yml"))

    return weights


def derive_tier(backed_by: list[str], source_weights: dict[str, float] | None = None) -> Tier:
    """Derive rule tier (CORE/EXPERIMENTAL) from backing source weights."""
    if not backed_by:
        return Tier.EXPERIMENTAL

    if source_weights is None:
        source_weights = _load_source_weights()
    max_weight = max(
        (source_weights.get(source_id, 0.0) for source_id in backed_by),
        default=0.0,
    )

    return Tier.CORE if max_weight >= CORE_WEIGHT_THRESHOLD else Tier.EXPERIMENTAL


def build_rule(frontmatter: dict[str, Any], md_path: Path, yml_path: Path | None) -> Rule:
    """Build Rule from parsed frontmatter. Raises KeyError/ValueError on bad input."""
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
            metadata_keys=item.get("metadata_keys", []),
        )
        checks.append(check)

    # Parse backed_by — plain string list (source IDs)
    backed_by: list[str] = [entry for entry in frontmatter.get("backed_by", []) if isinstance(entry, str)]

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
    """Filter rules by type."""
    return {k: v for k, v in rules.items() if v.type == rule_type}


def get_rules_by_category(rules: dict[str, Rule], category: Category) -> dict[str, Rule]:
    """Filter rules by category."""
    return {k: v for k, v in rules.items() if v.category == category}


def get_rule_yml_paths(rules: dict[str, Rule]) -> list[Path]:
    """Get .yml paths for rules that have them."""
    return [r.yml_path for r in rules.values() if r.yml_path is not None]
