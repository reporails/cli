"""Rule construction from markdown frontmatter. Pure functions where possible."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.bootstrap import get_framework_root
from reporails_cli.core.models import (
    Category,
    Check,
    Execution,
    FileMatch,
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
    base = rules_dir or get_framework_root()
    candidates = [
        base / "docs" / "sources.yml",  # installed mode: docs/ alongside rules
        base.parent / "docs" / "sources.yml",  # legacy: rules_dir is rules/, docs at parent
        base / "sources.yml",  # bundled: sources.yml at package root
        base.parent / "sources.yml",  # bundled: rules_dir is rules/, sources.yml at parent
    ]
    sources_path = next((p for p in candidates if p.exists()), candidates[0])
    weights = _parse_sources_yml(sources_path)

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


def _load_checks(frontmatter: dict[str, Any]) -> list[Check]:
    """Load check entries from frontmatter (pre-populated by registry from checks.yml)."""
    return [
        Check(
            id=item.get("id", ""),
            type=item.get("type", "deterministic"),
            check=item.get("check"),
            args=item.get("args"),
            query=item.get("query"),
            expect=item.get("expect", "present"),
            metadata_keys=item.get("metadata_keys", []),
            replaces=item.get("replaces", ""),
            severity=item.get("severity", ""),
            message=item.get("message", ""),
        )
        for item in frontmatter.get("checks", [])
    ]


def _parse_severity(frontmatter: dict[str, Any]) -> Severity:
    """Parse rule-level severity from frontmatter or legacy check-level severity."""
    raw = frontmatter.get("severity")
    if not raw:
        raw_checks = frontmatter.get("checks", [])
        if raw_checks:
            raw = raw_checks[0].get("severity")
    return Severity(raw) if raw else Severity.MEDIUM


def _parse_match(frontmatter: dict[str, Any]) -> FileMatch | None:
    """Parse property-based file targeting from frontmatter."""
    raw = frontmatter.get("match")
    if isinstance(raw, dict):
        return FileMatch(
            type=raw.get("type"),
            scope=raw.get("scope"),
            format=raw.get("format"),
            content_format=raw.get("content_format"),
            cardinality=raw.get("cardinality"),
            lifecycle=raw.get("lifecycle"),
            maintainer=raw.get("maintainer"),
            vcs=raw.get("vcs"),
            loading=raw.get("loading"),
            precedence=raw.get("precedence"),
        )
    if raw is not None:
        # Empty match (match: {}) parsed as None by YAML — treat as match-all
        return FileMatch()
    return None


def build_rule(frontmatter: dict[str, Any], md_path: Path, yml_path: Path | None) -> Rule:
    """Build Rule from parsed frontmatter. Raises KeyError/ValueError on bad input."""
    raw_confidence = frontmatter.get("pattern_confidence")
    raw_execution = frontmatter.get("execution", "local")

    return Rule(
        id=frontmatter["id"],
        title=frontmatter["title"],
        category=Category(frontmatter["category"]),
        type=RuleType(frontmatter["type"]),
        severity=_parse_severity(frontmatter),
        slug=frontmatter.get("slug", ""),
        execution=Execution(raw_execution),
        match=_parse_match(frontmatter),
        supersedes=frontmatter.get("supersedes"),
        inherited=frontmatter.get("inherited"),
        depends_on=frontmatter.get("depends_on", []),
        checks=_load_checks(frontmatter),
        sources=frontmatter.get("sources", []),
        see_also=frontmatter.get("see_also", []),
        backed_by=[e for e in frontmatter.get("backed_by", []) if isinstance(e, str)],
        pattern_confidence=PatternConfidence(raw_confidence) if raw_confidence else None,
        md_path=md_path,
        yml_path=yml_path,
    )


def get_rules_by_type(rules: dict[str, Rule], rule_type: RuleType) -> dict[str, Rule]:
    """Filter rules by type."""
    return {k: v for k, v in rules.items() if v.type == rule_type}


def get_rules_by_category(rules: dict[str, Rule], category: Category) -> dict[str, Rule]:
    """Filter rules by category."""
    return {k: v for k, v in rules.items() if v.category == category}


def get_checks_paths(rules: dict[str, Rule]) -> list[Path]:
    """Get checks.yml paths for rules that have them."""
    return [r.yml_path for r in rules.values() if r.yml_path is not None]
