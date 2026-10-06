"""Rule construction from markdown frontmatter. Pure functions where possible."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.platform.dto.models import (
    Category,
    Check,
    Execution,
    FileMatch,
    PatternConfidence,
    Rule,
    RuleType,
    Severity,
)


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
            project_scope=item.get("project_scope", ""),
            convention=item.get("convention", False),
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
            loading_verb=raw.get("loading_verb"),
            link_source_type=raw.get("link_source_type"),
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
        fix=str(frontmatter.get("fix", "") or "").strip(),
        match=_parse_match(frontmatter),
        supersedes=frontmatter.get("supersedes"),
        inherited=frontmatter.get("inherited"),
        depends_on=frontmatter.get("depends_on", []),
        enforcement_required=bool(frontmatter.get("enforcement_required", False)),
        enforcement_mechanism=frontmatter.get("enforcement_mechanism"),
        requires_capability=frontmatter.get("requires_capability"),
        surface_mutations=frontmatter.get("surface_mutations"),
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
