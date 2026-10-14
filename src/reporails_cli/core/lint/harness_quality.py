"""Quality reporting over discovered rules — structural lint and coverage baseline.

The harness's upper layer: it consumes the ``RuleInfo`` list from
``harness_discovery`` and produces the structural-lint errors and
coverage-baseline entries the ``ails test`` command surfaces. It depends on
the models + discovery, never on the run/batch stages, so it stays a leaf of
the harness split.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.lint.harness_discovery import discover_agent_rules
from reporails_cli.core.lint.harness_models import (
    BaselineEntry,
    CoverageGap,
    LintError,
    RuleInfo,
)
from reporails_cli.core.platform.dto.models import CATEGORY_CODES
from reporails_cli.core.platform.utils.utils import read_frontmatter

# ── Rule lint ───────────────────────────────────────────────────────


def _lint_single_rule(
    rule: RuleInfo,
    seen_ids: dict[str, Path],
    category_codes: dict[str, Any],
) -> list[LintError]:
    """Run lint checks on a single rule. Mutates seen_ids for duplicate tracking."""
    errors: list[LintError] = []

    # 1. ID-category match
    parts = rule.rule_id.split(":")
    if len(parts) >= 3:
        cat_code = parts[1]
        expected_cat = category_codes.get(cat_code)
        if expected_cat is None:
            errors.append(
                LintError(
                    rule_id=rule.rule_id,
                    check_name="id_category_match",
                    message=f"Unknown category code '{cat_code}' in rule ID",
                )
            )
        elif expected_cat.value != rule.category:
            errors.append(
                LintError(
                    rule_id=rule.rule_id,
                    check_name="id_category_match",
                    message=(
                        f"ID has category code '{cat_code}' ({expected_cat.value}) "
                        f"but category field is '{rule.category}'"
                    ),
                )
            )

    # 2. Check ID prefix
    expected_prefix = rule.rule_id.replace(":", ".")
    for check in rule.checks:
        check_id = check.id
        if check_id and not check_id.startswith(expected_prefix + "."):
            errors.append(
                LintError(
                    rule_id=rule.rule_id,
                    check_name="check_id_prefix",
                    message=f"Check '{check_id}' does not start with '{expected_prefix}.'",
                )
            )

    # 3. No duplicate rule IDs
    if rule.rule_id in seen_ids:
        errors.append(
            LintError(
                rule_id=rule.rule_id,
                check_name="duplicate_rule_id",
                message=f"Duplicate rule ID (also at {seen_ids[rule.rule_id]})",
            )
        )
    else:
        seen_ids[rule.rule_id] = rule.rule_dir

    # 4. Required frontmatter
    for field_name, value in [
        ("id", rule.rule_id),
        ("slug", rule.slug),
        ("title", rule.title),
        ("category", rule.category),
        ("type", rule.rule_type),
    ]:
        if not value:
            errors.append(
                LintError(
                    rule_id=rule.rule_id or "(unknown)",
                    check_name="required_frontmatter",
                    message=f"Missing required field: {field_name}",
                )
            )

    # Severity + enforcement-partner gap require re-reading frontmatter (not stored in RuleInfo)
    rule_md = rule.rule_dir / "rule.md"
    if rule_md.exists():
        read = read_frontmatter(rule_md.read_text(encoding="utf-8"))
        meta = read.data
        if meta and not meta.get("severity"):
            errors.append(
                LintError(
                    rule_id=rule.rule_id or "(unknown)",
                    check_name="required_frontmatter",
                    message="Missing required field: severity",
                )
            )
        # 5. Enforcement-partner gap — a rule that declares its concern needs an out-of-band
        # enforcement partner (`enforcement_required: true`) must name that partner in
        # `enforcement_mechanism`; a lint finding alone cannot make the concern stick, and an
        # unnamed mechanism leaves the gap the field exists to close.
        if meta and meta.get("enforcement_required") and not meta.get("enforcement_mechanism"):
            errors.append(
                LintError(
                    rule_id=rule.rule_id or "(unknown)",
                    check_name="enforcement_partner",
                    message=(
                        "Declares enforcement_required: true but names no enforcement_mechanism "
                        "partner (hook | permission | ci | managed_settings | static_analysis)"
                    ),
                )
            )

    return errors


def lint_rules(rules: list[RuleInfo]) -> list[LintError]:
    """Run structural integrity checks on all discovered rules.

    Checks:
    1. ID-category match — category code in rule ID matches category field
    2. Check ID prefix — all check IDs start with the dotted rule ID prefix
    3. No duplicate rule IDs — across all namespaces
    4. Required frontmatter — id, slug, title, category, type, severity present
    5. Enforcement-partner gap — enforcement_required: true must name an enforcement_mechanism
    """
    errors: list[LintError] = []
    seen_ids: dict[str, Path] = {}

    for rule in rules:
        if rule.load_error:
            errors.append(LintError(rule_id=rule.rule_id, check_name="checks_schema", message=rule.load_error))
        errors.extend(_lint_single_rule(rule, seen_ids, CATEGORY_CODES))

    return errors


# ── Coverage baseline ──────────────────────────────────────────────


def export_baseline(
    rules_root: Path,
    *,
    package_roots: list[Path] | None = None,
    agent: str = "claude",
) -> list[BaselineEntry]:
    """Export all discovered rule coordinates as a baseline.

    Args:
        rules_root: Primary rules repository root.
        package_roots: Additional package roots to scan.
        agent: Agent config for var resolution.
    """
    rules = discover_agent_rules(rules_root, agent, package_roots=package_roots)

    return [
        BaselineEntry(
            rule_id=r.rule_id,
            slug=r.slug,
            has_fixtures=r.has_pass_fixture or r.has_fail_fixture or r.has_cases,
        )
        for r in rules
    ]


def check_coverage(
    rules_root: Path,
    baseline: list[dict[str, Any]],
    *,
    package_roots: list[Path] | None = None,
    agent: str = "claude",
) -> list[CoverageGap]:
    """Check current rules against an expected-rules baseline.

    Args:
        rules_root: Primary rules repository root.
        baseline: List of baseline entries (dicts with rule_id, slug, has_fixtures).
        package_roots: Additional package roots to scan.
        agent: Agent config for var resolution.

    Returns:
        List of gaps (missing rules or rules without fixtures).
    """
    rules = discover_agent_rules(rules_root, agent, package_roots=package_roots)

    current_ids = {r.rule_id for r in rules}
    current_map = {r.rule_id: r for r in rules}

    gaps: list[CoverageGap] = []
    for entry in baseline:
        rule_id = entry["rule_id"]
        if rule_id not in current_ids:
            gaps.append(CoverageGap(rule_id=rule_id, reason="missing"))
        elif entry.get("has_fixtures") and not (
            current_map[rule_id].has_pass_fixture
            or current_map[rule_id].has_fail_fixture
            or current_map[rule_id].has_cases
        ):
            gaps.append(CoverageGap(rule_id=rule_id, reason="fixtures removed"))

    return gaps
