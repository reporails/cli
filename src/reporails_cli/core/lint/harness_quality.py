"""Quality reporting over discovered rules — scoring, lint, coverage baseline.

The harness's upper layer: it consumes the ``RuleInfo`` list from
``harness_discovery`` and produces the effectiveness deltas, structural-lint
errors, and coverage-baseline entries the ``ails test`` command surfaces. It
depends on the models + discovery, never on the run/batch stages, so it stays a
leaf of the harness split.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reporails_cli.core.lint.harness_discovery import discover_rules, load_agent_config
from reporails_cli.core.lint.harness_models import (
    BaselineEntry,
    CoverageGap,
    LintError,
    RuleInfo,
    ScoreDelta,
)
from reporails_cli.core.platform.utils.utils import read_frontmatter

logger = logging.getLogger(__name__)


def score_fixture(
    fixture_dir: Path,  # noqa: ARG001
    rules_paths: list[Path],  # noqa: ARG001
) -> float:
    """Run full validation scoring on a fixture directory.

    Returns 0.0 — scoring pending pipeline rewrite (0.5.0).
    """
    logger.warning("score_fixture: scoring disabled pending 0.5.0 pipeline rewrite")
    return 0.0


def score_rules(
    rules_root: Path,
    *,
    filter_path: str | None = None,
    filter_rule: str | None = None,
    package_roots: list[Path] | None = None,
    agent: str = "claude",
) -> list[ScoreDelta]:
    """Score pass/fail fixtures for all rules, returning quality deltas.

    Args:
        rules_root: Primary rules repository root.
        filter_path: Optional path prefix filter.
        filter_rule: Optional rule coordinate filter.
        package_roots: Additional package roots to scan.
        agent: Agent config for var resolution.
    """
    _, excludes = load_agent_config(rules_root, agent)
    rules = discover_rules(
        rules_root,
        filter_path=filter_path,
        filter_rule=filter_rule,
        package_roots=package_roots,
        excludes=excludes,
        agent=agent,
    )

    # Collect all rules_paths for scoring
    all_roots = [rules_root]
    if package_roots:
        all_roots.extend(package_roots)

    deltas: list[ScoreDelta] = []
    for rule in rules:
        pass_dir = rule.rule_dir / "tests" / "pass"
        fail_dir = rule.rule_dir / "tests" / "fail"

        if not rule.has_pass_fixture or not rule.has_fail_fixture:
            continue

        pass_score = score_fixture(pass_dir, all_roots)
        fail_score = score_fixture(fail_dir, all_roots)
        deltas.append(
            ScoreDelta(
                rule_id=rule.rule_id,
                slug=rule.slug,
                pass_score=round(pass_score, 1),
                fail_score=round(fail_score, 1),
                delta=round(pass_score - fail_score, 1),
            )
        )

    return deltas


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
    from reporails_cli.core.platform.dto.models import CATEGORY_CODES

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
    _, excludes = load_agent_config(rules_root, agent)
    rules = discover_rules(
        rules_root,
        package_roots=package_roots,
        excludes=excludes,
        agent=agent,
    )

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
    _, excludes = load_agent_config(rules_root, agent)
    rules = discover_rules(
        rules_root,
        package_roots=package_roots,
        excludes=excludes,
        agent=agent,
    )

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
