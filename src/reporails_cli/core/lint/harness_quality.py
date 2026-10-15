"""Quality reporting over discovered rules — structural lint and coverage baseline.

The harness's upper layer: it consumes the ``RuleInfo`` list from
``harness_discovery`` and produces the structural-lint errors and
coverage-baseline entries the ``ails test`` command surfaces. It depends on
the models + discovery, never on the run/batch stages, so it stays a leaf of
the harness split.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.lint.harness_discovery import discover_agent_rules
from reporails_cli.core.lint.harness_models import (
    BaselineEntry,
    CoverageGap,
    LintError,
    RuleInfo,
)
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.models import CATEGORY_CODES, Category

# ── Rule lint ───────────────────────────────────────────────────────


def _duplicate_id_errors(rule: RuleInfo, seen_ids: dict[str, Path]) -> list[LintError]:
    """The duplicate-id finding for `rule`; records its dir otherwise. A rule with no readable id has none to repeat."""
    if not rule.rule_id:
        return []
    if rule.rule_id in seen_ids:
        message = f"Duplicate rule ID (also at {seen_ids[rule.rule_id]})"
        return [LintError(rule_id=rule.rule_id, check_name="duplicate_rule_id", message=message)]
    seen_ids[rule.rule_id] = rule.rule_dir
    return []


def _id_category_errors(rule: RuleInfo, category_codes: dict[str, Category]) -> list[LintError]:
    """The finding when the category code in the rule id disagrees with the declared category."""
    parts = rule.rule_id.split(":")
    if len(parts) < 3:
        return []
    cat_code = parts[1]
    expected_cat = category_codes.get(cat_code)
    if expected_cat is None:
        message = f"Unknown category code '{cat_code}' in rule ID"
    elif expected_cat.value != rule.category:
        message = f"ID has category code '{cat_code}' ({expected_cat.value}) but category field is '{rule.category}'"
    else:
        return []
    return [LintError(rule_id=rule.rule_id, check_name="id_category_match", message=message)]


def _check_prefix_errors(rule: RuleInfo) -> list[LintError]:
    """One finding per check whose id does not start with the dotted rule id; none without a usable rule id."""
    if not rule.rule_id or "id" in rule.rejected_fields:
        return []
    expected_prefix = rule.rule_id.replace(":", ".")
    return [
        LintError(
            rule_id=rule.rule_id,
            check_name="check_id_prefix",
            message=f"Check '{check.id}' does not start with '{expected_prefix}.'",
        )
        for check in rule.checks
        if check.id and not check.id.startswith(expected_prefix + ".")
    ]


_PROBLEM_CHECK_NAMES = {"missing": "required_frontmatter", "invalid": "invalid_frontmatter"}


def _field_problem_errors(rule: RuleInfo, subject: str) -> list[LintError]:
    """One finding per rule.md field the build rejected, labelled by whether it is missing or invalid."""
    return [
        LintError(
            rule_id=subject,
            check_name=_PROBLEM_CHECK_NAMES[p.kind],
            message=f"{rule.rule_md_label}: {p.field}: {p.message}",
        )
        for p in rule.field_problems
    ]


def _undeclared_errors(rule: RuleInfo, subject: str) -> list[LintError]:
    """The findings for id, slug, title and severity when declared empty or not at all, bar the rejected ones."""
    declared = [
        ("id", rule.rule_id),
        ("slug", rule.slug),
        ("title", rule.title),
        ("severity", "declared" if rule.severity_declared else ""),
    ]
    return [
        LintError(
            rule_id=subject,
            check_name="required_frontmatter",
            message=f"{rule.rule_md_label}: {name}: Field required",
        )
        for name, value in declared
        if not value and name not in rule.rejected_fields
    ]


def _frontmatter_errors(rule: RuleInfo, category_codes: dict[str, Category]) -> list[LintError]:
    """The findings about what the rule's frontmatter declares: rejected fields, id-category, enforcement partner."""
    subject = rule.rule_id or "(unknown)"
    errors = _field_problem_errors(rule, subject)
    rejected = rule.rejected_fields
    if "id" not in rejected and "category" not in rejected:
        errors.extend(_id_category_errors(rule, category_codes))
    errors.extend(_undeclared_errors(rule, subject))
    # Enforcement-partner gap — a rule that declares its concern needs an out-of-band
    # enforcement partner (`enforcement_required: true`) must name that partner in
    # `enforcement_mechanism`; a lint finding alone cannot make the concern stick, and an
    # unnamed mechanism leaves the gap the field exists to close.
    if rule.enforcement_required and not rule.enforcement_mechanism_named:
        errors.append(
            LintError(
                rule_id=subject,
                check_name="enforcement_partner",
                message=(
                    "Declares enforcement_required: true but names no enforcement_mechanism "
                    "partner (hook | permission | ci | managed_settings | static_analysis)"
                ),
            )
        )
    return errors


def _lint_single_rule(
    rule: RuleInfo,
    seen_ids: dict[str, Path],
    category_codes: dict[str, Category],
) -> list[LintError]:
    """Run lint checks on a single rule. Mutates seen_ids for duplicate tracking.

    The frontmatter checks run for every rule whose frontmatter could be read, including one
    whose checks failed to load; a rule whose frontmatter could not be read gets only the
    checks that need no frontmatter.
    """
    errors = _duplicate_id_errors(rule, seen_ids)
    errors.extend(_check_prefix_errors(rule))
    if rule.frontmatter_read:
        errors.extend(_frontmatter_errors(rule, category_codes))
    return errors


def lint_rules(rules: list[RuleInfo]) -> list[LintError]:
    """Run structural integrity checks on all discovered rules.

    Checks:
    1. ID-category match — category code in rule ID matches category field
    2. Check ID prefix — all check IDs start with the dotted rule ID prefix
    3. No duplicate rule IDs — across all namespaces
    4. Frontmatter — each field the rule model rejects is reported as missing or invalid;
       id, slug, title and severity declared
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
    baseline: list[JsonObject],
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
        if not isinstance(rule_id, str):
            raise ValueError(f"baseline entry without a rule_id: {entry}")
        if rule_id not in current_ids:
            gaps.append(CoverageGap(rule_id=rule_id, reason="missing"))
        elif entry.get("has_fixtures") and not (
            current_map[rule_id].has_pass_fixture
            or current_map[rule_id].has_fail_fixture
            or current_map[rule_id].has_cases
        ):
            gaps.append(CoverageGap(rule_id=rule_id, reason="fixtures removed"))

    return gaps
