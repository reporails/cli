"""Mechanical check runner — dispatches rule checks to Python functions.

Produces Violation objects compatible with the scoring pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reporails_cli.core.mechanical.checks import MECHANICAL_CHECKS, CheckResult
from reporails_cli.core.models import Check, ClassifiedFile, Rule, Severity, Violation

logger = logging.getLogger(__name__)


def dispatch_single_check(
    check: Check,
    rule: Rule,
    root: Path,
    classified_files: list[ClassifiedFile],
    location: str,
) -> tuple[Violation | None, CheckResult | None]:
    """Dispatch a single mechanical check and return (violation, raw_result).

    Args:
        check: Check definition (must have type="mechanical" and check name).
        rule: Parent rule for context (id, title).
        root: Project root directory.
        classified_files: Classified files for file targeting.
        location: Pre-resolved location string for violation reporting.

    Returns:
        Tuple of (Violation if check failed else None, raw CheckResult or None on error).
    """
    if not check.check:
        return None, None

    fn = MECHANICAL_CHECKS.get(check.check)
    if fn is None:
        logger.warning("Unknown mechanical check: %s (rule %s)", check.check, rule.id)
        return None, None

    args: dict[str, Any] = dict(check.args or {})

    # Inject rule match type so checks can scope to the rule's file targets.
    if rule.match is not None and rule.match.type and "_targets" not in args:
        args["_match_type"] = rule.match.type

    try:
        result = fn(root, args, classified_files)
    except Exception:  # mechanical checks are plugin-like; any failure caught and logged
        logger.exception("Mechanical check %s failed for rule %s", check.check, rule.id)
        return None, None

    passed = result.passed if check.expect == "present" else not result.passed
    if not passed:
        # Check-level severity/message override rule-level defaults
        sev = Severity(check.severity) if check.severity else rule.severity
        msg = check.message or result.message
        violation = Violation(
            rule_id=rule.id,
            rule_title=rule.title,
            location=result.location or location,
            message=msg,
            severity=sev,
            check_id=check.id,
        )
        return violation, result

    return None, result


def run_mechanical_checks(
    rules: dict[str, Rule],
    target: Path,
    classified_files: list[ClassifiedFile],
) -> list[Violation]:
    """Run mechanical checks from rules and return violations.

    Scans each rule's checks array for entries with `type="mechanical"`.
    Rules of any type (mechanical, deterministic, semantic) may contain
    mechanical checks — the runner filters by check.type internally.

    Args:
        rules: Dict of applicable rules (any rule type accepted)
        target: Project root directory
        classified_files: Classified files for file targeting

    Returns:
        List of Violation objects for failed checks
    """
    from reporails_cli.core.classification import match_files

    violations: list[Violation] = []

    for rule in rules.values():
        # Filter classified files by rule match criteria (type, scope, format, etc.)
        if rule.match:
            matched = match_files(classified_files, rule.match)
            if not matched:
                continue
        else:
            matched = classified_files

        location = resolve_location(rule, matched, target)
        for check in rule.checks:
            if check.type != "mechanical":
                continue
            violation, _result = dispatch_single_check(check, rule, target, matched, location)
            if violation:
                violations.append(violation)

    return violations


def _relativize(path: Path, root: Path | None) -> str:
    """Return path relative to root, or just the name as fallback."""
    if root is not None:
        try:
            return path.relative_to(root).as_posix()
        except ValueError:
            pass
    return path.name


def _first_classified_path(
    classified_files: list[ClassifiedFile],
    root: Path | None,
    *type_names: str,
) -> str | None:
    """Return first relative path from classified files matching any type name."""
    for type_name in type_names:
        for cf in classified_files:
            if cf.file_type == type_name:
                return _relativize(cf.path, root)
    return None


def resolve_location(
    rule: Rule,
    classified_files: list[ClassifiedFile],
    root: Path | None = None,
) -> str:
    """Resolve a location string for mechanical violations.

    Uses rule.match to determine the best file for violation attribution.
    For rules matching 'main' type or match-all ({}), prefers the main file.

    Args:
        rule: Rule definition
        classified_files: Classified files for path lookup
        root: Project root for relativizing absolute paths

    Returns:
        Location string (e.g., "CLAUDE.md:0" or ".:0")
    """
    path = _resolve_location_path(rule, classified_files, root)
    return f"{path}:0" if path else ".:0"


def _resolve_location_path(
    rule: Rule,
    classified_files: list[ClassifiedFile],
    root: Path | None,
) -> str | None:
    """Find the best file path for violation attribution. Returns None for project root."""
    if rule.match is None:
        return None

    # For explicit "main" match type, only look for main files
    if rule.match.type == "main":
        return _first_classified_path(classified_files, root, "main")

    # For typed matches, find a file of that type
    if rule.match.type:
        type_names = rule.match.type if isinstance(rule.match.type, list) else [rule.match.type]
        return _first_classified_path(classified_files, root, *type_names)

    # Wildcard match (type is None) — prefer main file, then any file
    path = _first_classified_path(classified_files, root, "main")
    if path:
        return path

    if classified_files:
        return _relativize(classified_files[0].path, root)

    return None
