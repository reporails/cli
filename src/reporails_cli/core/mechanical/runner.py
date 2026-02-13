"""Mechanical check runner — dispatches rule checks to Python functions.

Produces Violation objects compatible with the scoring pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path, PurePosixPath
from typing import Any

from reporails_cli.core.mechanical.checks import MECHANICAL_CHECKS, CheckResult
from reporails_cli.core.models import Check, Rule, Violation

logger = logging.getLogger(__name__)


def dispatch_single_check(
    check: Check,
    rule: Rule,
    root: Path,
    effective_vars: dict[str, str | list[str]],
    location: str,
) -> tuple[Violation | None, CheckResult | None]:
    """Dispatch a single mechanical check and return (violation, raw_result).

    Args:
        check: Check definition (must have type="mechanical" and check name).
        rule: Parent rule for context (id, title).
        root: Project root directory.
        effective_vars: Template variables with concrete instruction file paths.
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

    args: dict[str, Any] = check.args or {}

    try:
        result = fn(root, args, effective_vars)
    except Exception:
        logger.exception("Mechanical check %s failed for rule %s", check.check, rule.id)
        return None, None

    passed = result.passed if not check.negate else not result.passed
    if not passed:
        violation = Violation(
            rule_id=rule.id,
            rule_title=rule.title,
            location=location,
            message=result.message,
            severity=check.severity,
            check_id=check.id,
        )
        return violation, result

    return None, result


def run_mechanical_checks(
    rules: dict[str, Rule],
    target: Path,
    template_vars: dict[str, str | list[str]],
    instruction_files: list[Path] | None = None,
) -> list[Violation]:
    """Run mechanical checks from rules and return violations.

    Scans each rule's checks array for entries with `type="mechanical"`.
    Rules of any type (mechanical, deterministic, semantic) may contain
    mechanical checks — the runner filters by check.type internally.

    Args:
        rules: Dict of applicable rules (any rule type accepted)
        target: Project root directory
        template_vars: Agent config template variables
        instruction_files: Pre-resolved instruction file paths from engine.
            When provided, replaces glob patterns in template_vars so checks
            operate on discovered files rather than re-globbing.

    Returns:
        List of Violation objects for failed checks
    """
    effective_vars = bind_instruction_files(template_vars, target, instruction_files)
    violations: list[Violation] = []

    for rule in rules.values():
        location = resolve_location(target, rule, effective_vars)
        for check in rule.checks:
            if check.type != "mechanical":
                continue
            violation, _result = dispatch_single_check(check, rule, target, effective_vars, location)
            if violation:
                violations.append(violation)

    return violations


def _matches_any_pattern(path: str, patterns: list[str]) -> bool:
    """Check if a relative path matches any of the given glob patterns.

    Uses PurePosixPath.match() for glob matching. For ``**/`` prefixed patterns,
    also checks the tail to handle zero-directory matches (e.g., ``CLAUDE.md``
    matching ``**/CLAUDE.md``).
    """
    p = PurePosixPath(path)
    for pattern in patterns:
        if p.match(pattern):
            return True
        # **/X should also match X at root (zero directories)
        if pattern.startswith("**/") and p.match(pattern[3:]):
            return True
    return False


def bind_instruction_files(
    template_vars: dict[str, str | list[str]],
    target: Path,
    instruction_files: list[Path] | None,
) -> dict[str, str | list[str]]:
    """Replace instruction_files glob patterns with concrete relative paths.

    When the engine provides pre-resolved instruction files, convert them to
    relative paths and inject into template_vars. Also binds main_instruction_file
    by filtering discovered files against the original glob patterns from the
    agent config (e.g., ``["**/CLAUDE.md"]``).

    Args:
        template_vars: Original template variables with glob patterns
        target: Project root for computing relative paths
        instruction_files: Pre-resolved file paths, or None to keep patterns

    Returns:
        Template vars with instruction_files and main_instruction_file replaced
    """
    if not instruction_files:
        return template_vars

    # Convert absolute paths to relative strings
    relative: list[str] = []
    for f in instruction_files:
        try:
            relative.append(str(f.relative_to(target)))
        except ValueError:
            relative.append(str(f))

    if not relative:
        return template_vars

    result = dict(template_vars)
    result["instruction_files"] = relative

    # Bind main_instruction_file by filtering against original glob patterns
    main_patterns = template_vars.get("main_instruction_file")
    if main_patterns is not None:
        if isinstance(main_patterns, str):
            main_patterns = [main_patterns]
        if main_patterns:
            main_matched = [r for r in relative if _matches_any_pattern(r, main_patterns)]
            if main_matched:
                result["main_instruction_file"] = main_matched

    return result


def resolve_location(
    target: Path,
    rule: Rule,
    template_vars: dict[str, str | list[str]],
) -> str:
    """Resolve a location string for mechanical violations.

    For rules targeting ``{{instruction_files}}`` or ``{{main_instruction_file}}``,
    prefers the first ``main_instruction_file`` entry so violations are attributed
    to the root instruction file (e.g., ``CLAUDE.md``) rather than skill files
    or scoped rule snippets.

    Args:
        target: Project root
        rule: Rule definition
        template_vars: Agent config template variables (may have concrete paths)

    Returns:
        Location string (e.g., "CLAUDE.md:0" or ".:0")
    """
    if not rule.targets:
        return ".:0"

    # For instruction_files targets, prefer main_instruction_file for location
    if "{{instruction_files}}" in rule.targets or "{{main_instruction_file}}" in rule.targets:
        main = template_vars.get("main_instruction_file")
        if isinstance(main, list) and main:
            return f"{main[0]}:0"

    # Resolve template variables
    resolved = rule.targets
    for key, value in template_vars.items():
        placeholder = "{{" + key + "}}"
        if placeholder in resolved:
            if isinstance(value, list):
                resolved = resolved.replace(placeholder, value[0] if value else "")
            else:
                resolved = resolved.replace(placeholder, str(value))

    # If still has unresolved placeholders, use as-is
    if "{{" in resolved:
        return f"{resolved}:0"

    # If resolved to a concrete file path, use it directly
    if (target / resolved).exists():
        return f"{resolved}:0"

    return f"{resolved}:0"
