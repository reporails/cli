"""Mechanical check runner — dispatches rule checks to Python functions.

Produces Violation objects compatible with the scoring pipeline.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from reporails_cli.core.mechanical.checks import MECHANICAL_CHECKS
from reporails_cli.core.models import Rule, Violation

logger = logging.getLogger(__name__)


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
    # Replace glob patterns with concrete paths so checks don't re-glob
    effective_vars = _bind_instruction_files(template_vars, target, instruction_files)

    violations: list[Violation] = []

    for rule_id, rule in rules.items():
        location = _resolve_location(target, rule, effective_vars)

        for check in rule.checks:
            if check.type != "mechanical" or not check.check:
                continue

            fn = MECHANICAL_CHECKS.get(check.check)
            if fn is None:
                logger.warning("Unknown mechanical check: %s (rule %s)", check.check, rule_id)
                continue

            args: dict[str, Any] = check.args or {}

            try:
                result = fn(target, args, effective_vars)
            except Exception:
                logger.exception("Mechanical check %s failed for rule %s", check.check, rule_id)
                continue

            passed = result.passed if not args.get("negate") else not result.passed
            if not passed:
                violations.append(
                    Violation(
                        rule_id=rule_id,
                        rule_title=rule.title,
                        location=location,
                        message=result.message,
                        severity=check.severity,
                        check_id=check.id,
                    )
                )

    return violations


def _bind_instruction_files(
    template_vars: dict[str, str | list[str]],
    target: Path,
    instruction_files: list[Path] | None,
) -> dict[str, str | list[str]]:
    """Replace instruction_files glob patterns with concrete relative paths.

    When the engine provides pre-resolved instruction files, convert them to
    relative paths and inject into template_vars. This ensures mechanical
    checks operate on the same file set the engine discovered, avoiding
    re-globbing that picks up test fixtures and other non-instruction files.

    Args:
        template_vars: Original template variables with glob patterns
        target: Project root for computing relative paths
        instruction_files: Pre-resolved file paths, or None to keep patterns

    Returns:
        Template vars with instruction_files replaced (or original if None)
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
    return result


def _resolve_location(
    target: Path, rule: Rule, template_vars: dict[str, str | list[str]],
) -> str:
    """Resolve a location string for mechanical violations.

    Uses the first instruction file from template_vars when targets reference
    {{instruction_files}}. Falls back to the resolved pattern or ".".

    Args:
        target: Project root
        rule: Rule definition
        template_vars: Agent config template variables (may have concrete paths)

    Returns:
        Location string (e.g., "CLAUDE.md:0" or ".:0")
    """
    if not rule.targets:
        return ".:0"

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
