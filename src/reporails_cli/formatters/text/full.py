"""Full terminal output formatter.

Provides rich, detailed output for interactive terminal use.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.models import ScanDelta, ValidationResult
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters.text.box import format_assessment_box
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.formatters.text.components import format_legend
from reporails_cli.formatters.text.violations import format_violations_section
from reporails_cli.templates import render


def _format_working_section(
    violations: list[dict[str, Any]],
    rules_passed: int,
    ascii_mode: bool | None = None,
) -> str:
    """Format 'What's working well' section."""
    if rules_passed <= 0:
        return ""

    chars = get_chars(ascii_mode)

    # Find categories with violations
    violation_categories: set[str] = set()
    for v in violations:
        rule_id = v.get("rule_id", "")
        if rule_id:
            violation_categories.add(rule_id[0])

    all_categories = {
        "S": "Structure", "C": "Content", "E": "Efficiency",
        "M": "Maintenance", "G": "Governance",
    }
    passing_categories = [
        name for code, name in all_categories.items() if code not in violation_categories
    ]

    if not passing_categories:
        return ""

    items = "\n".join(f"  {chars['check']} {cat}" for cat in passing_categories)
    return render("cli_working.txt", items=items)


def _format_pending_section(
    result: ValidationResult,
    quiet_semantic: bool = False,
) -> str:
    """Format pending semantic evaluation section."""
    if quiet_semantic or not result.pending_semantic:
        return ""

    ps = result.pending_semantic
    return render("cli_pending.txt",
        rule_count=ps.rule_count,
        file_count=ps.file_count,
        rule_list=", ".join(ps.rules),
    )


def _format_cta(
    result: ValidationResult,
    ascii_mode: bool | None = None,
) -> str:
    """Format MCP call-to-action for partial evaluation."""
    if not result.is_partial:
        return ""

    chars = get_chars(ascii_mode)
    separator = chars["sep"] * 64
    return render("cli_cta.txt", separator=separator)


def format_result(
    result: ValidationResult,
    ascii_mode: bool | None = None,
    quiet_semantic: bool = False,
    show_legend: bool = True,
    delta: ScanDelta | None = None,
    show_mcp_cta: bool = True,
) -> str:
    """Format validation result for terminal output."""
    data = json_formatter.format_result(result, delta)

    summary_info = data.get("summary", {})
    rules_passed = summary_info.get("rules_passed", 0)
    violations = data.get("violations", [])
    friction = data.get("friction", {})

    sections = []

    # Assessment box
    sections.append(format_assessment_box(data, ascii_mode, delta))
    sections.append("")

    # What's working well
    working = _format_working_section(violations, rules_passed, ascii_mode)
    if working:
        sections.append(working)
        sections.append("")

    # Violations
    sections.append(format_violations_section(violations, ascii_mode))

    # Pending semantic
    pending = _format_pending_section(result, quiet_semantic)
    if pending:
        sections.append(pending)
        sections.append("")

    # Friction estimate
    friction_level = friction.get("level", "none")
    friction_minutes = friction.get("estimated_minutes", 0)
    if friction_level != "none" and friction_minutes >= 5:
        threshold_hint = ">=20" if friction_level == "high" else ">=10" if friction_level == "medium" else ">=5"
        sections.append(f"Friction: {friction_level.title()} (~{friction_minutes} min/session, threshold: {threshold_hint})")

    # MCP CTA (only if partial, not quiet, and CTA enabled)
    if show_mcp_cta and result.is_partial and not quiet_semantic:
        cta = _format_cta(result, ascii_mode)
        if cta:
            sections.append("")
            sections.append(cta)

    # Legend footer
    if violations and show_legend:
        sections.append("")
        sections.append(format_legend(ascii_mode))

    return "\n".join(sections)
