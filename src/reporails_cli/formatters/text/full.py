"""Full terminal output formatter.

Provides rich, detailed output for interactive terminal use.
"""

from __future__ import annotations

from reporails_cli.core.models import ScanDelta, ValidationResult
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters.text.box import format_assessment_box
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.formatters.text.violations import format_violations_section
from reporails_cli.templates import render

# Full category names with code letter in parentheses
_CATEGORY_HEADERS = {
    "S": "(S)tructure",
    "C": "(C)ontent",
    "E": "(E)fficiency",
    "M": "(M)aintenance",
    "G": "(G)overnance",
}

def _format_category_table(
    result: ValidationResult,
    ascii_mode: bool | None = None,
) -> str:
    """Format per-category summary table.

    Template: ``{x_stat}{x_ind}`` (no gap) with 1-space gap between columns,
    matching the 1-space gap between headers.  So ``len(stat) + len(ind)``
    must equal ``len(hdr)`` for each column.

    Example output::

      (S)tructure (C)ontent (E)fficiency (M)aintenance (G)overnance
      6/7 ○       12/12     7/7          6/6           –
    """
    if not result.category_summary:
        return ""

    if all(cs.total == 0 for cs in result.category_summary):
        return ""

    chars = get_chars(ascii_mode)
    severity_icons = {
        "critical": chars["crit"],
        "high": chars["high"],
        "medium": chars["med"],
        "low": chars["low"],
    }

    template_vars: dict[str, str] = {}
    for cs in result.category_summary:
        key = cs.code.lower()
        hdr = _CATEGORY_HEADERS[cs.code]
        col_w = len(hdr)
        template_vars[f"{key}_hdr"] = hdr

        # Stat: passed/total or –
        stat = f"{cs.passed}/{cs.total}" if cs.total else "–"

        # Indicator: severity icon or empty
        ind = severity_icons.get(cs.worst_severity, "") if cs.worst_severity else ""

        # Build cell: "stat ind" padded to col_w via {x_stat}{x_ind}
        # Put stat + space into {x_stat}, indicator + padding into {x_ind}
        if ind:
            stat_part = stat + " "
            template_vars[f"{key}_stat"] = stat_part
            template_vars[f"{key}_ind"] = ind.ljust(col_w - len(stat_part))
        else:
            template_vars[f"{key}_stat"] = stat.ljust(col_w)
            template_vars[f"{key}_ind"] = ""

    return render("cli_working.txt", **template_vars).rstrip()


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


def _format_experimental_section(
    result: ValidationResult,
) -> str:
    """Format skipped experimental rules section."""
    if not result.skipped_experimental:
        return ""

    se = result.skipped_experimental
    rule_list = ", ".join(se.rules)
    return f"[dim]Experimental rules not checked: {se.rule_count}\n  Use --experimental to include: {rule_list}[/dim]"


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

    violations = data.get("violations", [])
    friction = data.get("friction", {})

    sections = []

    # Assessment box
    sections.append(format_assessment_box(data, ascii_mode, delta))
    sections.append("")

    # Category summary table
    working = _format_category_table(result, ascii_mode)
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
    friction_level = friction if isinstance(friction, str) else friction.get("level", "none")
    if friction_level != "none":
        sections.append(f"Friction: {friction_level.title()}")

    # Skipped experimental rules
    experimental = _format_experimental_section(result)
    if experimental:
        sections.append("")
        sections.append(experimental)

    # MCP CTA (only if partial, not quiet, and CTA enabled)
    if show_mcp_cta and result.is_partial and not quiet_semantic:
        cta = _format_cta(result, ascii_mode)
        if cta:
            sections.append("")
            sections.append(cta)

    return "\n".join(sections)
