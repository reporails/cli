"""Full terminal output formatter.

Provides rich, detailed output for interactive terminal use.
"""
# pylint: disable=too-many-locals

from __future__ import annotations

from reporails_cli.core.models import ScanDelta, ValidationResult
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters.text.box import format_assessment_box
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.formatters.text.components import get_severity_icons, pad_line
from reporails_cli.formatters.text.violations import format_violations_section


def _format_pending_section(
    result: ValidationResult,
    quiet_semantic: bool = False,
    ascii_mode: bool | None = None,
) -> str:
    """Format pending semantic evaluation box."""
    if quiet_semantic or not result.pending_semantic:
        return ""

    ps = result.pending_semantic
    chars = get_chars(ascii_mode)
    box_width = 62

    top_border = chars["tl"] + chars["h"] * box_width + chars["tr"]
    bottom_border = chars["bl"] + chars["h"] * box_width + chars["br"]
    empty_line = chars["v"] + " " * box_width + chars["v"]

    severity_icons = get_severity_icons(chars)

    # Header line: title + count on same line
    header_text = f"Pending semantic evaluation: {ps.rule_count} rules across {ps.file_count} files"
    header_line = pad_line(header_text, box_width, chars["v"])

    # Build per-rule table from judgment_requests
    seen: dict[str, tuple[str, str]] = {}  # rule_id -> (title, severity)
    for jr in result.judgment_requests:
        if jr.rule_id not in seen:
            seen[jr.rule_id] = (jr.rule_title, jr.severity.value)

    rule_lines = []
    rule_lines.append(pad_line("Rule             Description                  Severity", box_width, chars["v"]))
    rule_lines.append(pad_line(chars["sep"] * 53, box_width, chars["v"]))
    for rule_id in ps.rules:
        title, severity = seen.get(rule_id, ("", ""))
        icon = severity_icons.get(severity, "") if severity else ""
        # Truncate title to fit: 17 (rule) + 29 (title) + icon
        max_title = 29
        display_title = title[:max_title] if len(title) > max_title else title
        row = f"{rule_id:<17}{display_title:<29}{icon}"
        rule_lines.append(pad_line(row, box_width, chars["v"]))

    lines = [
        top_border,
        empty_line,
        header_line,
        empty_line,
        *rule_lines,
        empty_line,
        bottom_border,
    ]
    return "\n".join(lines)


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
    """Format MCP call-to-action box for partial evaluation."""
    if not result.is_partial:
        return ""

    chars = get_chars(ascii_mode)
    width = 64
    border = chars["h"] * width

    msg = "For complete analysis, add reporails MCP to your agent:"
    cmd = "claude mcp add reporails -- uvx --refresh --from reporails-cli ails-mcp"

    lines = [
        border,
        "",
        msg.center(width),
        cmd.center(width),
        "",
        border,
    ]
    return "\n".join(lines)


def format_result(
    result: ValidationResult,
    ascii_mode: bool | None = None,
    quiet_semantic: bool = False,
    _show_legend: bool = True,
    delta: ScanDelta | None = None,
    show_mcp_cta: bool = True,
) -> str:
    """Format validation result for terminal output."""
    data = json_formatter.format_result(result, delta)

    violations = data.get("violations", [])

    sections = []

    # Assessment box
    sections.append(format_assessment_box(data, ascii_mode, delta))
    sections.append("")

    # Violations
    sections.append(format_violations_section(violations, ascii_mode))

    # Pending semantic
    pending = _format_pending_section(result, quiet_semantic, ascii_mode)
    if pending:
        sections.append(pending)

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
