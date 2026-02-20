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
        # Word-boundary truncation for title
        max_title = 29
        if len(title) > max_title:
            truncated = title[: max_title - 3]
            last_space = truncated.rfind(" ")
            if last_space > max_title // 2:
                truncated = truncated[:last_space]
            display_title = truncated.rstrip() + "..."
        else:
            display_title = title
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


def _format_semantic_cta(
    result: ValidationResult,
) -> str:
    """Format semantic CTA for installed users with partial results."""
    if not result.is_partial:
        return ""
    return "[dim]For full semantic analysis: ails install[/dim]"


def _format_install_cta() -> str:
    """CTA for ephemeral (npx/uvx) users to install permanently."""
    from reporails_cli.core.self_update import is_ephemeral_install

    if not is_ephemeral_install():
        return ""
    return "[dim]Run ails install to enable MCP scoring and faster checks.[/dim]"


def format_result(
    result: ValidationResult,
    ascii_mode: bool | None = None,
    quiet_semantic: bool = False,
    _show_legend: bool = True,
    delta: ScanDelta | None = None,
    show_mcp_cta: bool = True,
    elapsed_ms: float | None = None,
    surface: dict[str, object] | None = None,
) -> str:
    """Format validation result for terminal output."""
    data = json_formatter.format_result(result, delta)

    violations = data.get("violations", [])

    sections = []

    # Violations first
    sections.append(format_violations_section(violations, ascii_mode))

    # Spacer before scorecard
    sections.append("")

    # Assessment box (scorecard at bottom)
    sections.append(format_assessment_box(data, ascii_mode, delta, elapsed_ms=elapsed_ms, surface=surface))

    # Pending semantic (below scorecard)
    pending = _format_pending_section(result, quiet_semantic, ascii_mode)
    if pending:
        sections.append(pending)

    # Skipped experimental rules
    experimental = _format_experimental_section(result)
    if experimental:
        sections.append("")
        sections.append(experimental)

    # CTA: ephemeral install CTA takes priority over semantic CTA
    if show_mcp_cta:
        install_cta = _format_install_cta()
        if install_cta:
            sections.append("")
            sections.append(install_cta)
        elif result.is_partial and not quiet_semantic:
            cta = _format_semantic_cta(result)
            if cta:
                sections.append("")
                sections.append(cta)

    return "\n".join(sections)
