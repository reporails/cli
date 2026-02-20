"""Violations section formatting.

Handles grouping, sorting, and rendering of violations.
"""
# pylint: disable=too-many-locals,too-many-statements

from __future__ import annotations

from typing import Any

from reporails_cli.formatters.text.chars import ASCII_MODE, get_chars
from reporails_cli.formatters.text.components import (
    format_legend,
    get_severity_icons,
    normalize_path,
)
from reporails_cli.templates import render

# Severities that are informational (not real issues)
_INFO_SEVERITIES = {"pending"}

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "pending": 4,
}


def _format_file_header(
    display_path: str,
    unique_violations: list[dict[str, Any]],
) -> str:
    """Format file header with issue and info-severity counts."""
    real_count = sum(1 for v in unique_violations if v.get("severity") not in _INFO_SEVERITIES)
    pending_count = sum(1 for v in unique_violations if v.get("severity") == "pending")
    issue_word = "issue" if real_count == 1 else "issues"

    if pending_count > 0:
        return f"  {display_path} ({real_count} {issue_word}, {pending_count} awaiting semantic)"
    return render(
        "cli_file_header.txt",
        filepath=display_path,
        count=real_count,
        issue_word=issue_word,
    )


def format_violations_section(
    violations: list[dict[str, Any]],
    ascii_mode: bool | None = None,
) -> str:
    """Format violations section grouped by file."""
    if not violations:
        return "No violations found."

    chars = get_chars(ascii_mode)
    use_ascii = ascii_mode if ascii_mode is not None else ASCII_MODE
    colored = not use_ascii
    legend = format_legend(ascii_mode, colored)
    plain_legend = format_legend(ascii_mode, colored=False)
    line_width = 64
    separator = "-" * line_width
    gap = line_width - len("Violations") - len(plain_legend)
    header = f"Violations{' ' * max(gap, 1)}{legend}"
    lines = ["", separator, header, separator]

    # Fixed column widths:  "    " (4) + icon (1) + "  " (2) + line (4) + "  " (2) = 13 prefix
    # suffix: "  " (2) + rule_id
    line_col_w = 4
    prefix_w = 4 + 1 + 2 + line_col_w + 2  # 13
    suffix_gap = 2
    rule_col_w = 14
    issue_w = line_width - prefix_w - suffix_gap - rule_col_w
    col_labels = f"    {'':1}  {'line':<{line_col_w}}  {'issue':<{issue_w}}  {'rule':>{rule_col_w}}"

    # Group by file
    grouped: dict[str, list[dict[str, Any]]] = {}
    for v in violations:
        location = v.get("location", "")
        file_path = location.rsplit(":", 1)[0] if ":" in location else location
        if file_path not in grouped:
            grouped[file_path] = []
        grouped[file_path].append(v)

    # Sort files by worst severity
    def file_sort_key(item: tuple[str, list[dict[str, Any]]]) -> tuple[int, int]:
        worst = min(_SEVERITY_ORDER.get(v.get("severity", "low"), 3) for v in item[1])
        return (worst, -len(item[1]))

    sorted_files = sorted(grouped.items(), key=file_sort_key)
    severity_icons = get_severity_icons(chars, colored)

    for file_path, file_violations in sorted_files:
        display_path = normalize_path(file_path)

        # Deduplicate by rule_id within file
        seen_rules: set[str] = set()
        unique_violations: list[dict[str, Any]] = []
        for v in file_violations:
            rule_id = v.get("rule_id", "")
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                unique_violations.append(v)

        lines.append(_format_file_header(display_path, unique_violations))
        lines.append(separator)
        lines.append(col_labels)

        sorted_violations = sorted(
            unique_violations,
            key=lambda v: (_SEVERITY_ORDER.get(v.get("severity", ""), 9), v.get("location", "")),
        )

        for v in sorted_violations:
            sev = v.get("severity", "medium")
            icon = severity_icons.get(sev, "?")
            location = v.get("location", "")
            raw_line = location.rsplit(":", 1)[-1] if ":" in location else ""
            msg = v.get("message", "")
            rule_id = v.get("rule_id", "")

            # Line number: show :N for line-specific, blank for file-wide (line 1)
            line_str = f":{raw_line}" if raw_line and raw_line != "1" else ""
            line_field = line_str.ljust(line_col_w)

            # Fit message within remaining space with word-boundary truncation
            max_msg_len = line_width - prefix_w - suffix_gap - len(rule_id)
            max_msg_len = max(max_msg_len, 10)
            if len(msg) > max_msg_len:
                truncated = msg[: max_msg_len - 3]
                last_space = truncated.rfind(" ")
                if last_space > max_msg_len // 2:
                    truncated = truncated[:last_space]
                msg = truncated.rstrip() + "..."
            msg = msg.ljust(max_msg_len)

            lines.append(
                render(
                    "cli_violation.txt",
                    icon=icon,
                    line=line_field,
                    rule_id=rule_id,
                    message=msg,
                )
            )

        lines.append(separator)
        lines.append("")

    return "\n".join(lines)
