"""Violations section formatting.

Handles grouping, sorting, and rendering of violations.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.formatters.text.components import (
    format_legend,
    get_severity_icons,
    normalize_path,
)
from reporails_cli.templates import render


def format_violations_section(
    violations: list[dict[str, Any]],
    ascii_mode: bool | None = None,
) -> str:
    """Format violations section grouped by file."""
    if not violations:
        return "No violations found."

    chars = get_chars(ascii_mode)
    legend = format_legend(ascii_mode)
    lines = [f"Violations:  {legend}", "-" * 60]

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
        file_violations = item[1]
        severity_weights = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        worst_severity = min(
            severity_weights.get(v.get("severity", "low"), 3) for v in file_violations
        )
        return (worst_severity, -len(file_violations))

    sorted_files = sorted(grouped.items(), key=file_sort_key)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

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

        issue_word = "issue" if len(unique_violations) == 1 else "issues"
        lines.append(render("cli_file_header.txt",
            filepath=display_path,
            count=len(unique_violations),
            issue_word=issue_word,
        ))

        sorted_violations = sorted(
            unique_violations,
            key=lambda v: (severity_order.get(v.get("severity", ""), 9), v.get("location", "")),
        )

        severity_icons = get_severity_icons(chars)

        for v in sorted_violations:
            sev = v.get("severity", "medium")
            icon = severity_icons.get(sev, "?")
            location = v.get("location", "")
            line_num = location.rsplit(":", 1)[-1] if ":" in location else "?"
            msg = v.get("message", "")
            max_msg_len = 50
            if len(msg) > max_msg_len:
                msg = msg[: max_msg_len - 3] + "..."
            rule_id = v.get("rule_id", "")

            lines.append(render("cli_violation.txt",
                icon=icon,
                rule_id=rule_id,
                line=line_num,
                message=msg,
            ))

        lines.append("")

    return "\n".join(lines)
