"""Compact terminal output formatter.

Provides minimal output for non-TTY contexts and quick checks.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.levels import get_level_labels
from reporails_cli.core.models import ScanDelta, ValidationResult
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.formatters.text.components import (
    format_legend,
    format_level_delta,
    format_score_delta,
    format_violations_delta,
    get_severity_icons,
    normalize_path,
)


def format_compact(
    result: ValidationResult,
    ascii_mode: bool | None = None,
    show_legend: bool = True,
    delta: ScanDelta | None = None,
) -> str:
    """Format validation result in compact form for Claude Code / non-TTY."""
    data = json_formatter.format_result(result, delta)
    chars = get_chars(ascii_mode)
    lines = []

    score = data.get("score", 0.0)
    level = data.get("level", "L1")
    level_label = get_level_labels().get(result.level, "Unknown")
    violations = data.get("violations", [])
    is_partial = data.get("is_partial", True)

    # Group and dedupe violations
    grouped: dict[str, list[dict[str, Any]]] = {}
    for v in violations:
        location = v.get("location", "")
        file_path = location.rsplit(":", 1)[0] if ":" in location else location
        if file_path not in grouped:
            grouped[file_path] = []
        grouped[file_path].append(v)

    deduped_count = 0
    deduped_grouped: dict[str, list[dict[str, Any]]] = {}
    for file_path, file_violations in grouped.items():
        seen: set[str] = set()
        unique = [v for v in file_violations if not (v.get("rule_id", "") in seen or seen.add(v.get("rule_id", "")))]  # type: ignore[func-returns-value]
        deduped_grouped[file_path] = unique
        deduped_count += len(unique)

    # Header line with delta indicators
    score_delta_str = format_score_delta(delta, ascii_mode)
    level_delta_str = format_level_delta(delta, ascii_mode)
    violations_delta_str = format_violations_delta(delta, ascii_mode) if deduped_count > 0 else ""
    partial_marker = " (partial)" if is_partial else ""
    if deduped_count > 0:
        lines.append(f"Score: {score:.1f}/10{score_delta_str} ({level_label} ({level}){level_delta_str}){partial_marker} - {deduped_count} violations{violations_delta_str}")
    else:
        lines.append(f"Score: {score:.1f}/10{score_delta_str} ({level_label} ({level}){level_delta_str}){partial_marker} {chars['check']} clean")
        return "\n".join(lines)

    lines.append("")

    severity_icons = get_severity_icons(chars)

    for file_path, unique in deduped_grouped.items():
        display_path = normalize_path(file_path)
        lines.append(f"{display_path}:")
        for v in unique:
            sev = v.get("severity", "medium")
            icon = severity_icons.get(sev, "?")
            rule_id = v.get("rule_id", "?")
            check_id = v.get("check_id")
            display_id = f"{rule_id}.{check_id}" if check_id else rule_id
            msg = v.get("message", "")
            location = v.get("location", "")
            line_num = location.rsplit(":", 1)[-1] if ":" in location else "?"
            if len(msg) > 45:
                msg = msg[:42] + "..."
            lines.append(f"  {icon} {display_id}:{line_num} {msg}")
        lines.append("")

    # Pending semantic
    if result.pending_semantic and result.is_partial:
        ps = result.pending_semantic
        lines.append(f"Pending: {ps.rule_count} semantic rules ({', '.join(ps.rules)})")
        lines.append("")

    # Friction
    friction = data.get("friction", "none")
    friction_level = friction if isinstance(friction, str) else friction.get("level", "none")
    if friction_level != "none":
        lines.append(f"Friction: {friction_level.title()}")
        lines.append("")

    # Legend footer
    if deduped_count > 0 and show_legend:
        lines.append(format_legend(ascii_mode))

    return "\n".join(lines).rstrip()


def format_score(result: ValidationResult, ascii_mode: bool | None = None) -> str:
    """Format quick score summary for terminal."""
    level_label = get_level_labels().get(result.level, "Unknown")
    violation_count = len(result.violations)
    partial = " (partial)" if result.is_partial else ""

    if violation_count == 0:
        return f"ails: {result.score:.1f}/10 {level_label} ({result.level.value}){partial}"
    else:
        return f"ails: {result.score:.1f}/10 {level_label} ({result.level.value}){partial} - {violation_count} violations"
