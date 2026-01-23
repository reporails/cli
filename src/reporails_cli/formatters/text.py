"""Terminal text output formatter.

Renders ValidationResult for terminal display.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

from reporails_cli.core.models import ValidationResult
from reporails_cli.formatters import json as json_formatter

# ASCII mode: set AILS_ASCII=1 or pass ascii=True to format functions
_ASCII_MODE = os.environ.get("AILS_ASCII", "").lower() in ("1", "true", "yes")

# Character sets for box drawing
_UNICODE_CHARS = {
    "tl": "╔", "tr": "╗", "bl": "╚", "br": "╝",
    "h": "═", "v": "║",
    "filled": "▓", "empty": "░",
    "check": "✓", "crit": "▲", "high": "!", "med": "○", "low": "·",
}
_ASCII_CHARS = {
    "tl": "+", "tr": "+", "bl": "+", "br": "+",
    "h": "-", "v": "|",
    "filled": "#", "empty": ".",
    "check": "*", "crit": "!", "high": "!", "med": "o", "low": "-",
}


def _get_chars(ascii_mode: bool | None = None) -> dict[str, str]:
    """Get character set based on mode."""
    if ascii_mode is None:
        ascii_mode = _ASCII_MODE
    return _ASCII_CHARS if ascii_mode else _UNICODE_CHARS


def _normalize_path(file_path: str, max_len: int = 50) -> str:
    """
    Normalize file path for display.

    Converts absolute paths to relative (to cwd) and shortens very long paths.

    Args:
        file_path: Raw file path from violation
        max_len: Max display length before truncation

    Returns:
        Normalized path for display
    """
    # Handle absolute paths - make relative to cwd
    if file_path.startswith("/"):
        with contextlib.suppress(ValueError):
            # On Windows, relpath can fail for different drives
            file_path = os.path.relpath(file_path)

    # Only truncate if path is too long for display
    if len(file_path) <= max_len:
        return file_path

    # Shorten long paths (show last 3 segments with ellipsis)
    parts = file_path.split("/")
    if len(parts) > 3:
        return ".../" + "/".join(parts[-3:])
    return file_path


def _build_score_bar(score: float, ascii_mode: bool | None = None) -> str:
    """
    Build visual score bar for 0-10 scale.

    Args:
        score: Score on 0-10 scale
        ascii_mode: Force ASCII mode (None = use env var)

    Returns:
        Visual bar string
    """
    chars = _get_chars(ascii_mode)
    bar_width = 50
    filled = int((score / 10) * bar_width)
    filled = min(filled, bar_width)

    bar = chars["filled"] * filled + chars["empty"] * (bar_width - filled)
    return bar


def _format_assessment_box(data: dict[str, Any], ascii_mode: bool | None = None) -> str:
    """
    Format the visual assessment box.

    Args:
        data: Canonical dict from json formatter
        ascii_mode: Force ASCII mode (None = use env var)

    Returns:
        Formatted assessment box string
    """
    chars = _get_chars(ascii_mode)
    lines = []
    box_width = 62

    score = data.get("score", 0.0)
    level = data.get("level", "L1")
    feature_summary = data.get("feature_summary", "")
    summary_info = data.get("summary", {})
    rules_checked = summary_info.get("rules_checked", 0)
    violations = data.get("violations", [])

    # Map level code to label
    level_labels = {
        "L1": "Absent",
        "L2": "Basic",
        "L3": "Structured",
        "L4": "Modular",
        "L5": "Governed",
        "L6": "Adaptive",
    }
    level_label = level_labels.get(level, level)

    # Top border
    lines.append(chars["tl"] + chars["h"] * box_width + chars["tr"])
    lines.append(chars["v"] + " " * box_width + chars["v"])

    # Score line with capability
    score_text = f"SCORE: {score:.1f} / 10  |  CAPABILITY: {level_label}"
    lines.append(chars["v"] + "   " + score_text.ljust(box_width - 3) + chars["v"])

    # Score bar
    bar = _build_score_bar(score, ascii_mode)
    lines.append(chars["v"] + "   " + bar.ljust(box_width - 3) + chars["v"])
    lines.append(chars["v"] + " " * box_width + chars["v"])

    # Setup line
    setup_text = f"Setup: {feature_summary}"
    # Truncate if too long
    if len(setup_text) > box_width - 6:
        setup_text = setup_text[: box_width - 9] + "..."
    lines.append(chars["v"] + "   " + setup_text.ljust(box_width - 3) + chars["v"])
    lines.append(chars["v"] + " " * box_width + chars["v"])

    # Summary line
    violation_count = len(violations)
    if violation_count == 0:
        summary = f"No violations · {rules_checked} rules checked"
    else:
        summary = f"{violation_count} violation(s) · {rules_checked} rules checked"
    lines.append(chars["v"] + "   " + summary.ljust(box_width - 3) + chars["v"])
    lines.append(chars["v"] + " " * box_width + chars["v"])

    # Bottom border
    lines.append(chars["bl"] + chars["h"] * box_width + chars["br"])

    return "\n".join(lines)


def format_result(result: ValidationResult, ascii_mode: bool | None = None) -> str:
    """
    Format validation result for terminal output.

    Args:
        result: ValidationResult from engine
        ascii_mode: Force ASCII mode (None = use env var)

    Returns:
        Formatted string for terminal
    """
    # Convert to canonical dict first
    data = json_formatter.format_result(result)
    chars = _get_chars(ascii_mode)

    lines = []

    summary_info = data.get("summary", {})
    rules_passed = summary_info.get("rules_passed", 0)
    violations = data.get("violations", [])
    judgment_requests = data.get("judgment_requests", [])
    friction = data.get("friction", {})

    # Assessment box
    lines.append(_format_assessment_box(data, ascii_mode))
    lines.append("")

    # What's working well - positive feedback
    if rules_passed > 0:
        # Count violations by category
        violation_categories: set[str] = set()
        for v in violations:
            rule_id = v.get("rule_id", "")
            if rule_id:
                violation_categories.add(rule_id[0])

        # Categories with no violations
        all_categories = {
            "S": "Structure",
            "C": "Content",
            "E": "Efficiency",
            "M": "Maintenance",
            "G": "Governance",
        }
        passing_categories = [
            name for code, name in all_categories.items() if code not in violation_categories
        ]

        if passing_categories:
            lines.append("What's working well:")
            for cat in passing_categories:
                lines.append(f"  {chars['check']} {cat}")
            lines.append("")

    # Violations - grouped by file
    if violations:
        lines.append("Violations:")
        lines.append("-" * 60)

        # Group by file
        grouped: dict[str, list[dict[str, Any]]] = {}
        for v in violations:
            location = v.get("location", "")
            file_path = location.rsplit(":", 1)[0] if ":" in location else location
            if file_path not in grouped:
                grouped[file_path] = []
            grouped[file_path].append(v)

        # Sort files by total points (worst first)
        sorted_files = sorted(grouped.items(), key=lambda x: sum(v.get("points", 0) for v in x[1]))

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        for file_path, file_violations in sorted_files:
            display_path = _normalize_path(file_path)
            total_points = sum(v.get("points", 0) for v in file_violations)
            lines.append(
                f"  {display_path} ({len(file_violations)} violations, {total_points} pts)"
            )

            # Sort violations by severity within file
            sorted_violations = sorted(
                file_violations,
                key=lambda v: (severity_order.get(v.get("severity", ""), 9), v.get("location", "")),
            )

            for v in sorted_violations:
                severity = v.get("severity", "")
                severity_label = {
                    "critical": f"{chars['crit']} CRIT",
                    "high": f"{chars['high']} HIGH",
                    "medium": f"{chars['med']} MED",
                    "low": f"{chars['low']} LOW",
                }.get(severity, "???")

                location = v.get("location", "")
                line_num = location.rsplit(":", 1)[-1] if ":" in location else "?"
                msg = v.get("message", "")
                msg = msg[:40] + "..." if len(msg) > 43 else msg
                rule_id = v.get("rule_id", "")
                lines.append(f"    {severity_label:<6} {rule_id:<3} :{line_num:<4} {msg}")

            lines.append("")
    else:
        lines.append("No violations found.")
        lines.append("")

    # Semantic rules (brief - require MCP for evaluation)
    if judgment_requests:
        # Count unique rules
        unique_rule_ids = {jr.get("rule_id", "") for jr in judgment_requests}
        lines.append(f"{len(unique_rule_ids)} semantic rules skipped (require MCP)")
        lines.append("")

    # Friction estimate (only if significant)
    friction_level = friction.get("level", "none")
    friction_minutes = friction.get("estimated_minutes", 0)
    if friction_level != "none" and friction_minutes >= 5:
        lines.append(f"Friction: {friction_level.title()} (est. ~{friction_minutes} min redo loops)")

    return "\n".join(lines)


def format_score(result: ValidationResult, ascii_mode: bool | None = None) -> str:
    """
    Format quick score summary for terminal.

    Args:
        result: ValidationResult from engine
        ascii_mode: Force ASCII mode (None = use env var)

    Returns:
        One-line score summary
    """
    from reporails_cli.core.scorer import LEVEL_LABELS

    level_label = LEVEL_LABELS.get(result.level, "Unknown")
    violation_count = len(result.violations)

    if violation_count == 0:
        return f"ails: {result.score:.1f}/10 ({result.level.value}) {level_label}"
    else:
        return f"ails: {result.score:.1f}/10 ({result.level.value}) {level_label} - {violation_count} violations"


def format_rule(rule_id: str, rule_data: dict[str, Any]) -> str:
    """
    Format rule explanation for terminal.

    Args:
        rule_id: Rule identifier
        rule_data: Rule metadata

    Returns:
        Formatted rule details
    """
    lines = []

    lines.append(f"Rule: {rule_id}")
    lines.append("=" * 60)
    lines.append("")

    if rule_data.get("title"):
        lines.append(f"Title: {rule_data['title']}")

    if rule_data.get("category"):
        lines.append(f"Category: {rule_data['category']}")

    if rule_data.get("type"):
        lines.append(f"Type: {rule_data['type']}")

    if rule_data.get("level"):
        lines.append(f"Required Level: {rule_data['level']}")

    lines.append("")

    if rule_data.get("description"):
        lines.append("Description:")
        lines.append(f"  {rule_data['description']}")
        lines.append("")

    antipatterns = rule_data.get("antipatterns", [])
    if antipatterns:
        lines.append("Antipatterns:")
        for ap in antipatterns:
            lines.append(f"  - {ap.get('id', '?')}: {ap.get('name', 'Unknown')}")
            lines.append(f"    Severity: {ap.get('severity', 'medium')}")
            lines.append(f"    Points: {ap.get('points', -10)}")
        lines.append("")

    see_also = rule_data.get("see_also", [])
    if see_also:
        lines.append("See Also:")
        for ref in see_also:
            lines.append(f"  - {ref}")

    return "\n".join(lines)
