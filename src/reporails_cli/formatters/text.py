"""Terminal text output formatter.

Renders ValidationResult for terminal display.
"""

from __future__ import annotations

import contextlib
import os
from typing import Any

from reporails_cli.core.models import ValidationResult
from reporails_cli.core.scorer import LEVEL_LABELS
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


def format_legend(ascii_mode: bool | None = None) -> str:
    """Format severity legend for display."""
    chars = _get_chars(ascii_mode)
    return f"{chars['crit']}=CRIT  {chars['high']}=HIGH  {chars['med']}=MED  {chars['low']}=LOW"


def _normalize_path(file_path: str, max_len: int = 50) -> str:
    """Normalize file path for display."""
    if file_path.startswith("/"):
        with contextlib.suppress(ValueError):
            file_path = os.path.relpath(file_path)

    if len(file_path) <= max_len:
        return file_path

    parts = file_path.split("/")
    if len(parts) > 3:
        return ".../" + "/".join(parts[-3:])
    return file_path


def _build_score_bar(score: float, ascii_mode: bool | None = None) -> str:
    """Build visual score bar for 0-10 scale."""
    chars = _get_chars(ascii_mode)
    bar_width = 50
    filled = int((score / 10) * bar_width)
    filled = min(filled, bar_width)
    return chars["filled"] * filled + chars["empty"] * (bar_width - filled)


def _format_assessment_box(data: dict[str, Any], ascii_mode: bool | None = None) -> str:
    """Format the visual assessment box."""
    chars = _get_chars(ascii_mode)
    lines = []
    box_width = 62

    score = data.get("score", 0.0)
    level = data.get("level", "L1")
    feature_summary = data.get("feature_summary", "")
    summary_info = data.get("summary", {})
    rules_checked = summary_info.get("rules_checked", 0)
    violations = data.get("violations", [])

    level_label = LEVEL_LABELS.get(level, level)

    # Top border
    lines.append(chars["tl"] + chars["h"] * box_width + chars["tr"])
    lines.append(chars["v"] + " " * box_width + chars["v"])

    # Score line with capability
    score_text = f"SCORE: {score:.1f} / 10  |  CAPABILITY: {level_label} ({level})"
    lines.append(chars["v"] + "   " + score_text.ljust(box_width - 3) + chars["v"])

    # Score bar
    bar = _build_score_bar(score, ascii_mode)
    lines.append(chars["v"] + "   " + bar.ljust(box_width - 3) + chars["v"])
    lines.append(chars["v"] + " " * box_width + chars["v"])

    # Setup line
    setup_text = f"Setup: {feature_summary}"
    if len(setup_text) > box_width - 6:
        setup_text = setup_text[: box_width - 9] + "..."
    lines.append(chars["v"] + "   " + setup_text.ljust(box_width - 3) + chars["v"])
    lines.append(chars["v"] + " " * box_width + chars["v"])

    # Summary line - count deduplicated violations
    seen_violations: set[tuple[str, str]] = set()
    for v in violations:
        location = v.get("location", "")
        file_path = location.rsplit(":", 1)[0] if ":" in location else location
        rule_id = v.get("rule_id", "")
        seen_violations.add((file_path, rule_id))
    violation_count = len(seen_violations)
    if violation_count == 0:
        summary = f"No violations · {rules_checked} rules checked"
    else:
        summary = f"{violation_count} violation(s) · {rules_checked} rules checked"
    lines.append(chars["v"] + "   " + summary.ljust(box_width - 3) + chars["v"])
    lines.append(chars["v"] + " " * box_width + chars["v"])

    # Bottom border
    lines.append(chars["bl"] + chars["h"] * box_width + chars["br"])

    return "\n".join(lines)


def format_result(
    result: ValidationResult,
    ascii_mode: bool | None = None,
    quiet_semantic: bool = False,
    show_legend: bool = True,
) -> str:
    """Format validation result for terminal output."""
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

    # What's working well
    if rules_passed > 0:
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

        if passing_categories:
            lines.append("What's working well:")
            for cat in passing_categories:
                lines.append(f"  {chars['check']} {cat}")
            lines.append("")

    # Violations
    if violations:
        lines.append("Violations:")
        lines.append("-" * 60)

        grouped: dict[str, list[dict[str, Any]]] = {}
        for v in violations:
            location = v.get("location", "")
            file_path = location.rsplit(":", 1)[0] if ":" in location else location
            if file_path not in grouped:
                grouped[file_path] = []
            grouped[file_path].append(v)

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
            display_path = _normalize_path(file_path)

            seen_rules: set[str] = set()
            unique_violations: list[dict[str, Any]] = []
            for v in file_violations:
                rule_id = v.get("rule_id", "")
                if rule_id not in seen_rules:
                    seen_rules.add(rule_id)
                    unique_violations.append(v)

            issue_word = "issue" if len(unique_violations) == 1 else "issues"
            lines.append(f"  {display_path} ({len(unique_violations)} {issue_word})")

            sorted_violations = sorted(
                unique_violations,
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
                max_msg_len = 48
                if len(msg) > max_msg_len:
                    msg = msg[: max_msg_len - 3] + "..."
                rule_id = v.get("rule_id", "")
                check_id = v.get("check_id")
                display_id = f"{rule_id}.{check_id}" if check_id else rule_id
                lines.append(f"    {severity_label:<6} {display_id:<18} :{line_num:<4} {msg}")

            lines.append("")
    else:
        lines.append("No violations found.")
        lines.append("")

    # Semantic rules
    if judgment_requests and not quiet_semantic:
        unique_rule_ids = sorted({jr.get("rule_id", "") for jr in judgment_requests})
        rule_list = ", ".join(unique_rule_ids)
        lines.append(f"Semantic rules pending: {rule_list} (evaluate via MCP)")
        lines.append("")

    # Friction estimate
    friction_level = friction.get("level", "none")
    friction_minutes = friction.get("estimated_minutes", 0)
    if friction_level != "none" and friction_minutes >= 5:
        threshold_hint = ">=20" if friction_level == "high" else ">=10" if friction_level == "medium" else ">=5"
        lines.append(f"Friction: {friction_level.title()} (~{friction_minutes} min/session, threshold: {threshold_hint})")

    # Legend footer
    if violations and show_legend:
        lines.append("")
        lines.append(f"Legend: {format_legend(ascii_mode)}")

    return "\n".join(lines)


def format_compact(
    result: ValidationResult,
    ascii_mode: bool | None = None,
    show_legend: bool = True,
) -> str:
    """Format validation result in compact form for Claude Code / non-TTY."""
    data = json_formatter.format_result(result)
    chars = _get_chars(ascii_mode)
    lines = []

    score = data.get("score", 0.0)
    level = data.get("level", "L1")
    level_label = LEVEL_LABELS.get(result.level, "Unknown")
    violations = data.get("violations", [])

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

    # Header line
    if deduped_count > 0:
        lines.append(f"Score: {score:.1f}/10 ({level_label} ({level})) - {deduped_count} violations")
    else:
        lines.append(f"Score: {score:.1f}/10 ({level_label} ({level})) {chars['check']} clean")
        return "\n".join(lines)

    lines.append("")

    severity_icons = {"critical": chars["crit"], "high": chars["high"], "medium": chars["med"], "low": chars["low"]}

    for file_path, unique in deduped_grouped.items():
        display_path = _normalize_path(file_path)
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

    # Friction
    friction = data.get("friction", {})
    friction_level = friction.get("level", "none")
    friction_minutes = friction.get("estimated_minutes", 0)
    if friction_level != "none" and friction_minutes >= 5:
        threshold_hint = ">=20" if friction_level == "high" else ">=10" if friction_level == "medium" else ">=5"
        lines.append(f"Friction: {friction_level.title()} (~{friction_minutes} min/session, threshold: {threshold_hint})")
        lines.append("")

    # Legend footer
    if deduped_count > 0 and show_legend:
        lines.append(f"Legend: {format_legend(ascii_mode)}")

    return "\n".join(lines).rstrip()


def format_score(result: ValidationResult, ascii_mode: bool | None = None) -> str:
    """Format quick score summary for terminal."""
    level_label = LEVEL_LABELS.get(result.level, "Unknown")
    violation_count = len(result.violations)

    if violation_count == 0:
        return f"ails: {result.score:.1f}/10 {level_label} ({result.level.value})"
    else:
        return f"ails: {result.score:.1f}/10 {level_label} ({result.level.value}) - {violation_count} violations"


def format_rule(rule_id: str, rule_data: dict[str, Any]) -> str:
    """Format rule explanation for terminal."""
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

    # Support both checks and legacy antipatterns
    checks = rule_data.get("checks", rule_data.get("antipatterns", []))
    if checks:
        lines.append("Checks:")
        for check in checks:
            lines.append(f"  - {check.get('id', '?')}: {check.get('name', 'Unknown')}")
            lines.append(f"    Severity: {check.get('severity', 'medium')}")
        lines.append("")

    see_also = rule_data.get("see_also", [])
    if see_also:
        lines.append("See Also:")
        for ref in see_also:
            lines.append(f"  - {ref}")

    return "\n".join(lines)
