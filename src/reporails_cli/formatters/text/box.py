"""Assessment box formatting.

Handles the main score/capability box at the top of output.
"""
# pylint: disable=too-many-locals,too-many-statements

from __future__ import annotations

from typing import Any

from reporails_cli.core.levels import get_level_labels
from reporails_cli.core.models import ScanDelta
from reporails_cli.formatters.text.chars import ASCII_MODE, get_chars
from reporails_cli.formatters.text.components import (
    _category_result_color,
    _friction_color,
    _level_color,
    _score_color,
    _violations_count_color,
    build_score_bar,
    format_level_delta,
    format_score_delta,
    format_violations_delta,
    get_severity_icons,
    pad_line,
)
from reporails_cli.templates import render


def _format_category_table(
    cat_summary: list[dict[str, Any]],
    chars: dict[str, str],
    box_width: int,
    empty_line: str,
    colored: bool,
) -> str:
    """Format the category table inside the assessment box."""
    if not any(cs["total"] > 0 for cs in cat_summary):
        return empty_line

    sev_key_map = {"critical": "crit", "high": "high", "medium": "med", "low": "low"}
    severity_icons = get_severity_icons(chars, colored)
    cat_lines = []
    cat_lines.append(pad_line("Check            Result    Severity", box_width, chars["v"]))
    cat_lines.append(pad_line(chars["sep"] * 35, box_width, chars["v"]))
    for cs in cat_summary:
        name = cs["name"].title()
        if cs["total"]:
            stat_plain = f"{cs['passed']}/{cs['total']}"
            icon_plain = chars.get(sev_key_map.get(cs["worst_severity"] or "", ""), "") if cs["worst_severity"] else ""
            icon = severity_icons.get(cs["worst_severity"], "") if cs["worst_severity"] else ""
            if colored:
                rc = _category_result_color(cs["passed"], cs["total"])
                stat_rich = f"[{rc}]{stat_plain}[/{rc}]"
                stat_extra = len(stat_rich) - len(stat_plain)
                icon_extra = len(icon) - len(icon_plain) if icon else 0
            else:
                stat_rich = stat_plain
                stat_extra = 0
                icon_extra = 0
            row = f"{name:<17}{stat_rich:<{10 + stat_extra}}{icon}"
            row_extra = stat_extra + icon_extra
        else:
            if colored:
                stat_rich = "[dim]\u2013[/dim]"
                stat_extra = len(stat_rich) - 1  # plain is just en-dash
            else:
                stat_rich = "\u2013"
                stat_extra = 0
            row = f"{name:<17}{stat_rich:<{10 + stat_extra}}"
            row_extra = stat_extra
        cat_lines.append(pad_line(row, box_width + row_extra, chars["v"]))
    cat_lines.append(empty_line)
    return "\n".join(cat_lines)


def _format_summary_line(
    violations: list[dict[str, Any]],
    rules_checked: int,
    viol_delta_plain: str,
    viol_delta_rich: str,
    colored: bool,
    box_width: int,
    chars: dict[str, str],
) -> str:
    """Format the violations summary line inside the box."""
    seen: set[tuple[str, str]] = set()
    for v in violations:
        location = v.get("location", "")
        file_path = location.rsplit(":", 1)[0] if ":" in location else location
        seen.add((file_path, v.get("rule_id", "")))
    violation_count = len(seen)
    if violation_count == 0:
        summary_plain = f"No violations \u00b7 {rules_checked} rules checked"
        if colored:
            vc = _violations_count_color(violation_count)
            summary_rich = f"[{vc}]No violations[/{vc}] \u00b7 {rules_checked} rules checked"
            summary_extra = len(summary_rich) - len(summary_plain)
        else:
            summary_rich = summary_plain
            summary_extra = 0
    else:
        count_str = f"{violation_count}"
        summary_plain = f"{count_str} violation(s){viol_delta_plain} \u00b7 {rules_checked} rules checked"
        if colored:
            vc = _violations_count_color(violation_count)
            summary_rich = (
                f"[{vc}]{count_str}[/{vc}] violation(s){viol_delta_rich} \u00b7 {rules_checked} rules checked"
            )
            summary_extra = len(summary_rich) - len(summary_plain)
        else:
            summary_rich = summary_plain
            summary_extra = 0
    return pad_line(summary_rich, box_width + summary_extra, chars["v"])


def _format_friction_line(
    data: dict[str, Any],
    colored: bool,
    box_width: int,
    chars: dict[str, str],
    empty_line: str,
) -> str:
    """Format the friction line inside the box."""
    friction_raw = data.get("friction", "none")
    friction_level = friction_raw if isinstance(friction_raw, str) else friction_raw.get("level", "none")
    if friction_level == "none":
        return empty_line
    friction_plain = f"Friction: {friction_level.title()}"
    if colored:
        fc = _friction_color(friction_level)
        friction_rich = f"Friction: [bold {fc}]{friction_level.title()}[/bold {fc}]"
    else:
        friction_rich = f"Friction: [underline]{friction_level.title()}[/underline]"
    markup_extra = len(friction_rich) - len(friction_plain)
    return pad_line(friction_rich, box_width + markup_extra, chars["v"])


def format_assessment_box(
    data: dict[str, Any],
    ascii_mode: bool | None = None,
    delta: ScanDelta | None = None,
) -> str:
    """Format the visual assessment box using templates."""
    chars = get_chars(ascii_mode)
    box_width = 62

    # Determine coloring: enabled unless ASCII mode
    use_ascii = ascii_mode if ascii_mode is not None else ASCII_MODE
    colored = not use_ascii

    score = data.get("score", 0.0)
    level = data.get("level", "L1")
    feature_summary = data.get("feature_summary", "")
    summary_info = data.get("summary", {})
    rules_checked = summary_info.get("rules_checked", 0)
    violations = data.get("violations", [])

    level_label = get_level_labels().get(level, level)

    # Plain delta strings (always uncolored, for width calculations)
    score_delta_plain, _ = format_score_delta(delta, ascii_mode, colored=False)
    level_delta_plain, _ = format_level_delta(delta, ascii_mode, colored=False)
    viol_delta_plain, _ = format_violations_delta(delta, ascii_mode, colored=False)

    # Colored delta strings (may contain Rich markup)
    score_delta_rich, _ = format_score_delta(delta, ascii_mode, colored)
    level_delta_rich, _ = format_level_delta(delta, ascii_mode, colored)
    viol_delta_rich, _ = format_violations_delta(delta, ascii_mode, colored)

    # Orphan features → L3+ display
    has_orphan = data.get("has_orphan_features", False)
    level_display = f"{level}+" if has_orphan else level

    # Build individual lines
    top_border = chars["tl"] + chars["h"] * box_width + chars["tr"]
    bottom_border = chars["bl"] + chars["h"] * box_width + chars["br"]
    empty_line = chars["v"] + " " * box_width + chars["v"]

    # Score line: left = score, right = capability (right-aligned)
    # Use plain strings for width calculation
    left_plain = f"SCORE: {score:.1f} / 10{score_delta_plain}"
    right_plain = f"CAPABILITY: {level_label} ({level_display}){level_delta_plain}"

    gap = box_width - 3 - len(left_plain) - len(right_plain) - 3
    if gap < 3:
        # Word-boundary truncation for level label
        max_label = box_width - 3 - len(left_plain) - 3 - len(f"CAPABILITY:  ({level_display}){level_delta_plain}") - 3
        max_label = max(max_label, 3)
        truncated = level_label[:max_label]
        last_space = truncated.rfind(" ")
        if last_space > max_label // 2:
            truncated = truncated[:last_space]
        level_label = truncated.rstrip() + "..."
        right_plain = f"CAPABILITY: {level_label} ({level_display}){level_delta_plain}"
        gap = box_width - 3 - len(left_plain) - len(right_plain) - 3

    # Build the rich or plain score text
    if colored:
        sc = _score_color(score)
        lc = _level_color(level)
        left_rich = f"SCORE: [bold {sc}]{score:.1f}[/bold {sc}] / 10{score_delta_rich}"
        right_rich = f"CAPABILITY: [{lc}]{level_label} ({level_display})[/{lc}]{level_delta_rich}"
        score_text = f"{left_rich}{' ' * gap}{right_rich}"
        score_extra = len(score_text) - len(left_plain) - gap - len(right_plain)
    else:
        score_text = f"{left_plain}{' ' * gap}{right_plain}"
        score_extra = 0
    score_line = pad_line(score_text, box_width + score_extra, chars["v"])

    # Progress bar
    bar, bar_extra = build_score_bar(score, ascii_mode, colored)
    bar_line = pad_line(bar, box_width + bar_extra, chars["v"])

    # Setup line
    setup_text = f"Setup: {feature_summary}"
    setup_line = pad_line(setup_text, box_width, chars["v"])

    summary_line = _format_summary_line(
        violations, rules_checked, viol_delta_plain, viol_delta_rich, colored, box_width, chars
    )
    friction_line = _format_friction_line(data, colored, box_width, chars, empty_line)

    # Category table inside box
    cat_summary = data.get("category_summary", [])
    category_section = _format_category_table(cat_summary, chars, box_width, empty_line, colored)

    return render(
        "cli_box.txt",
        top_border=top_border,
        bottom_border=bottom_border,
        empty_line=empty_line,
        score_line=score_line,
        bar_line=bar_line,
        setup_line=setup_line,
        summary_line=summary_line,
        friction_line=friction_line,
        category_section=category_section,
    )
