"""Assessment box formatting.

Handles the main score/capability box at the top of output.
"""
# pylint: disable=too-many-locals,too-many-statements

from __future__ import annotations

from typing import Any

from reporails_cli.core.levels import get_level_labels
from reporails_cli.core.models import ScanDelta
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.formatters.text.components import (
    build_score_bar,
    format_level_delta,
    format_score_delta,
    format_violations_delta,
    get_severity_icons,
    pad_line,
)
from reporails_cli.templates import render


def format_assessment_box(
    data: dict[str, Any],
    ascii_mode: bool | None = None,
    delta: ScanDelta | None = None,
) -> str:
    """Format the visual assessment box using templates."""
    chars = get_chars(ascii_mode)
    box_width = 62

    score = data.get("score", 0.0)
    level = data.get("level", "L1")
    feature_summary = data.get("feature_summary", "")
    summary_info = data.get("summary", {})
    rules_checked = summary_info.get("rules_checked", 0)
    violations = data.get("violations", [])

    level_label = get_level_labels().get(level, level)

    # Delta indicators
    score_delta_str = format_score_delta(delta, ascii_mode)
    level_delta_str = format_level_delta(delta, ascii_mode)
    violations_delta_str = format_violations_delta(delta, ascii_mode)

    # Orphan features → L3+ display
    has_orphan = data.get("has_orphan_features", False)
    level_display = f"{level}+" if has_orphan else level

    # Build individual lines
    top_border = chars["tl"] + chars["h"] * box_width + chars["tr"]
    bottom_border = chars["bl"] + chars["h"] * box_width + chars["br"]
    empty_line = chars["v"] + " " * box_width + chars["v"]

    # Score line: left = score, right = capability (right-aligned)
    left = f"SCORE: {score:.1f} / 10{score_delta_str}"
    right = f"CAPABILITY: {level_label} ({level_display}){level_delta_str}"
    # 3-char left pad + left + gap + right + 3-char right pad = box_width
    gap = box_width - 3 - len(left) - len(right) - 3
    if gap < 3:
        # Word-boundary truncation for level label
        max_label = box_width - 3 - len(left) - 3 - len(f"CAPABILITY:  ({level_display}){level_delta_str}") - 3
        max_label = max(max_label, 3)
        truncated = level_label[:max_label]
        # Find last space for word boundary
        last_space = truncated.rfind(" ")
        if last_space > max_label // 2:
            truncated = truncated[:last_space]
        level_label = truncated.rstrip() + "..."
        right = f"CAPABILITY: {level_label} ({level_display}){level_delta_str}"
        gap = box_width - 3 - len(left) - len(right) - 3
    score_text = f"{left}{' ' * gap}{right}"
    score_line = pad_line(score_text, box_width, chars["v"])

    # Progress bar
    bar = build_score_bar(score, ascii_mode)
    bar_line = pad_line(bar, box_width, chars["v"])

    # Setup line
    setup_text = f"Setup: {feature_summary}"
    setup_line = pad_line(setup_text, box_width, chars["v"])

    # Summary line - count deduplicated violations
    seen_violations: set[tuple[str, str]] = set()
    for v in violations:
        location = v.get("location", "")
        file_path = location.rsplit(":", 1)[0] if ":" in location else location
        rule_id = v.get("rule_id", "")
        seen_violations.add((file_path, rule_id))
    violation_count = len(seen_violations)
    if violation_count == 0:
        summary_text = f"No violations · {rules_checked} rules checked"
    else:
        summary_text = f"{violation_count} violation(s){violations_delta_str} · {rules_checked} rules checked"
    summary_line = pad_line(summary_text, box_width, chars["v"])

    # Friction line (below summary, only if friction is present)
    friction_raw = data.get("friction", "none")
    friction_level = friction_raw if isinstance(friction_raw, str) else friction_raw.get("level", "none")
    if friction_level != "none":
        friction_plain = f"Friction: {friction_level.title()}"
        friction_rich = f"Friction: [underline]{friction_level.title()}[/underline]"
        markup_extra = len(friction_rich) - len(friction_plain)
        friction_line = pad_line(friction_rich, box_width + markup_extra, chars["v"])
    else:
        friction_line = empty_line

    # Category table inside box
    cat_summary = data.get("category_summary", [])
    if any(cs["total"] > 0 for cs in cat_summary):
        severity_icons = get_severity_icons(chars)
        cat_lines = []
        cat_lines.append(pad_line("Check            Result    Severity", box_width, chars["v"]))
        cat_lines.append(pad_line(chars["sep"] * 35, box_width, chars["v"]))
        for cs in cat_summary:
            name = cs["name"].title()
            if cs["total"]:
                stat = f"{cs['passed']}/{cs['total']}"
                icon = severity_icons.get(cs["worst_severity"], "") if cs["worst_severity"] else ""
            else:
                stat = "\u2013"
                icon = ""
            row = f"{name:<17}{stat:<10}{icon}"
            cat_lines.append(pad_line(row, box_width, chars["v"]))
        cat_lines.append(empty_line)
        category_section = "\n".join(cat_lines)
    else:
        category_section = empty_line

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
