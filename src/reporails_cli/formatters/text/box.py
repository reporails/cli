"""Assessment box formatting.

Handles the main score/capability box at the top of output.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.models import ScanDelta
from reporails_cli.core.scorer import LEVEL_LABELS
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.formatters.text.components import (
    build_score_bar,
    format_level_delta,
    format_score_delta,
    format_violations_delta,
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
    is_partial = data.get("is_partial", True)

    level_label = LEVEL_LABELS.get(level, level)

    # Delta indicators
    score_delta_str = format_score_delta(delta, ascii_mode)
    level_delta_str = format_level_delta(delta, ascii_mode)
    violations_delta_str = format_violations_delta(delta, ascii_mode)

    # Partial marker
    partial_marker = "(partial)" if is_partial else ""

    # Build individual lines
    top_border = chars["tl"] + chars["h"] * box_width + chars["tr"]
    bottom_border = chars["bl"] + chars["h"] * box_width + chars["br"]
    empty_line = chars["v"] + " " * box_width + chars["v"]

    # Score line with capability and delta
    score_text = f"SCORE: {score:.1f} / 10 {partial_marker}{score_delta_str}  |  CAPABILITY: {level_label} ({level}){level_delta_str}"
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
        summary = f"No violations · {rules_checked} rules checked"
    else:
        summary = f"{violation_count} violation(s){violations_delta_str} · {rules_checked} rules checked"
    summary_line = pad_line(summary, box_width, chars["v"])

    return render("cli_box.txt",
        top_border=top_border,
        bottom_border=bottom_border,
        empty_line=empty_line,
        score_line=score_line,
        bar_line=bar_line,
        setup_line=setup_line,
        summary_line=summary_line,
    )
