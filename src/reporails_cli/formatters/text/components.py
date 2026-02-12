"""Reusable components for terminal output.

Small helper functions used by both full and compact formatters.
"""

from __future__ import annotations

import contextlib
import os

from reporails_cli.core.models import ScanDelta
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.templates import render


def format_legend(ascii_mode: bool | None = None) -> str:
    """Format severity legend for display."""
    chars = get_chars(ascii_mode)
    return render(
        "cli_legend.txt",
        crit=chars["crit"],
        high=chars["high"],
        med=chars["med"],
        low=chars["low"],
    )


def normalize_path(file_path: str, max_len: int = 50) -> str:
    """Normalize file path for display.

    Converts absolute paths to relative and truncates long paths.
    """
    if file_path.startswith("/"):
        with contextlib.suppress(ValueError):
            file_path = os.path.relpath(file_path)

    if len(file_path) <= max_len:
        return file_path

    parts = file_path.split("/")
    if len(parts) > 3:
        return ".../" + "/".join(parts[-3:])
    return file_path


def build_score_bar(score: float, ascii_mode: bool | None = None) -> str:
    """Build visual score bar for 0-10 scale."""
    chars = get_chars(ascii_mode)
    bar_width = 50
    filled = int((score / 10) * bar_width)
    filled = min(filled, bar_width)
    return chars["filled"] * filled + chars["empty"] * (bar_width - filled)


def format_score_delta(delta: ScanDelta | None, ascii_mode: bool | None = None) -> str:
    """Format score delta indicator."""
    if delta is None or delta.score_delta is None:
        return ""
    chars = get_chars(ascii_mode)
    if delta.score_delta > 0:
        return f"  {chars['up']} +{delta.score_delta:.1f}"
    else:
        return f"  {chars['down']} {delta.score_delta:.1f}"


def format_level_delta(delta: ScanDelta | None, ascii_mode: bool | None = None) -> str:
    """Format level delta indicator."""
    if delta is None or delta.level_previous is None:
        return ""
    chars = get_chars(ascii_mode)
    if delta.level_improved:
        return f"  {chars['up']} from {delta.level_previous}"
    else:
        return f"  {chars['down']} from {delta.level_previous}"


def format_violations_delta(delta: ScanDelta | None, ascii_mode: bool | None = None) -> str:
    """Format violations delta indicator."""
    if delta is None or delta.violations_delta is None:
        return ""
    chars = get_chars(ascii_mode)
    if delta.violations_delta < 0:
        # Decreased = good
        return f"  {chars['down']} {delta.violations_delta}"
    else:
        # Increased = bad
        return f"  {chars['up']} +{delta.violations_delta}"


def pad_line(content: str, width: int, v_char: str) -> str:
    """Pad content to fit box width.

    Content goes between vertical bars with padding.
    """
    inner = f"   {content}"
    if len(inner) > width - 3:
        inner = inner[: width - 6] + "..."
    return f"{v_char}{inner.ljust(width)}{v_char}"


def get_severity_label(severity: str, chars: dict[str, str]) -> str:
    """Get formatted severity label with icon."""
    return {
        "critical": f"{chars['crit']} CRIT",
        "high": f"{chars['high']} HIGH",
        "medium": f"{chars['med']} MED",
        "low": f"{chars['low']} LOW",
    }.get(severity, "???")


def get_severity_icons(chars: dict[str, str]) -> dict[str, str]:
    """Get severity icon mapping."""
    return {
        "critical": chars["crit"],
        "high": chars["high"],
        "medium": chars["med"],
        "low": chars["low"],
    }
