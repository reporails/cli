"""Reusable components for terminal output.

Small helper functions used by both full and compact formatters.
"""

from __future__ import annotations

import contextlib
import os

from reporails_cli.core.models import ScanDelta
from reporails_cli.formatters.text.chars import get_chars
from reporails_cli.templates import render

# --- Color helpers ---

SEVERITY_COLORS: dict[str, str] = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}


def _score_color(score: float) -> str:
    if score >= 8:
        return "green"
    if score >= 6:
        return "yellow"
    return "red"


def _level_color(level: str) -> str:
    if level in ("L5", "L6"):
        return "green"
    if level in ("L3", "L4"):
        return "cyan"
    if level in ("L1", "L2"):
        return "yellow"
    return "red"


def _friction_color(friction: str) -> str:
    low = friction.lower()
    if low == "high":
        return "red"
    if low == "medium":
        return "yellow"
    return "green"


def _violations_count_color(count: int) -> str:
    if count > 5:
        return "red"
    if count > 0:
        return "yellow"
    return "green"


def _category_result_color(passed: int, total: int) -> str:
    if total == 0:
        return "dim"
    ratio = passed / total
    if ratio >= 1.0:
        return "green"
    if ratio > 0.5:
        return "yellow"
    return "red"


def format_legend(ascii_mode: bool | None = None, colored: bool = False) -> str:
    """Format severity legend for display."""
    chars = get_chars(ascii_mode)
    if colored:
        return render(
            "cli_legend.txt",
            crit=f"[red]{chars['crit']}[/red]",
            high=f"[red]{chars['high']}[/red]",
            med=f"[yellow]{chars['med']}[/yellow]",
            low=f"[green]{chars['low']}[/green]",
        )
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


def build_score_bar(score: float, ascii_mode: bool | None = None, colored: bool = False) -> tuple[str, int]:
    """Build visual score bar for 0-10 scale.

    Returns (bar_string, markup_extra) where markup_extra is the number
    of invisible Rich markup characters added.
    """
    chars = get_chars(ascii_mode)
    bar_width = 50
    filled = int((score / 10) * bar_width)
    filled = min(filled, bar_width)
    filled_str = chars["filled"] * filled
    empty_str = chars["empty"] * (bar_width - filled)
    if colored and filled_str:
        color = _score_color(score)
        rich = f"[{color}]{filled_str}[/{color}][dim]{empty_str}[/dim]"
        plain_len = len(filled_str) + len(empty_str)
        return (rich, len(rich) - plain_len)
    return (filled_str + empty_str, 0)


def format_score_delta(
    delta: ScanDelta | None, ascii_mode: bool | None = None, colored: bool = False
) -> tuple[str, int]:
    """Format score delta indicator.

    Returns (delta_string, markup_extra).
    """
    if delta is None or delta.score_delta is None:
        return ("", 0)
    chars = get_chars(ascii_mode)
    if delta.score_delta > 0:
        plain = f"  {chars['up']} +{delta.score_delta:.1f}"
        if colored:
            rich = f"  [green]{chars['up']} +{delta.score_delta:.1f}[/green]"
            return (rich, len(rich) - len(plain))
        return (plain, 0)
    else:
        plain = f"  {chars['down']} {delta.score_delta:.1f}"
        if colored:
            rich = f"  [red]{chars['down']} {delta.score_delta:.1f}[/red]"
            return (rich, len(rich) - len(plain))
        return (plain, 0)


def format_level_delta(
    delta: ScanDelta | None, ascii_mode: bool | None = None, colored: bool = False
) -> tuple[str, int]:
    """Format level delta indicator.

    Returns (delta_string, markup_extra).
    """
    if delta is None or delta.level_previous is None:
        return ("", 0)
    chars = get_chars(ascii_mode)
    if delta.level_improved:
        plain = f"  {chars['up']} from {delta.level_previous}"
        if colored:
            rich = f"  [green]{chars['up']} from {delta.level_previous}[/green]"
            return (rich, len(rich) - len(plain))
        return (plain, 0)
    else:
        plain = f"  {chars['down']} from {delta.level_previous}"
        if colored:
            rich = f"  [red]{chars['down']} from {delta.level_previous}[/red]"
            return (rich, len(rich) - len(plain))
        return (plain, 0)


def format_violations_delta(
    delta: ScanDelta | None, ascii_mode: bool | None = None, colored: bool = False
) -> tuple[str, int]:
    """Format violations delta indicator.

    Returns (delta_string, markup_extra).
    """
    if delta is None or delta.violations_delta is None:
        return ("", 0)
    chars = get_chars(ascii_mode)
    if delta.violations_delta < 0:
        # Decreased = good
        plain = f"  {chars['down']} {delta.violations_delta}"
        if colored:
            rich = f"  [green]{chars['down']} {delta.violations_delta}[/green]"
            return (rich, len(rich) - len(plain))
        return (plain, 0)
    else:
        # Increased = bad
        plain = f"  {chars['up']} +{delta.violations_delta}"
        if colored:
            rich = f"  [red]{chars['up']} +{delta.violations_delta}[/red]"
            return (rich, len(rich) - len(plain))
        return (plain, 0)


def pad_line(content: str, width: int, v_char: str) -> str:
    """Pad content to fit box width.

    Content goes between vertical bars with padding.
    """
    inner = f"   {content}"
    if len(inner) > width - 3:
        inner = inner[: width - 6] + "..."
    return f"{v_char}{inner.ljust(width)}{v_char}"


def get_severity_label(severity: str, chars: dict[str, str], colored: bool = False) -> str:
    """Get formatted severity label with icon."""
    plain = {
        "critical": f"{chars['crit']} CRIT",
        "high": f"{chars['high']} HIGH",
        "medium": f"{chars['med']} MED",
        "low": f"{chars['low']} LOW",
    }.get(severity, "???")
    if colored and severity in SEVERITY_COLORS:
        c = SEVERITY_COLORS[severity]
        return f"[{c}]{plain}[/{c}]"
    return plain


def get_severity_icons(chars: dict[str, str], colored: bool = False) -> dict[str, str]:
    """Get severity icon mapping."""
    icons = {
        "critical": chars["crit"],
        "high": chars["high"],
        "medium": chars["med"],
        "low": chars["low"],
    }
    if colored:
        return {sev: f"[{SEVERITY_COLORS[sev]}]{icon}[/{SEVERITY_COLORS[sev]}]" for sev, icon in icons.items()}
    return icons
