"""The lines that name a healed file that has slipped since the heal."""

from __future__ import annotations

from collections.abc import Iterable

from rich.console import Console
from rich.markup import escape

from reporails_cli.core.platform.dto.heal import HealRegression
from reporails_cli.core.platform.utils.utils import format_score
from reporails_cli.formatters.text.chars import get_chars

# The most rules one line names; the rest are counted.
_RULES_NAMED = 3


def heal_regression_sentence(regression: HealRegression, arrow: str) -> str:
    """`Since the last heal: <file> score 8.4 → 7.9; findings back: <rule> +2, ...`, plain text."""
    parts: list[str] = []
    if regression.score_before is not None and regression.score_after is not None:
        parts.append(f"score {format_score(regression.score_before)} {arrow} {format_score(regression.score_after)}")
    if regression.rules:
        ranked = sorted(regression.rules.items(), key=lambda item: -item[1])
        named = ", ".join(f"{rule} +{n}" for rule, n in ranked[:_RULES_NAMED])
        more = f" and {len(ranked) - _RULES_NAMED} more" if len(ranked) > _RULES_NAMED else ""
        parts.append(f"findings back: {named}{more}")
    return f"Since the last heal: {regression.file} {'; '.join(parts)}"


def heal_regression_lines(regressions: Iterable[HealRegression], ascii_mode: bool | None = None) -> list[str]:
    """One dim line per regressed file; empty when none."""
    arrow = get_chars(ascii_mode)["arrow"]
    return [f"[dim]{escape(heal_regression_sentence(r, arrow))}[/dim]" for r in regressions]


def print_heal_regressions(console: Console, regressions: Iterable[HealRegression], ascii_mode: bool) -> None:
    """Print the lines under the run's results; nothing when no healed file slipped."""
    lines = heal_regression_lines(regressions, ascii_mode)
    if lines:
        console.print()
        for line in lines:
            console.print(f"  {line}", soft_wrap=True)
