"""Score rendering helpers — leverage-basis counting + color thresholds.

The 0-10 score itself is the api's verdict; the CLI renders the returned scalar
and never computes one. This module keeps the render-side helpers: the
leverage-basis caption counts (score-movers / conditional / cosmetic) and the
single source of the score-color thresholds.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from reporails_cli.core.platform.policy.leverage import LeverageTier, resolve_leverage

# Score-color thresholds — the single place the green/yellow/red cutoffs live.
SCORE_GREEN_CUTOFF = 7.0
SCORE_YELLOW_CUTOFF = 4.0


def score_color(score: float) -> str:
    """Map a 0-10 score to its display color band."""
    if score >= SCORE_GREEN_CUTOFF:
        return "green"
    if score >= SCORE_YELLOW_CUTOFF:
        return "yellow"
    return "red"


def leverage_basis(findings: Sequence[Any]) -> tuple[int, int, int]:
    """Return `(score_movers, conditional, cosmetic)` counts over findings."""
    movers = conditional = cosmetic = 0
    for f in findings:
        tier = resolve_leverage(f)
        if tier is LeverageTier.GATE_MOVER:
            movers += 1
        elif tier is LeverageTier.CONDITIONAL:
            conditional += 1
        else:
            cosmetic += 1
    return movers, conditional, cosmetic
