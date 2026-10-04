"""Score rendering helpers — the single source of the score-color thresholds.

The CLI renders the returned score scalar and never computes one.
"""

from __future__ import annotations

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
