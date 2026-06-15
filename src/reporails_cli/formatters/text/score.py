"""Shared scoring + leverage-basis counting for the scorecard.

One scoring function (`score_for`) backs the whole-project, per-surface, and
per-file scores so the headline can't shift on a severity re-bucket. The score
reads as gate-distance — a compliance-band base, nudged down only by the
findings that actually move it (resolved leverage `gate_mover`). Cosmetic and
conditional findings carry no penalty weight.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from reporails_cli.core.platform.policy.leverage import LeverageTier, resolve_leverage

# Band base: the equation's pre-computed aggregate, stable under a re-bucket.
_BAND_BASE = {"HIGH": 8.5, "MODERATE": 5.5, "LOW": 3.0}
_OFFLINE_BASE = 6.0
# Gate-movers nudge; the band dominates. These coefficients are starting guesses
# flagged for corpus calibration — NOT measured constants. Calibrate against the
# validation corpus before treating either as load-bearing.
_MOVER_COEF = 20.0
_MOVER_PENALTY_CAP = 3.0


def _band_base(band: str) -> float:
    """Base score for a compliance band; neutral base when no band (offline)."""
    return _BAND_BASE.get(band, _OFFLINE_BASE)


def count_movers(findings: Sequence[Any]) -> int:
    """Count findings whose resolved leverage is `gate_mover`."""
    return sum(1 for f in findings if resolve_leverage(f) is LeverageTier.GATE_MOVER)


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


def score_for(band: str, findings: Sequence[Any], n_atoms: int) -> float:
    """0-10 gate-distance score: band base minus a gate-mover-only penalty.

    Stable under a severity re-bucket — only `gate_mover` findings penalize, so
    relabelling a non-mover error<->warning<->info leaves the score unchanged.
    `band` is "" for offline runs (no compliance band); the neutral base stands.
    The penalty is size-normalized so larger projects aren't penalized for
    having more findings to check.
    """
    if not findings:
        return 10.0
    base = _band_base(band)
    movers = count_movers(findings)
    if movers == 0:
        return float(round(max(0.0, min(10.0, base)), 1))
    denom = max(n_atoms, len(findings), 1)
    penalty = min(_MOVER_PENALTY_CAP, (movers / denom) * _MOVER_COEF)
    return float(round(max(0.0, min(10.0, base - penalty)), 1))
