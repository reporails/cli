"""Health model shared by the surface and per-item scorecards.

Owns the per-row health record, the atom-weighted mean score, and the finding-count tag.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from reporails_cli.formatters.text.display_constants import counted


@dataclass
class SurfaceHealth:
    """Per-surface health score for the scorecard."""

    name: str
    # `None` marks an unscored item/surface (no charged atoms — a non-instruction
    # surface or an empty instruction file); rendered as "not scored", no bar/band.
    score: float | None
    file_count: int
    finding_count: int
    # Items beside the type name: a skill folder counts once, every other file once.
    item_count: int
    errors: int = 0
    warnings: int = 0
    infos: int = 0
    # Findings grouped by Category enum value (`structure`, `direction`,
    # `coherence`, `efficiency`, `maintenance`, `governance`). Empty when no
    # findings have a recognizable category code. Sum of values equals
    # `finding_count` for findings whose rule-id second segment maps via
    # `CATEGORY_CODES`; rules with non-standard IDs are excluded.
    category_breakdown: dict[str, int] = field(default_factory=dict)


def mean_display_score(analyses: list[Any]) -> float | None:
    """Atom-weighted mean of the reported per-file display scores.

    A surface's bar (and the filtered headline) aggregate the same way the
    whole-project headline does. Unscored files (`display_score`
    is `None`) are excluded from the aggregation. Falls back to a
    simple mean when atom counts are unavailable; `None` when there is no scored analysis to aggregate.
    """
    scored = [
        (float(fa.display_score), int(fa.stats.get("atoms", 0)))
        for fa in analyses
        if fa is not None and fa.display_score is not None
    ]
    if not scored:
        return None
    total_weight = sum(w for _, w in scored)
    if total_weight <= 0:
        return round(sum(s for s, _ in scored) / len(scored), 1)
    return round(sum(s * w for s, w in scored) / total_weight, 1)


def count_tag(s: SurfaceHealth, count_width: int = 0) -> str:
    """Tag beside a health bar: `N findings · M errors` (the error part only when M > 0).

    One axis, whole then part, so the row answers "which surface is worst" without
    competing with the bar. Empty when the surface has no findings at all.
    """
    if not s.finding_count:
        return ""
    count = f"{s.finding_count:,}".rjust(count_width)
    tag = f"  [dim]{count} finding{'' if s.finding_count == 1 else 's'}[/dim]"
    if s.errors:
        tag += f"[dim] · [/dim][red]{counted(s.errors, 'error')}[/red]"
    return tag
