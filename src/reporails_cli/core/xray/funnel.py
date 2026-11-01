"""How many sources of each kind sit on disk, are advertised, load and are used."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.xray import SourceEntry, XrayFunnelRow, XraySource
from reporails_cli.core.platform.dto.xray_graph import SourceKind


def _used(kind: SourceKind, items: Sequence[SourceEntry], had: set[str], ran: set[str]) -> int | None:
    if kind == "skill":
        return sum(1 for item in items if item.id in ran)
    if kind == "memory":
        return sum(1 for item in items if item.linked is True and item.id in had)
    return None


def build_funnel(
    entries: Sequence[SourceEntry], sources: Sequence[XraySource], kinds: Sequence[SourceKind], ran: set[str]
) -> tuple[XrayFunnelRow, ...]:
    """One row per source kind in `kinds` that has a source, in that order; `ran` holds the ids of the skill and
    command sources that ran."""
    had = {source.id for source in sources if source.had_by}
    rows: list[XrayFunnelRow] = []
    for kind in kinds:
        items = [item for item in entries if item.kind == kind]
        if not items:
            continue
        marks = [item.advertised for item in items if item.advertised is not None]
        rows.append(
            XrayFunnelRow(
                kind=kind,
                on_disk=len(items),
                advertised=sum(marks) if marks else None,
                loaded=sum(1 for item in items if item.id in had),
                used=_used(kind, items, had, ran),
            )
        )
    return tuple(rows)
