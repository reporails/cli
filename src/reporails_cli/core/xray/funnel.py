"""How many sources of each kind sit on disk, are advertised, load and are used."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.xray import XrayFunnelRow
from reporails_cli.core.platform.dto.xray_build import SourceTable
from reporails_cli.core.platform.dto.xray_graph import SourceKind
from reporails_cli.core.platform.dto.xray_sources import SourceEntry, XraySource


def _used(kind: SourceKind, items: Sequence[SourceEntry], had: set[str], ran: set[str]) -> int | None:
    if kind == "skill":
        return sum(1 for item in items if item.id in ran)
    if kind == "memory":
        return sum(1 for item in items if item.linked is True and item.id in had)
    return None


def build_funnel(
    table: SourceTable, sources: Sequence[XraySource], kinds: Sequence[SourceKind], ran: set[str]
) -> tuple[XrayFunnelRow, ...]:
    """One row per source kind in `kinds` that has a source, in that order, the built-in agent types counted; `ran`
    holds the ids of the skill and command sources that ran. A kind whose loads the session does not record has
    no loaded or used count."""
    had = {source.id for source in sources if source.availability == "loaded"}
    entries = table.entries
    unrecorded = table.unrecorded
    rows: list[XrayFunnelRow] = []
    for kind in kinds:
        items = [item for item in entries if item.kind == kind]
        builtin = [source for source in sources if source.kind == kind and source.builtin]
        if not items and not builtin:
            continue
        marks = [item.advertised for item in items if item.advertised is not None]
        rows.append(
            XrayFunnelRow(
                kind=kind,
                on_disk=len(items) + len(builtin),
                advertised=sum(marks) if marks else None,
                loaded=None
                if kind in unrecorded
                else sum(1 for item in items if item.id in had) + sum(1 for source in builtin if source.had_by),
                used=None if kind in unrecorded else _used(kind, items, had, ran),
            )
        )
    return tuple(rows)
