"""The headline facts of a session, read from the artifacts, funnel and sources already built."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.xray import XrayFact, XrayFunnelRow, XrayTarget
from reporails_cli.core.platform.dto.xray_graph import SourceKind
from reporails_cli.core.platform.dto.xray_sources import SourceEntry, XraySource


def _memory_unlinked(entries: Sequence[SourceEntry]) -> tuple[XrayFact, ...]:
    """The fact of the memory files the memory index does not link, pointing at the first by path."""
    paths = sorted(item.id for item in entries if item.kind == "memory" and item.linked is False)
    if not paths:
        return ()
    return (XrayFact("memory_unlinked", "memory", (("count", len(paths)),), XrayTarget("path", paths[0])),)


def _extra_tokens(source: XraySource) -> int:
    return 0 if source.tokens_est is None else source.tokens_est * (len(source.had_by) - 1)


def _repeated(sources: Sequence[XraySource], definitions: frozenset[SourceKind]) -> tuple[XrayFact, ...]:
    """The fact of the files that entered more than one context, pointing at the one with the largest extra; a
    source of a kind in `definitions` is left out, as each subagent must receive its own."""
    several = sorted(
        (item for item in sources if item.path is not None and item.kind not in definitions and len(item.had_by) > 1),
        key=lambda i: i.id,
    )
    if not several:
        return ()
    numbers = (
        ("files", len(several)),
        ("contexts", max(len(item.had_by) for item in several)),
        ("tokens_est", sum(_extra_tokens(item) for item in several)),
    )
    largest = max(several, key=_extra_tokens)
    return (XrayFact("repeated_instructions", None, numbers, XrayTarget("path", largest.id)),)


def _absent_kinds(funnel: Sequence[XrayFunnelRow], kinds: Sequence[SourceKind]) -> tuple[XrayFact, ...]:
    """One fact per source kind of the adapter with no source at all."""
    present = {row.kind for row in funnel}
    return tuple(XrayFact("kind_absent", kind, (), XrayTarget("kind", kind)) for kind in kinds if kind not in present)


def build_facts(
    entries: Sequence[SourceEntry],
    sources: Sequence[XraySource],
    funnel: Sequence[XrayFunnelRow],
    kinds: Sequence[SourceKind],
    definitions: frozenset[SourceKind],
) -> tuple[XrayFact, ...]:
    """The headline facts of the session, in the order the page shows them; `kinds` lists the adapter's source
    kinds and `definitions` those whose sources subagents are launched from."""
    return (
        *_memory_unlinked(entries),
        *_repeated(sources, definitions),
        *_absent_kinds(funnel, kinds),
    )
