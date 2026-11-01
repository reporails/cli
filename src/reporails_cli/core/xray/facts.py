"""The headline facts of a session, read from the artifacts, funnel and compactions already built."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.xray import (
    SourceEntry,
    XrayFact,
    XrayFunnelRow,
    XraySource,
    XrayTarget,
)
from reporails_cli.core.platform.dto.xray_graph import SourceKind, XrayCompaction


def _count(source: XraySource) -> int:
    return 0 if source.findings is None else source.findings.count


def _errors(source: XraySource) -> int:
    return 0 if source.findings is None else source.findings.by_severity["error"]


def _file_findings(sources: Sequence[XraySource]) -> tuple[XrayFact, ...]:
    """The fact of the findings over all files, pointing at the file with the most."""
    found = sorted(
        (item for item in sources if _count(item) > 0),
        key=lambda item: (-_count(item), -_errors(item), item.id),
    )
    if not found:
        return ()
    numbers = (
        ("findings", sum(_count(item) for item in found)),
        ("files", len(found)),
        ("errors", sum(_errors(item) for item in found)),
    )
    return (XrayFact("file_findings", None, numbers, XrayTarget("path", found[0].id)),)


def _funnel_drops(funnel: Sequence[XrayFunnelRow]) -> tuple[XrayFact, ...]:
    """One fact per kind whose used count is below the advertised count, else below the on-disk count."""
    facts: list[XrayFact] = []
    for row in funnel:
        base = row.on_disk if row.advertised is None else row.advertised
        if row.used is None or row.used >= base:
            continue
        counts = (("on_disk", row.on_disk), ("advertised", row.advertised), ("loaded", row.loaded), ("used", row.used))
        numbers = tuple((name, count) for name, count in counts if count is not None)
        facts.append(XrayFact("funnel_drop", row.kind, numbers, XrayTarget("kind", row.kind)))
    return tuple(facts)


def _memory_unlinked(entries: Sequence[SourceEntry]) -> tuple[XrayFact, ...]:
    """The fact of the memory files the memory index does not link, pointing at the first by path."""
    paths = sorted(item.id for item in entries if item.kind == "memory" and item.linked is False)
    if not paths:
        return ()
    return (XrayFact("memory_unlinked", "memory", (("count", len(paths)),), XrayTarget("path", paths[0])),)


def _compaction_losses(compactions: Sequence[tuple[str, XrayCompaction]]) -> tuple[XrayFact, ...]:
    """One fact per compaction whose context before and after are both known, pointing at the node it ran in."""
    facts: list[XrayFact] = []
    for node, item in compactions:
        if item.before is None or item.after is None:
            continue
        numbers = (("before", item.before), ("after", item.after), ("lost", item.before - item.after))
        facts.append(XrayFact("compaction_loss", None, numbers, XrayTarget("node", node)))
    return tuple(facts)


def _extra_tokens(source: XraySource) -> int:
    return 0 if source.tokens_est is None else source.tokens_est * (len(source.had_by) - 1)


def _repeated(sources: Sequence[XraySource]) -> tuple[XrayFact, ...]:
    """The fact of the files that entered more than one context, pointing at the one with the largest extra."""
    several = sorted((item for item in sources if item.path is not None and len(item.had_by) > 1), key=lambda i: i.id)
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
    compactions: Sequence[tuple[str, XrayCompaction]],
    kinds: Sequence[SourceKind],
) -> tuple[XrayFact, ...]:
    """The headline facts of the session, in the order the page shows them; `compactions` pairs each compaction
    with the id of the node it ran in and `kinds` lists the adapter's source kinds."""
    return (
        *_file_findings(sources),
        *_funnel_drops(funnel),
        *_memory_unlinked(entries),
        *_compaction_losses(compactions),
        *_repeated(sources),
        *_absent_kinds(funnel, kinds),
    )
