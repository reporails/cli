"""The headline facts of a session, read from the artifacts, funnel and compactions already built."""

from __future__ import annotations

from collections.abc import Sequence
from typing import get_args

from reporails_cli.core.platform.dto.xray import (
    ArtifactKind,
    XrayArtifact,
    XrayCompaction,
    XrayFact,
    XrayFunnelRow,
    XrayTarget,
)


def _count(artifact: XrayArtifact) -> int:
    return 0 if artifact.findings is None else artifact.findings.count


def _errors(artifact: XrayArtifact) -> int:
    return 0 if artifact.findings is None else artifact.findings.by_severity["error"]


def _file_findings(artifacts: Sequence[XrayArtifact]) -> tuple[XrayFact, ...]:
    """The fact of the findings over all files, pointing at the file with the most."""
    found = sorted(
        (item for item in artifacts if _count(item) > 0),
        key=lambda item: (-_count(item), -_errors(item), item.path),
    )
    if not found:
        return ()
    numbers = (
        ("findings", sum(_count(item) for item in found)),
        ("files", len(found)),
        ("errors", sum(_errors(item) for item in found)),
    )
    return (XrayFact("file_findings", None, numbers, XrayTarget("path", found[0].path)),)


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


def _memory_unlinked(artifacts: Sequence[XrayArtifact]) -> tuple[XrayFact, ...]:
    """The fact of the memory files the memory index does not link, pointing at the first by path."""
    paths = sorted(item.path for item in artifacts if item.kind == "memory" and item.linked is False)
    if not paths:
        return ()
    return (XrayFact("memory_unlinked", "memory", (("count", len(paths)),), XrayTarget("path", paths[0])),)


def _compaction_losses(compactions: Sequence[XrayCompaction]) -> tuple[XrayFact, ...]:
    """One fact per compaction whose context before and after are both known."""
    facts: list[XrayFact] = []
    for item in compactions:
        if item.before is None or item.after is None:
            continue
        numbers = (("before", item.before), ("after", item.after), ("lost", item.before - item.after))
        facts.append(XrayFact("compaction_loss", None, numbers, XrayTarget("turn", item.turn)))
    return tuple(facts)


def _extra_tokens(artifact: XrayArtifact) -> int:
    if artifact.tokens_est is None or artifact.session_tokens_est is None:
        return 0
    return artifact.session_tokens_est - artifact.tokens_est


def _repeated(artifacts: Sequence[XrayArtifact]) -> tuple[XrayFact, ...]:
    """The fact of the files that entered more than one context, pointing at the one with the largest extra."""
    several = sorted((item for item in artifacts if item.contexts > 1), key=lambda item: item.path)
    if not several:
        return ()
    numbers = (
        ("files", len(several)),
        ("contexts", max(item.contexts for item in several)),
        ("tokens_est", sum(_extra_tokens(item) for item in several)),
    )
    largest = max(several, key=_extra_tokens)
    return (XrayFact("repeated_instructions", None, numbers, XrayTarget("path", largest.path)),)


def _absent_kinds(funnel: Sequence[XrayFunnelRow]) -> tuple[XrayFact, ...]:
    """One fact per artifact kind with nothing on disk."""
    present = {row.kind for row in funnel}
    absent: list[ArtifactKind] = [kind for kind in get_args(ArtifactKind) if kind not in present]
    return tuple(XrayFact("kind_absent", kind, (), XrayTarget("kind", kind)) for kind in absent)


def build_facts(
    artifacts: Sequence[XrayArtifact], funnel: Sequence[XrayFunnelRow], compactions: Sequence[XrayCompaction]
) -> tuple[XrayFact, ...]:
    """The headline facts of the session, in the order the page shows them."""
    return (
        *_file_findings(artifacts),
        *_funnel_drops(funnel),
        *_memory_unlinked(artifacts),
        *_compaction_losses(compactions),
        *_repeated(artifacts),
        *_absent_kinds(funnel),
    )
