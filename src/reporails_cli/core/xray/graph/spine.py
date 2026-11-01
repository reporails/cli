"""The facts every node with a spine has, read from its loads and calls whatever its kind."""

from __future__ import annotations

from collections.abc import Sequence
from itertools import pairwise

from reporails_cli.core.platform.dto.events import ToolCategory
from reporails_cli.core.platform.dto.xray import AdapterVocabulary
from reporails_cli.core.platform.dto.xray_build import ProducedCall, ProducedNode, SourceTable
from reporails_cli.core.platform.dto.xray_graph import (
    LoadEvent,
    SourceKind,
    XrayBreak,
    XrayCall,
    XrayFailureRun,
    XrayMcpCluster,
    XraySlot,
    XrayWithheld,
    XrayWithheldSource,
)

# MCP calls to one server merge into one cluster while the gap to the one before is at most this share of the
# node's span.
CLUSTER_GAP_SHARE = 0.09

# Shell calls in a row with one command, all failed, that make a failure run.
FAILURE_RUN_MIN = 3

# A stretch with no record this long (seconds) is a break.
BREAK_S = 1800.0


def had_sources(node: ProducedNode) -> list[str]:
    """The ids of the sources that entered the node's context, in the order they first did: its loads, and the MCP
    servers whose results it took in."""
    ids = [load.source for load in node.spine.loads]
    ids.extend(call.mcp_source for call in node.spine.calls if call.mcp_source is not None)
    return list(dict.fromkeys(ids))


def slots(had: Sequence[str], sources: SourceTable, vocabulary: AdapterVocabulary) -> dict[SourceKind, XraySlot]:
    """For each source kind of the vocabulary, how many sources of it the node had and their findings together."""
    counts = {kind.key: [0, 0] for kind in vocabulary.source_kinds}
    for source_id in had:
        entry = sources.get(source_id)
        if entry is None or entry.kind not in counts:
            continue
        counts[entry.kind][0] += 1
        counts[entry.kind][1] += 0 if entry.findings is None else entry.findings.count
    return {kind: XraySlot(count, findings) for kind, (count, findings) in counts.items()}


def tool_counts(node: ProducedNode, vocabulary: AdapterVocabulary) -> dict[ToolCategory, int]:
    """For each tool category of the vocabulary, how many calls the node made."""
    return {
        info.key: sum(1 for call in node.spine.calls if call.category == info.key) for info in vocabulary.categories
    }


def track_calls(node: ProducedNode, vocabulary: AdapterVocabulary) -> tuple[XrayCall, ...]:
    """The node's calls whose category sits on the side track, in time order."""
    tracked = {info.key for info in vocabulary.categories if info.track}
    return tuple(
        XrayCall(call.t, call.category, call.label, call.source, call.failed, call.use_id)
        for call in sorted(node.spine.calls, key=lambda item: item.t)
        if call.category in tracked
    )


def mcp_clusters(node: ProducedNode) -> tuple[XrayMcpCluster, ...]:
    """The node's MCP calls per server, merged into clusters of calls close together in time."""
    limit = CLUSTER_GAP_SHARE * (node.end - node.start)
    groups: dict[str, list[list[ProducedCall]]] = {}
    for call in sorted(node.spine.calls, key=lambda item: item.t):
        if call.mcp_source is None:
            continue
        runs = groups.setdefault(call.mcp_source, [])
        if runs and call.t - runs[-1][-1].t <= limit:
            runs[-1].append(call)
        else:
            runs.append([call])
    clusters = [
        XrayMcpCluster(
            server,
            run[0].t,
            run[-1].t,
            len(run),
            sum(call.back_tokens_est or 0 for call in run),
        )
        for server, runs in groups.items()
        for run in runs
    ]
    return tuple(sorted(clusters, key=lambda item: item.first))


def failure_runs(node: ProducedNode) -> tuple[XrayFailureRun, ...]:
    """The runs of three or more shell calls in a row that all failed with one command; calls of other categories
    between them do not break a run."""
    found: list[XrayFailureRun] = []
    run: list[ProducedCall] = []

    def close() -> None:
        if len(run) >= FAILURE_RUN_MIN:
            found.append(XrayFailureRun(run[0].t, run[-1].t, len(run), run[0].use_id))
        run.clear()

    for call in sorted(node.spine.calls, key=lambda item: item.t):
        if call.category != "run":
            continue
        if not call.failed or call.fingerprint is None:
            close()
        elif run and run[0].fingerprint != call.fingerprint:
            close()
            run.append(call)
        else:
            run.append(call)
    close()
    return tuple(found)


def breaks(node: ProducedNode) -> tuple[XrayBreak, ...]:
    """The stretches of at least `BREAK_S` seconds in which the node held no record."""
    times = sorted(node.spine.activity)
    return tuple(XrayBreak(before, after) for before, after in pairwise(times) if after - before >= BREAK_S)


def _held_tokens(source: str, loads: Sequence[LoadEvent], sources: SourceTable) -> int | None:
    """What the parent held of `source`: the sum of its loads before the launch for a hook, which fires over and over,
    else the source's size."""
    entry = sources.get(source)
    if entry is None:
        return None
    if entry.kind != "hook":
        return entry.tokens_est
    return sum(load.tokens_est or 0 for load in loads if load.source == source)


def withheld(parent: ProducedNode, child: ProducedNode, out_t: float, sources: SourceTable) -> XrayWithheld:
    """What the parent had at the launch of `child` that the child never had, and the parent's context then."""
    child_had = set(had_sources(child))
    before = [load for load in parent.spine.loads if load.t is None or load.t <= out_t]
    missing = [source for source in dict.fromkeys(load.source for load in before) if source not in child_had]
    context = [tokens for t, tokens in parent.spine.series if t <= out_t]
    return XrayWithheld(
        tuple(XrayWithheldSource(source, _held_tokens(source, before, sources)) for source in missing),
        context[-1] if context else None,
    )


def child_sources(children: Sequence[str], had: dict[str, list[str]]) -> dict[str, int]:
    """For each source at least one of `children` had, how many of them had it."""
    counts: dict[str, int] = {}
    for child in children:
        for source in had.get(child, ()):
            counts[source] = counts.get(source, 0) + 1
    return counts
