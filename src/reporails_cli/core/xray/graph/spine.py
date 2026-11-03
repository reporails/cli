"""The facts every node with a spine has, read from its loads and calls whatever its kind."""

from __future__ import annotations

from collections.abc import Sequence
from itertools import pairwise

from reporails_cli.core.platform.dto.events import ToolCategory
from reporails_cli.core.platform.dto.xray import AdapterVocabulary
from reporails_cli.core.platform.dto.xray_build import ProducedCall, ProducedNode, SourceTable
from reporails_cli.core.platform.dto.xray_graph import (
    ClusterItem,
    LoadEvent,
    SourceKind,
    XrayBreak,
    XrayCall,
    XrayFailureRun,
    XrayHookStretch,
    XrayMcpCluster,
    XraySlot,
    XrayToolCount,
    XrayWithheld,
    XrayWithheldSource,
)

# MCP calls to one server merge into one cluster while the gap to the one before is at most this share of the
# node's span.
CLUSTER_GAP_SHARE = 0.09

# Loads of one hook in a run that make a stretch rather than separate loads.
HOOK_STRETCH_MIN = 2

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


def _agent_slot(node: ProducedNode, launched: bool, sources: SourceTable) -> list[int]:
    """The `agent` slot of a node: a launched node has its own definition (count 1, that definition's findings) or
    none when its type is built in; the root received the listing of every definition."""
    definitions = [entry for entry in sources.entries if entry.kind == "agent"]
    if not launched:
        return [len(definitions), 0]
    own = next((entry for entry in definitions if node.type is not None and entry.name == node.type), None)
    if own is None:
        return [0, 0]
    return [1, 0 if own.findings is None else own.findings.count]


def slots(
    node: ProducedNode, launched: bool, had: Sequence[str], sources: SourceTable, vocabulary: AdapterVocabulary
) -> dict[SourceKind, XraySlot]:
    """For each source kind of the vocabulary, how many sources of it the node had and their findings together;
    `launched` is whether a parent launched the node."""
    counts = {kind.key: [0, 0] for kind in vocabulary.source_kinds}
    for source_id in had:
        entry = sources.get(source_id)
        if entry is None or entry.kind not in counts:
            continue
        counts[entry.kind][0] += 1
        counts[entry.kind][1] += 0 if entry.findings is None else entry.findings.count
    if "agent" in counts:
        counts["agent"] = _agent_slot(node, launched, sources)
    return {kind: XraySlot(count, findings) for kind, (count, findings) in counts.items()}


def tools(node: ProducedNode) -> tuple[XrayToolCount, ...]:
    """The node's calls counted per tool with how many failed, the most called first and equals by tool name."""
    counts: dict[tuple[str, ToolCategory], list[int]] = {}
    for call in node.spine.calls:
        entry = counts.setdefault((call.tool, call.category), [0, 0])
        entry[0] += 1
        entry[1] += call.failed
    rows = [XrayToolCount(tool, category, calls, failed) for (tool, category), (calls, failed) in counts.items()]
    return tuple(sorted(rows, key=lambda item: (-item.calls, item.tool)))


def track_calls(node: ProducedNode) -> tuple[XrayCall, ...]:
    """Every call of the node, in time order."""
    return tuple(
        XrayCall(
            call.t,
            call.category,
            call.tool,
            call.label,
            call.source,
            call.mcp_source,
            call.failed,
            call.use_id,
            call.duration_s,
            call.back_tokens_est,
        )
        for call in sorted(node.spine.calls, key=lambda item: item.t)
    )


def _runs(items: Sequence[ClusterItem], node: ProducedNode) -> list[list[ClusterItem]]:
    """`items` grouped by key, each group split into runs of items close together in time: the gap to the item
    before is at most `CLUSTER_GAP_SHARE` of the node's span."""
    limit = CLUSTER_GAP_SHARE * (node.end - node.start)
    groups: dict[str, list[list[ClusterItem]]] = {}
    for item in sorted(items, key=lambda entry: entry.t):
        runs = groups.setdefault(item.key, [])
        if runs and item.t - runs[-1][-1].t <= limit:
            runs[-1].append(item)
        else:
            runs.append([item])
    return [run for runs in groups.values() for run in runs]


def mcp_clusters(node: ProducedNode) -> tuple[XrayMcpCluster, ...]:
    """The node's MCP calls per server, merged into clusters of calls close together in time."""
    items = [
        ClusterItem(call.mcp_source, call.t, call.back_tokens_est or 0, number)
        for number, call in enumerate(node.spine.calls)
        if call.mcp_source is not None
    ]
    clusters = [
        XrayMcpCluster(run[0].key, run[0].t, run[-1].t, len(run), sum(item.tokens for item in run))
        for run in _runs(items, node)
    ]
    return tuple(sorted(clusters, key=lambda item: item.first))


def hook_stretches(node: ProducedNode, sources: SourceTable) -> tuple[tuple[XrayHookStretch, ...], frozenset[int]]:
    """The node's hook loads that came close together, a run of two or more per hook as one stretch, and the
    positions in `node.spine.loads` of the loads that went into a stretch."""
    items = [
        ClusterItem(load.source, load.t, load.tokens_est or 0, number)
        for number, load in enumerate(node.spine.loads)
        if load.t is not None and (entry := sources.get(load.source)) is not None and entry.kind == "hook"
    ]
    stretches = [
        (XrayHookStretch(run[0].key, run[0].t, run[-1].t, len(run), sum(item.tokens for item in run)), run)
        for run in _runs(items, node)
        if len(run) >= HOOK_STRETCH_MIN
    ]
    stretches.sort(key=lambda found: found[0].first)
    return tuple(found for found, _ in stretches), frozenset(item.position for _, run in stretches for item in run)


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
