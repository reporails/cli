"""The session graph: the registered producers' nodes linked into one tree, with the facts every node with a spine
carries."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.xray import AdapterVocabulary, Availability, Graph, SourceEntry, XraySource
from reporails_cli.core.platform.dto.xray_build import (
    BuildContext,
    Frame,
    NodeLayout,
    ProducedNode,
    ProducerContext,
    SourceTable,
)
from reporails_cli.core.platform.dto.xray_cost import PriceList
from reporails_cli.core.platform.dto.xray_graph import (
    LoadEvent,
    SourceKind,
    XrayLoad,
    XrayNode,
    XrayStation,
    XrayTrack,
    XrayTree,
)
from reporails_cli.core.xray.graph import spine
from reporails_cli.core.xray.graph.bursts import bursts
from reporails_cli.core.xray.graph.port import PRODUCERS

# A load smaller than this many tokens is small.
SMALL_TOKENS = 1000


def _layout(nodes: Sequence[ProducedNode]) -> NodeLayout:
    """The layout of `nodes`; a parent that names no node leaves the node a root. Raises `ValueError` when the
    parents form a loop."""
    known = {item.id for item in nodes}
    parents = {node.id: node.parent if node.parent in known else None for node in nodes}
    children: dict[str, list[str]] = {node.id: [] for node in nodes}
    depth: dict[str, int] = {}
    descendants = dict.fromkeys(parents, 0)
    for node_id, parent in parents.items():
        if parent is not None:
            children[parent].append(node_id)
        chain = [node_id]
        while (above := parents[chain[-1]]) is not None:
            if above in chain:
                raise ValueError(f"node {node_id!r} is its own ancestor")
            chain.append(above)
        depth[node_id] = len(chain) - 1
        for ancestor in chain[1:]:
            descendants[ancestor] += 1
    return NodeLayout(parents, depth, children, descendants)


def _station(node: ProducedNode, sources: SourceTable, vocabulary: AdapterVocabulary) -> XrayStation:
    small_kinds = {kind.key for kind in vocabulary.source_kinds if kind.small}
    hooks, stretched = spine.hook_stretches(node, sources)
    return XrayStation(
        node.id,
        tuple(
            _load(load, sources, small_kinds) for number, load in enumerate(node.spine.loads) if number not in stretched
        ),
        spine.mcp_clusters(node),
        node.spine.compactions,
        hooks,
    )


def _load(load: LoadEvent, sources: SourceTable, small_kinds: set[SourceKind]) -> XrayLoad:
    entry = sources.get(load.source)
    small = (
        load.tokens_est < SMALL_TOKENS
        if load.tokens_est is not None
        else entry is not None and entry.kind in small_kinds
    )
    return XrayLoad(load.source, load.t, load.tokens_est, load.trigger, load.event, load.on_spine, small)


def _availability(entry: SourceEntry, had_by: Sequence[str]) -> Availability:
    if had_by:
        return "loaded"
    return "listed" if entry.advertised else "on_disk"


def _xray_node(node: ProducedNode, build: BuildContext) -> XrayNode:
    """The node with its place, its slots, its call counts and what its parent withheld from it."""
    edge = build.launch.get(node.id)
    parent = build.by_id.get(edge.parent) if edge is not None else None
    layout = build.layout
    withheld = (
        spine.withheld(parent, node, edge.out_t, build.sources)
        if node.kind in build.has_spine and edge is not None and parent is not None
        else None
    )
    return XrayNode(
        id=node.id,
        kind=node.kind,
        tree=XrayTree(
            layout.parents[node.id],
            layout.depth[node.id],
            tuple(layout.children[node.id]),
            layout.descendants[node.id],
            bursts(
                [item for item in build.launch.values() if item.parent == node.id],
                node.end - node.start,
                build.vocabulary.burst,
            ),
        ),
        name=node.name,
        type=node.type,
        start=node.start,
        end=node.end,
        slots=spine.slots(node, edge is not None, build.had[node.id], build.sources, build.vocabulary),
        tool_counts=spine.tool_counts(node, build.vocabulary),
        withheld=withheld,
        child_sources=spine.child_sources(layout.children[node.id], build.had),
        detail=node.detail,
    )


def build_graph(
    records: Sequence[EventRecord],
    frame: Frame,
    sources: SourceTable,
    vocabulary: AdapterVocabulary,
    prices: PriceList,
) -> Graph:
    """The graph of `records`: the nodes and edges of every registered producer, linked by parent."""
    context = ProducerContext(sources, vocabulary, prices)
    produced = [producer.produce(records, frame, context) for producer in PRODUCERS]
    pnodes = [node for item in produced for node in item.nodes]
    edges = tuple(edge for item in produced for edge in item.edges)
    build = BuildContext(
        by_id={node.id: node for node in pnodes},
        launch={edge.child: edge for edge in edges},
        had={node.id: spine.had_sources(node) for node in pnodes},
        has_spine={info.key for info in vocabulary.node_kinds if info.has_spine},
        layout=_layout(pnodes),
        sources=sources,
        vocabulary=vocabulary,
    )
    spined = [node for node in pnodes if node.kind in build.has_spine]
    return Graph(
        tuple(_xray_node(node, build) for node in pnodes),
        edges,
        _sources(sources, pnodes, build.had, set(build.launch)),
        tuple(_station(node, sources, vocabulary) for node in spined),
        tuple(
            XrayTrack(node.id, spine.track_calls(node, vocabulary), spine.failure_runs(node), spine.breaks(node))
            for node in spined
        ),
    )


def _had_by(
    entry: SourceEntry, nodes: Sequence[ProducedNode], had: dict[str, list[str]], launched: set[str]
) -> tuple[str, ...]:
    """The nodes whose context the source entered; for an agent definition, the launched nodes of its type."""
    if entry.kind == "agent":
        return tuple(node.id for node in nodes if node.id in launched and node.type == entry.name)
    return tuple(node.id for node in nodes if entry.id in had[node.id])


def _source_costs(nodes: Sequence[ProducedNode]) -> dict[str, float]:
    """Each source's estimated cost summed over every agent's replies."""
    total: dict[str, float] = {}
    for node in nodes:
        for source, usd in node.detail.usage.cost.by_source_usd_est:
            total[source] = total.get(source, 0.0) + usd
    return total


def _sources(
    sources: SourceTable, nodes: Sequence[ProducedNode], had: dict[str, list[str]], launched: set[str]
) -> tuple[XraySource, ...]:
    out: list[XraySource] = []
    costs = _source_costs(nodes)
    for entry in sources.entries:
        had_by = _had_by(entry, nodes, had, launched)
        out.append(
            XraySource(
                id=entry.id,
                kind=entry.kind,
                name=entry.name,
                path=entry.path,
                tokens_est=entry.tokens_est,
                findings=entry.findings,
                availability=_availability(entry, had_by),
                had_by=had_by,
                actionable=entry.actionable,
                launches=len(had_by) if entry.kind == "agent" else None,
                cost_usd_est=costs.get(entry.id),
            )
        )
    return tuple(out)
