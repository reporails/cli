"""The session graph: the registered producers' nodes linked into one tree, with the facts every node with a spine
carries."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.xray import (
    AdapterVocabulary,
    Availability,
    SourceKind,
    XrayEdge,
    XrayLoad,
    XrayNode,
    XraySource,
    XrayStation,
    XrayTrack,
)
from reporails_cli.core.xray.derive import Frame
from reporails_cli.core.xray.graph import spine
from reporails_cli.core.xray.graph.port import PRODUCERS, ProducedLoad, ProducedNode, ProducerContext
from reporails_cli.core.xray.graph.sources import SourceEntry, SourceTable

# A load smaller than this many tokens is small.
SMALL_TOKENS = 1000


@dataclass(frozen=True)
class Graph:
    """The built graph: nodes in producer order, their edges, the sources with who had them, and the station and
    track of each node with a spine."""

    nodes: tuple[XrayNode, ...]
    edges: tuple[XrayEdge, ...]
    sources: tuple[XraySource, ...]
    stations: tuple[XrayStation, ...]
    tracks: tuple[XrayTrack, ...]


def _depths(nodes: Sequence[ProducedNode]) -> tuple[dict[str, int], dict[str, list[str]], dict[str, int]]:
    """Each node's depth, its children by id in node order and its number of descendants; raises `ValueError` when
    the parents form a loop."""
    parents = {node.id: node.parent if node.parent in {item.id for item in nodes} else None for node in nodes}
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
    return depth, children, descendants


def _station(node: ProducedNode, sources: SourceTable, vocabulary: AdapterVocabulary) -> XrayStation:
    small_kinds = {kind.key for kind in vocabulary.source_kinds if kind.small}
    return XrayStation(
        node.id,
        tuple(_load(load, sources, small_kinds) for load in node.loads),
        spine.mcp_clusters(node),
        node.compactions,
    )


def _load(load: ProducedLoad, sources: SourceTable, small_kinds: set[SourceKind]) -> XrayLoad:
    entry = sources.get(load.source)
    small = (
        load.tokens_est < SMALL_TOKENS
        if load.tokens_est is not None
        else entry is not None and entry.kind in small_kinds
    )
    return XrayLoad(load.source, load.t, load.tokens_est, load.trigger, load.event, small, load.on_spine)


def _availability(entry: SourceEntry, had_by: Sequence[str]) -> Availability:
    if had_by:
        return "loaded"
    return "listed" if entry.advertised else "on_disk"


def build_graph(
    records: Sequence[EventRecord], frame: Frame, sources: SourceTable, vocabulary: AdapterVocabulary
) -> Graph:
    """The graph of `records`: the nodes and edges of every registered producer, linked by parent."""
    context = ProducerContext(sources, vocabulary)
    produced = [producer.produce(records, frame, context) for producer in PRODUCERS]
    pnodes = [node for item in produced for node in item.nodes]
    edges = tuple(edge for item in produced for edge in item.edges)
    depth, children, descendants = _depths(pnodes)
    has_spine = {info.key for info in vocabulary.node_kinds if info.has_spine}
    by_id = {node.id: node for node in pnodes}
    launch = {edge.child: edge for edge in edges}
    had = {node.id: spine.had_sources(node) for node in pnodes}
    nodes: list[XrayNode] = []
    stations: list[XrayStation] = []
    tracks: list[XrayTrack] = []
    for node in pnodes:
        edge = launch.get(node.id)
        parent = by_id.get(edge.parent) if edge is not None else None
        nodes.append(
            XrayNode(
                id=node.id,
                kind=node.kind,
                parent=node.parent if node.parent in by_id else None,
                depth=depth[node.id],
                name=node.name,
                type=node.type,
                start=node.start,
                end=node.end,
                children=tuple(children[node.id]),
                descendants=descendants[node.id],
                slots=spine.slots(had[node.id], sources, vocabulary),
                tool_counts=spine.tool_counts(node, vocabulary),
                withheld=None
                if node.kind not in has_spine or edge is None or parent is None
                else spine.withheld(parent, node, edge.out_t, sources),
                detail=node.detail,
            )
        )
        if node.kind not in has_spine:
            continue
        stations.append(_station(node, sources, vocabulary))
        tracks.append(
            XrayTrack(node.id, spine.track_calls(node, vocabulary), spine.failure_runs(node), spine.breaks(node))
        )
    return Graph(tuple(nodes), edges, _sources(sources, pnodes, had), tuple(stations), tuple(tracks))


def _sources(sources: SourceTable, nodes: Sequence[ProducedNode], had: dict[str, list[str]]) -> tuple[XraySource, ...]:
    out: list[XraySource] = []
    for entry in sources.entries:
        had_by = tuple(node.id for node in nodes if entry.id in had[node.id])
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
            )
        )
    return tuple(out)
