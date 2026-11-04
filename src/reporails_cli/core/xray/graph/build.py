"""The session graph: the registered producers' nodes linked into one tree, with the facts every node with a spine
carries."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.events import EventRecord, RequestSize, SubagentMeta
from reporails_cli.core.platform.dto.xray import AdapterVocabulary, Graph
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
from reporails_cli.core.platform.dto.xray_sources import Availability, SourceEntry, XrayBuiltin, XraySource
from reporails_cli.core.xray.cost import session_cost
from reporails_cli.core.xray.graph import spine
from reporails_cli.core.xray.graph.agents import MAIN_ID, main_records
from reporails_cli.core.xray.graph.builtin import builtin_items
from reporails_cli.core.xray.graph.bursts import bursts
from reporails_cli.core.xray.graph.port import PRODUCERS
from reporails_cli.core.xray.graph.shapes import first_requests, launch_metas, launched_with
from reporails_cli.core.xray.graph.sources import builtin_agent_id, memory_role, source_label

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
    return XrayLoad(load.source, load.t, load.tokens_est, load.trigger, load.event, small)


def _availability(entry: SourceEntry, had_by: Sequence[str], unrecorded: frozenset[SourceKind]) -> Availability:
    if had_by:
        return "loaded"
    if entry.kind in unrecorded:
        return "unrecorded"
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
                {item.id: item.end for item in build.by_id.values()},
            ),
        ),
        name=node.name,
        type=node.type,
        start=node.start,
        end=node.end,
        slots=spine.slots(node, edge is not None, build.had[node.id], build.sources, build.vocabulary),
        tools=spine.tools(node),
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
        _sources(sources, pnodes, build, first_requests(records), launch_metas(records)),
        tuple(_station(node, sources, vocabulary) for node in spined),
        tuple(
            XrayTrack(node.id, spine.track_calls(node), spine.failure_runs(node), spine.breaks(node)) for node in spined
        ),
        _builtin(pnodes, records, vocabulary),
        session_cost([(node.id, node.detail.usage.cost) for node in pnodes]),
    )


def _builtin(
    nodes: Sequence[ProducedNode], records: Sequence[EventRecord], vocabulary: AdapterVocabulary
) -> tuple[XrayBuiltin, ...]:
    """The coding agent's own context, read from the main agent's records; none when the graph has no main agent."""
    main = next((node for node in nodes if node.id == MAIN_ID), None)
    return () if main is None else builtin_items(main, main_records(records), vocabulary)


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


def _builtin_agents(
    nodes: Sequence[ProducedNode],
    launched: set[str],
    defined: set[str],
    vocabulary: AdapterVocabulary,
    *,
    first: dict[str, RequestSize],
    metas: dict[str, SubagentMeta],
) -> list[XraySource]:
    """An agent source for each subagent type launched in the session that no agent definition stands for."""
    labels = {item.key: item.label for item in vocabulary.agent_types}
    launches: dict[str, list[str]] = {}
    for node in nodes:
        if node.id in launched and node.type is not None and node.type not in defined:
            launches.setdefault(node.type, []).append(node.id)
    return [_builtin_agent(agent_type, ids, labels, first=first, metas=metas) for agent_type, ids in launches.items()]


def _builtin_agent(
    agent_type: str,
    ids: list[str],
    labels: dict[str, str],
    *,
    first: dict[str, RequestSize],
    metas: dict[str, SubagentMeta],
) -> XraySource:
    return XraySource(
        id=builtin_agent_id(agent_type),
        kind="agent",
        name=agent_type,
        path=None,
        tokens_est=None,
        findings=None,
        availability="loaded",
        had_by=tuple(ids),
        actionable=False,
        launches=len(ids),
        cost_usd_est=None,
        label=labels.get(agent_type, agent_type),
        agent_type=agent_type,
        detail=launched_with(ids, first, metas),
    )


def _sources(
    sources: SourceTable,
    nodes: Sequence[ProducedNode],
    build: BuildContext,
    first: dict[str, RequestSize],
    metas: dict[str, SubagentMeta],
) -> tuple[XraySource, ...]:
    had, launched, vocabulary = build.had, set(build.launch), build.vocabulary
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
                availability=_availability(entry, had_by, sources.unrecorded),
                had_by=had_by,
                actionable=entry.actionable,
                excluded=entry.excluded,
                launches=len(had_by) if entry.kind == "agent" else None,
                cost_usd_est=costs.get(entry.id),
                label=source_label(entry),
                scopes=entry.scopes,
                tools=entry.tools,
                agent_type=entry.name if entry.kind == "agent" else None,
                memory_role=memory_role(entry),
                detail=launched_with(had_by, first, metas) if entry.kind == "agent" else entry.detail,
            )
        )
    defined = {entry.name for entry in sources.entries if entry.kind == "agent"}
    out.extend(_builtin_agents(nodes, launched, defined, vocabulary, first=first, metas=metas))
    return tuple(out)
