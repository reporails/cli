"""The seam node kinds plug into: a producer turns a session's records into nodes, and the builder links whatever the
registered producers return."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from reporails_cli.core.platform.dto.events import EventRecord, ToolCategory
from reporails_cli.core.platform.dto.xray import AdapterVocabulary
from reporails_cli.core.platform.dto.xray_graph import (
    LoadEvent,
    NodeKind,
    XrayCompaction,
    XrayDetail,
    XrayEdge,
)
from reporails_cli.core.xray.derive import Frame
from reporails_cli.core.xray.graph.sources import SourceTable


@dataclass(frozen=True)
class ProducedCall:
    """One call a node made: when, its category and label, the source its file is, the MCP server source it went to,
    whether it failed, its id, the fingerprint of its command and the size of its result in tokens."""

    t: float
    category: ToolCategory
    label: str
    source: str | None
    mcp_source: str | None
    failed: bool
    use_id: str
    fingerprint: str | None
    back_tokens_est: int | None


@dataclass(frozen=True)
class ProducedSpine:
    """What the builder derives a node's generic facts from: its context line, loads, calls, compactions and every
    time it held a record."""

    series: tuple[tuple[float, int], ...]
    loads: tuple[LoadEvent, ...]
    calls: tuple[ProducedCall, ...]
    compactions: tuple[XrayCompaction, ...]
    activity: tuple[float, ...]


@dataclass(frozen=True)
class ProducedNode:
    """A node a producer makes: its place by parent id, its time span, its kind's own detail and its spine."""

    id: str
    kind: NodeKind
    parent: str | None
    name: str
    type: str | None
    start: float
    end: float
    detail: XrayDetail
    spine: ProducedSpine


@dataclass(frozen=True)
class Produced:
    """What one producer made: its nodes and the edges between them."""

    nodes: tuple[ProducedNode, ...]
    edges: tuple[XrayEdge, ...]


@dataclass(frozen=True)
class ProducerContext:
    """What a producer reads beside the records: the session's sources and the coding agent's vocabulary."""

    sources: SourceTable
    vocabulary: AdapterVocabulary


@dataclass(frozen=True)
class NodeProducer:
    """Makes the nodes of one kind: `produce` turns a session's records into that kind's nodes and edges."""

    kind: NodeKind
    produce: Callable[[Sequence[EventRecord], Frame, ProducerContext], Produced]


# The registered producers, in the order their nodes are listed.
PRODUCERS: list[NodeProducer] = []


def register(producer: NodeProducer) -> None:
    """Add `producer` to the registered ones; raises `ValueError` when a producer of its kind is registered."""
    if any(item.kind == producer.kind for item in PRODUCERS):
        raise ValueError(f"a producer of node kind {producer.kind!r} is already registered")
    PRODUCERS.append(producer)
