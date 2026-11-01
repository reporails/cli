"""The seam node kinds plug into: a producer turns a session's records into nodes, and the builder links whatever the
registered producers return."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from reporails_cli.core.platform.dto.events import EventRecord, ToolCategory
from reporails_cli.core.platform.dto.xray import (
    AdapterVocabulary,
    LoadTrigger,
    NodeKind,
    XrayCompaction,
    XrayDetail,
    XrayEdge,
)
from reporails_cli.core.xray.derive import Frame
from reporails_cli.core.xray.graph.sources import SourceTable


@dataclass(frozen=True)
class ProducedLoad:
    """A source entering a node's context at a time, before the builder marks it small."""

    source: str
    t: float | None
    tokens_est: int | None
    trigger: LoadTrigger
    event: str | None
    on_spine: bool


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
class ProducedNode:
    """A node a producer makes: its place by parent id, its time span, its kind's own detail, and what the builder
    derives the generic facts from (its loads, calls, compactions, context line and every time it held a record)."""

    id: str
    kind: NodeKind
    parent: str | None
    name: str
    type: str | None
    start: float
    end: float
    detail: XrayDetail
    series: tuple[tuple[float, int], ...]
    loads: tuple[ProducedLoad, ...]
    calls: tuple[ProducedCall, ...]
    compactions: tuple[XrayCompaction, ...]
    activity: tuple[float, ...]


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


class NodeProducer(Protocol):
    """Makes the nodes of one kind from a session's records."""

    kind: NodeKind

    def produce(self, records: Sequence[EventRecord], frame: Frame, context: ProducerContext) -> Produced:
        """The nodes and edges of this kind in `records`."""


# The registered producers, in the order their nodes are listed.
PRODUCERS: list[NodeProducer] = []


def register(producer: NodeProducer) -> None:
    """Add `producer` to the registered ones; raises `ValueError` when a producer of its kind is registered."""
    if any(item.kind == producer.kind for item in PRODUCERS):
        raise ValueError(f"a producer of node kind {producer.kind!r} is already registered")
    PRODUCERS.append(producer)
