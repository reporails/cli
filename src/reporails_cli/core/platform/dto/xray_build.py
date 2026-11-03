"""The build-time records of the session view: what a derivation, a node producer and the graph builder read and
hand on, as numbers, names and paths."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from reporails_cli.core.platform.dto.events import EventRecord, HarnessEntry, HarnessKind
from reporails_cli.core.platform.dto.xray import AdapterVocabulary
from reporails_cli.core.platform.dto.xray_cost import PriceList
from reporails_cli.core.platform.dto.xray_graph import (
    AgentOutcome,
    CallFacts,
    LoadEvent,
    NodeKind,
    SourceKind,
    XrayCompaction,
    XrayDetail,
    XrayDown,
    XrayEdge,
)
from reporails_cli.core.platform.dto.xray_sources import FindingTally, SourceEntry


@dataclass(frozen=True)
class Frame:
    """What a derivation reads beside the records: the session's first time, the project, its findings and the
    files a run name can stand for, the agent definition files and whether the session is still going."""

    t0: float
    root: Path
    findings: Mapping[str, FindingTally]
    # Absolute path of the skill or command file each run name stands for.
    runnable: Mapping[str, str]
    # The size in tokens of the definition file of each agent type found on disk, by type.
    agent_files: Mapping[str, int]
    # Whether the session's transcript was written recently enough that the session is still going.
    live: bool


@dataclass(frozen=True)
class Replies:
    """The main session's replies in time order: (time, context)."""

    points: tuple[tuple[float, int], ...]

    def before(self, t: float) -> int | None:
        """The context of the last reply at or before `t`."""
        found = [context for moment, context in self.points if moment <= t]
        return found[-1] if found else None

    def after(self, t: float) -> int | None:
        """The context of the first reply at or after `t`."""
        return next((context for moment, context in self.points if moment >= t), None)


@dataclass
class HarnessSlot:
    """One harness item as it is summed: its count and size, the size of each item present that a delta row
    added, and the size each name last had."""

    kind: HarnessKind
    label: str
    count: int | None
    chars: int
    sizes: dict[str, int] = field(default_factory=dict)
    known: dict[str, int] = field(default_factory=dict)

    @classmethod
    def of(cls, entry: HarnessEntry) -> HarnessSlot:
        """The slot a kind's first record opens."""
        sizes = {**dict(entry.added), **dict.fromkeys(entry.readded, 0)}
        return cls(entry.kind, entry.label, entry.count, entry.chars, sizes, dict(sizes))

    def add(self, entry: HarnessEntry) -> None:
        """Fold in a later delta row of the same kind: the size of each name it removed leaves, its own added items
        arrive, and a name it re-added keeps the size it has, or takes the size it last had when it had left."""
        present = sum(1 for name in entry.readded if name in self.sizes)
        revived = [name for name in entry.readded if name not in self.sizes]
        delta = (entry.count or 0) - present
        self.count = None if self.count is None and entry.count is None else (self.count or 0) + delta
        self.chars += entry.chars - sum(self.sizes.pop(name, 0) for name in entry.removed)
        self.sizes.update(entry.added)
        self.known.update(entry.added)
        for name in revived:
            self.sizes[name] = self.known.get(name, 0)
            self.chars += self.sizes[name]


@dataclass(frozen=True)
class SourceTable:
    """The sources in listing order, with the lookups from a file path or a skill or command name to its id and the
    kinds whose loads the session does not record."""

    entries: tuple[SourceEntry, ...]
    root: Path
    by_real: Mapping[str, str]
    by_run: Mapping[str, str]
    # The kinds whose loads the session records nowhere: nothing can be said of whether a source of one loaded.
    unrecorded: frozenset[SourceKind] = frozenset()

    def get(self, source_id: str) -> SourceEntry | None:
        """The source with id `source_id`, or None when the session has none."""
        return next((entry for entry in self.entries if entry.id == source_id), None)


@dataclass(frozen=True)
class ProducedCall(CallFacts):
    """One call a node made: its facts, the MCP server source it went to, the fingerprint of its command and the
    size of its result in tokens."""

    mcp_source: str | None
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
    """What a producer reads beside the records: the session's sources, the coding agent's vocabulary and the price
    list."""

    sources: SourceTable
    vocabulary: AdapterVocabulary
    prices: PriceList


@dataclass(frozen=True)
class NodeProducer:
    """Makes the nodes of one kind: `produce` turns a session's records into that kind's nodes and edges."""

    kind: NodeKind
    produce: Callable[[Sequence[EventRecord], Frame, ProducerContext], Produced]


@dataclass(frozen=True)
class CallResult:
    """The result of a call: when it came, how big it was, whether it reported an error and whether it only
    acknowledged the launch of a background agent."""

    t: float
    chars: int | None
    error: bool
    launch_ack: bool = False


@dataclass(frozen=True)
class AgentReply:
    """The text an agent ended on: when it came, how long it was and whether Claude Code wrote it for an API error or
    an interrupt."""

    t: float
    chars: int
    synthetic: bool


@dataclass(frozen=True)
class AgentRecords:
    """What one agent's own records hold."""

    key: str
    records: list[EventRecord]
    replies: Replies
    results: dict[str, CallResult]
    calls: tuple[ProducedCall, ...]
    loads: tuple[LoadEvent, ...]
    compactions: tuple[XrayCompaction, ...]
    times: tuple[float, ...]
    reply: AgentReply | None

    @property
    def start(self) -> float:
        """When the agent's first record came; 0 when none is timed."""
        return self.times[0] if self.times else 0.0

    @property
    def end(self) -> float:
        """When the agent's last record came; 0 when none is timed."""
        return self.times[-1] if self.times else 0.0

    @property
    def handback(self) -> ProducedCall | None:
        """The agent's first call that hands its result back."""
        return next((call for call in self.calls if call.category == "handback"), None)


@dataclass(frozen=True)
class LoadReading:
    """What loads are read against: the frame, the sources, the time of the agent's first reply and whether the agent
    is the main one."""

    frame: Frame
    sources: SourceTable
    first: float
    is_main: bool


@dataclass(frozen=True)
class AgentWorld:
    """What every agent is read against: the frame, the sources with the vocabulary, and the session's last time."""

    frame: Frame
    context: ProducerContext
    session_end: float


@dataclass(frozen=True)
class Handoff:
    """What went down to a subagent and how it ended: the sizes, the launching call's time and the outcome."""

    down: XrayDown
    back: int | None
    out_t: float
    back_t: float | None
    outcome: AgentOutcome


@dataclass(frozen=True)
class NodeLayout:
    """Where each node hangs: its parent, depth, children by id in node order and number of descendants."""

    parents: dict[str, str | None]
    depth: dict[str, int]
    children: dict[str, list[str]]
    descendants: dict[str, int]


@dataclass(frozen=True)
class BuildContext:
    """What each node is built against: the produced nodes, the launching edge of each child, the sources every
    node had, the node kinds that carry a spine, the layout, the sources and the vocabulary."""

    by_id: dict[str, ProducedNode]
    launch: dict[str, XrayEdge]
    had: dict[str, list[str]]
    has_spine: set[str]
    layout: NodeLayout
    sources: SourceTable
    vocabulary: AdapterVocabulary
