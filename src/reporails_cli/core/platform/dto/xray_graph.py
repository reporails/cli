"""The nodes of the session view and what hangs on them: their loads, calls, compactions, hand-offs and the
details of each node kind, as numbers, names and paths.

A value with no source is `None`, which reads as "not known here".
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.events import ToolCategory

CompactionTrigger = Literal["manual", "auto"]
NodeKind = Literal["agent"]
SourceKind = Literal["instructions", "rule", "skill", "memory", "mcp", "hook"]
LoadTrigger = Literal["session_start", "path_match", "agent", "inherited", "hook"]
AgentOutcome = Literal["returned", "failed", "stopped", "no_handback", "running"]


def objects(items: Iterable[JsonObject]) -> JsonValue:
    """Plain JSON objects as one JSON list."""
    values: list[JsonValue] = list(items)
    return values


def series_json(series: Iterable[tuple[float, int]]) -> JsonValue:
    """(seconds, tokens) points as a JSON list of pairs."""
    points: list[JsonValue] = [[t, tokens] for t, tokens in series]
    return points


@dataclass(frozen=True)
class LoadEvent:
    """A source entering a node's context: when, how big, what brought it there and the hook event behind it;
    `on_spine` is false for an instruction file the node started with."""

    source: str
    t: float | None
    tokens_est: int | None
    trigger: LoadTrigger
    event: str | None
    on_spine: bool


@dataclass(frozen=True)
class XrayLoad(LoadEvent):
    """One station on a node's spine: a load and whether it is small."""

    small: bool

    def to_json(self) -> JsonObject:
        """The load as a JSON object."""
        return {
            "source": self.source,
            "t": self.t,
            "tokens_est": self.tokens_est,
            "trigger": self.trigger,
            "event": self.event,
            "small": self.small,
            "on_spine": self.on_spine,
        }


@dataclass(frozen=True)
class XrayMcpCluster:
    """The calls a node made to one MCP server close together in time, and the size of their results."""

    server: str
    first: float
    last: float
    calls: int
    back_tokens_est: int

    def to_json(self) -> JsonObject:
        """The cluster as a JSON object."""
        return {
            "server": self.server,
            "first": self.first,
            "last": self.last,
            "calls": self.calls,
            "back_tokens_est": self.back_tokens_est,
        }


@dataclass(frozen=True)
class XrayCompaction:
    """One compaction of a node's context: when, what started it and the context before and after."""

    t: float
    trigger: CompactionTrigger | None
    before: int | None
    after: int | None

    def to_json(self) -> JsonObject:
        """The compaction as a JSON object."""
        return {"t": self.t, "trigger": self.trigger, "before": self.before, "after": self.after}


@dataclass(frozen=True)
class XrayStation:
    """What happened on one node's spine: its loads, its MCP clusters and its compactions."""

    node: str
    loads: tuple[XrayLoad, ...]
    mcp: tuple[XrayMcpCluster, ...]
    compactions: tuple[XrayCompaction, ...]

    def to_json(self) -> JsonObject:
        """The station as a JSON object."""
        return {
            "node": self.node,
            "loads": objects(load.to_json() for load in self.loads),
            "mcp": objects(cluster.to_json() for cluster in self.mcp),
            "compactions": objects(item.to_json() for item in self.compactions),
        }


@dataclass(frozen=True)
class XrayCall:
    """One call on a node's side track: when, its category, its label, the source its file is, whether it failed
    and the id the page asks the command text by."""

    t: float
    category: ToolCategory
    label: str
    source: str | None
    failed: bool
    use_id: str

    def to_json(self) -> JsonObject:
        """The call as a JSON object."""
        return {
            "t": self.t,
            "category": self.category,
            "label": self.label,
            "source": self.source,
            "failed": self.failed,
            "use_id": self.use_id,
        }


@dataclass(frozen=True)
class XrayFailureRun:
    """Three or more shell calls in a row that ran one command and all failed."""

    first: float
    last: float
    count: int
    call_id: str

    def to_json(self) -> JsonObject:
        """The run as a JSON object."""
        return {"first": self.first, "last": self.last, "count": self.count, "call_id": self.call_id}


@dataclass(frozen=True)
class XrayBreak:
    """A long stretch in which a node held no record."""

    start: float
    end: float

    def to_json(self) -> JsonObject:
        """The break as a JSON object."""
        return {"start": self.start, "end": self.end}


@dataclass(frozen=True)
class XrayTrack:
    """A node's side track: its calls, the runs of one failing command and its breaks."""

    node: str
    calls: tuple[XrayCall, ...]
    failure_runs: tuple[XrayFailureRun, ...]
    breaks: tuple[XrayBreak, ...]

    def to_json(self) -> JsonObject:
        """The track as a JSON object."""
        return {
            "node": self.node,
            "calls": objects(call.to_json() for call in self.calls),
            "failure_runs": objects(item.to_json() for item in self.failure_runs),
            "breaks": objects(item.to_json() for item in self.breaks),
        }


@dataclass(frozen=True)
class XrayPrompt:
    """One prompt a person typed: the id the page asks the text by, when, and its size. Never the text."""

    id: str
    t: float
    tokens_est: int

    def to_json(self) -> JsonObject:
        """The prompt as a JSON object."""
        return {"id": self.id, "t": self.t, "tokens_est": self.tokens_est}


@dataclass(frozen=True)
class XrayGiven:
    """One piece of what an agent started with: its label, size and, for a source, the source's id."""

    label: str
    tokens_est: int | None
    source: str | None

    def to_json(self) -> JsonObject:
        """The piece as a JSON object."""
        return {"label": self.label, "tokens_est": self.tokens_est, "source": self.source}


@dataclass(frozen=True)
class XrayDown:
    """What a parent handed an agent: the task prompt's size (None for the root) and the rest it started with."""

    task_tokens_est: int | None
    inherited_tokens_est: int

    def to_json(self) -> JsonObject:
        """The hand-down as a JSON object."""
        return {"task_tokens_est": self.task_tokens_est, "inherited_tokens_est": self.inherited_tokens_est}


@dataclass(frozen=True)
class XrayAgentDetail:
    """What the page shows of an agent beyond the generic node: its context line, what it was handed, what it
    handed back, how it ended and the prompts a person typed to it."""

    context_start: int | None
    peak: int | None
    series: tuple[tuple[float, int], ...]
    down: XrayDown
    back_tokens_est: int | None
    outcome: AgentOutcome | None
    given: tuple[XrayGiven, ...]
    prompts: tuple[XrayPrompt, ...]
    brief: bool
    kind: NodeKind = "agent"

    def to_json(self) -> JsonObject:
        """The detail as a JSON object."""
        return {
            "kind": self.kind,
            "context_start": self.context_start,
            "peak": self.peak,
            "series": series_json(self.series),
            "down": self.down.to_json(),
            "back_tokens_est": self.back_tokens_est,
            "outcome": self.outcome,
            "given": objects(item.to_json() for item in self.given),
            "prompts": objects(item.to_json() for item in self.prompts),
            "brief": self.brief,
        }


# What a node carries beyond the generic facts, one member per node kind.
XrayDetail = XrayAgentDetail


@dataclass(frozen=True)
class XraySlot:
    """How many sources of one kind a node had and how many findings they carry together."""

    count: int
    findings: int


@dataclass(frozen=True)
class XrayWithheldSource:
    """A source the parent had at a child's launch that the child never had."""

    source: str
    tokens_est: int | None


@dataclass(frozen=True)
class XrayWithheld:
    """What a child did not get: the sources its parent had at the launch and the parent's context then."""

    sources: tuple[XrayWithheldSource, ...]
    context_tokens: int | None

    def to_json(self) -> JsonObject:
        """What was withheld as a JSON object."""
        return {
            "sources": objects({"source": item.source, "tokens_est": item.tokens_est} for item in self.sources),
            "context_tokens": self.context_tokens,
        }


@dataclass(frozen=True)
class XrayTree:
    """Where a node hangs: its parent (None for a root), its depth, its children in launch order and how many nodes
    hang below it."""

    parent: str | None
    depth: int
    children: tuple[str, ...]
    descendants: int


@dataclass(frozen=True)
class XrayNode:
    """One node of the session's graph: where it hangs, when it ran, the sources it had by kind, the calls it made by
    category, what its parent withheld from it, and its kind's own detail."""

    id: str
    kind: NodeKind
    tree: XrayTree
    name: str
    type: str | None
    start: float
    end: float
    slots: dict[SourceKind, XraySlot]
    tool_counts: dict[ToolCategory, int]
    withheld: XrayWithheld | None
    detail: XrayDetail

    def to_json(self) -> JsonObject:
        """The node as a JSON object."""
        slots: dict[str, JsonValue] = {
            kind: {"count": slot.count, "findings": slot.findings} for kind, slot in self.slots.items()
        }
        counts: dict[str, JsonValue] = {str(category): count for category, count in self.tool_counts.items()}
        return {
            "id": self.id,
            "kind": self.kind,
            "parent": self.tree.parent,
            "depth": self.tree.depth,
            "name": self.name,
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "children": list(self.tree.children),
            "descendants": self.tree.descendants,
            "slots": slots,
            "tool_counts": counts,
            "withheld": None if self.withheld is None else self.withheld.to_json(),
            "detail": self.detail.to_json(),
        }


@dataclass(frozen=True)
class XrayEdge:
    """One handoff from a parent node to a child: what went down, what came back, when each happened and how the
    child ended."""

    parent: str
    child: str
    down: int
    back: int | None
    out_t: float
    back_t: float | None
    outcome: AgentOutcome | None

    def to_json(self) -> JsonObject:
        """The edge as a JSON object."""
        return {
            "from": self.parent,
            "to": self.child,
            "kind": "handoff",
            "down": self.down,
            "back": self.back,
            "out_t": self.out_t,
            "back_t": self.back_t,
            "outcome": self.outcome,
        }
