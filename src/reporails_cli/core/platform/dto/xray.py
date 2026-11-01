"""The session view: one session's agents, the sources they had and the calls they made, as numbers, names and
paths.

A view never holds prompt, tool or file text. A value with no source is `None`, which reads as
"not known here".
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal, TypeGuard, get_args

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.events import HarnessKind, ToolCategory

CompactionTrigger = Literal["manual", "auto"]
ArtifactKind = Literal["instructions", "rule", "memory", "skill", "agent", "command", "hook"]
ArtifactScope = Literal["project", "user", "managed", "local", "plugin", "auto", "synced"]
CheckState = Literal["running", "done", "refused"]
FactKind = Literal[
    "file_findings", "funnel_drop", "memory_unlinked", "compaction_loss", "repeated_instructions", "kind_absent"
]
TargetKind = Literal["path", "node", "kind"]
NodeKind = Literal["agent"]
SourceKind = Literal["instructions", "rule", "skill", "memory", "mcp", "hook"]
LoadTrigger = Literal["session_start", "path_match", "agent", "inherited", "hook"]
AgentOutcome = Literal["returned", "failed", "stopped", "no_handback", "running"]
Availability = Literal["loaded", "listed", "on_disk"]

# The kind of artifact a config file type is shown as; a file type not listed is an instruction file.
ARTIFACT_KIND_OF_FILE_TYPE: dict[str, ArtifactKind] = {
    "memory": "memory",
    "subagent_memory": "memory",
    "rules": "rule",
    "skills": "skill",
    "agents": "agent",
    "commands": "command",
    "hooks": "hook",
}

# The kinds a session invokes: each such artifact is the one `invocable` entry of its file, never a loaded file.
INVOCABLE_ARTIFACT_KINDS: frozenset[ArtifactKind] = frozenset({"skill", "agent", "command", "hook"})

# The kinds a person or the agent runs by name: a run of one is the file loading into context.
RUNNABLE_ARTIFACT_KINDS: frozenset[ArtifactKind] = frozenset({"skill", "command"})

# Which scope wins when two listed files share a label, highest first. The skills page ranks managed over user over
# project, the sub-agents page managed over project over user; a plugin's file carries its plugin's name in its
# label and never competes.
SCOPE_PRECEDENCE: dict[ArtifactKind, tuple[ArtifactScope, ...]] = {
    "skill": ("managed", "user", "project"),
    "command": ("managed", "user", "project"),
    "agent": ("managed", "project", "user"),
}

# The source kind an artifact kind is shown as; agent files and hook configs are no source.
SOURCE_KIND_OF_ARTIFACT: dict[ArtifactKind, SourceKind] = {
    "instructions": "instructions",
    "rule": "rule",
    "memory": "memory",
    "skill": "skill",
    "command": "skill",
}


def is_artifact_scope(precedence: str) -> TypeGuard[ArtifactScope]:
    """Whether a config scope's precedence is one of the scopes the view shows."""
    return precedence in get_args(ArtifactScope)


def objects(items: Iterable[JsonObject]) -> JsonValue:
    """Plain JSON objects as one JSON list."""
    values: list[JsonValue] = list(items)
    return values


def series_json(series: Iterable[tuple[float, int]]) -> JsonValue:
    """(seconds, tokens) points as a JSON list of pairs."""
    points: list[JsonValue] = [[t, tokens] for t, tokens in series]
    return points


@dataclass(frozen=True)
class FindingTally:
    """The findings of one file: how many, and how many of each severity."""

    count: int
    by_severity: dict[FindingSeverity, int]

    def to_json(self) -> JsonObject:
        """The tally as a JSON object."""
        by_severity: dict[str, JsonValue] = {
            severity: self.by_severity[severity] for severity in get_args(FindingSeverity)
        }
        return {"count": self.count, "by_severity": by_severity}


def _tally_json(tally: FindingTally | None) -> JsonValue:
    return None if tally is None else tally.to_json()


@dataclass(frozen=True)
class XrayCheck:
    """The launch check of the whole project: running, done, or refused with the reason."""

    state: CheckState
    message: str | None

    def to_json(self) -> JsonObject:
        """The launch check as a JSON object."""
        return {"state": self.state, "message": self.message}


@dataclass(frozen=True)
class XrayLoad:
    """One station on a node's spine: a source entering its context, when, how big, what brought it there and
    whether it is small; `on_spine` is false for an instruction file the node started with."""

    source: str
    t: float | None
    tokens_est: int | None
    trigger: LoadTrigger
    event: str | None
    small: bool
    on_spine: bool

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
class XrayHarnessItem:
    """One piece of the harness's own context at an agent's start, sized by an estimate."""

    kind: HarnessKind
    label: str
    count: int | None
    tokens_est: int | None


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
class XrayNode:
    """One node of the session's graph: where it hangs, when it ran, the sources it had by kind, the calls it made by
    category, what its parent withheld from it, and its kind's own detail."""

    id: str
    kind: NodeKind
    parent: str | None
    depth: int
    name: str
    type: str | None
    start: float
    end: float
    children: tuple[str, ...]
    descendants: int
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
            "parent": self.parent,
            "depth": self.depth,
            "name": self.name,
            "type": self.type,
            "start": self.start,
            "end": self.end,
            "children": list(self.children),
            "descendants": self.descendants,
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


@dataclass(frozen=True)
class XraySource:
    """One thing that can enter a context: its kind, name, path (None for an MCP server or a hook), size, findings,
    whether it loaded, was only listed or sat on disk, the nodes whose context it entered, and whether the page
    may check or fix it."""

    id: str
    kind: SourceKind
    name: str
    path: str | None
    tokens_est: int | None
    findings: FindingTally | None
    availability: Availability
    had_by: tuple[str, ...]
    actionable: bool

    def to_json(self) -> JsonObject:
        """The source as a JSON object."""
        return {
            "id": self.id,
            "kind": self.kind,
            "name": self.name,
            "path": self.path,
            "tokens_est": self.tokens_est,
            "findings": _tally_json(self.findings),
            "availability": self.availability,
            "had_by": list(self.had_by),
            "actionable": self.actionable,
        }


@dataclass(frozen=True)
class ArtifactFile:
    """One file the session could load: its absolute path, what kind of file it is, where it comes from
    (`scope`, and `plugin` for an installed plugin's file) and its display `label`; a memory topic file
    also carries its type and whether the memory index links it."""

    path: str
    kind: ArtifactKind
    scope: ArtifactScope
    plugin: str | None
    label: str
    memory_type: str | None
    linked: bool | None


@dataclass(frozen=True)
class XrayArtifact(ArtifactFile):
    """A file the session could load with its size, its findings, whether the harness listed it by name
    (`advertised`, None when no listing names its kind) and whether the page may check or fix it."""

    findings: FindingTally | None
    actionable: bool
    tokens_est: int | None
    advertised: bool | None


@dataclass(frozen=True)
class XrayFunnelRow:
    """How many sources of a kind sit on disk, are advertised by the harness, load and are used; a count with
    no source is None."""

    kind: SourceKind
    on_disk: int
    advertised: int | None
    loaded: int | None
    used: int | None

    def to_json(self) -> JsonObject:
        """The row as a JSON object."""
        return {
            "kind": self.kind,
            "on_disk": self.on_disk,
            "advertised": self.advertised,
            "loaded": self.loaded,
            "used": self.used,
        }


@dataclass(frozen=True)
class XrayTarget:
    """What a fact points at on the page: a file path, a node id or a source kind."""

    kind: TargetKind
    value: str

    def to_json(self) -> JsonObject:
        """The target as a JSON object."""
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class XrayFact:
    """One headline fact of the session: its kind, the source kind it is about, its named counts and its target."""

    kind: FactKind
    artifact_kind: SourceKind | None
    numbers: tuple[tuple[str, int], ...]
    target: XrayTarget | None

    def to_json(self) -> JsonObject:
        """The fact as a JSON object."""
        numbers: dict[str, JsonValue] = dict(self.numbers)
        return {
            "kind": self.kind,
            "artifact_kind": self.artifact_kind,
            "numbers": numbers,
            "target": None if self.target is None else self.target.to_json(),
        }


@dataclass(frozen=True)
class XrayWindow:
    """The context window size in tokens and how it is known."""

    size: int
    basis: Literal["observed"]

    def to_json(self) -> JsonObject:
        """The window as a JSON object."""
        return {"size": self.size, "basis": self.basis}


@dataclass(frozen=True)
class XraySessionInfo:
    """Which session and project the page shows, when the session began (the time of its first record) and how
    long it ran, in seconds."""

    session: str
    project: str
    started_at: str | None
    length_s: float | None


@dataclass(frozen=True)
class XrayVerdict:
    """What the page says about the files: the funnel per kind, the headline facts and the state of the launch
    check."""

    funnel: tuple[XrayFunnelRow, ...]
    facts: tuple[XrayFact, ...]
    check: XrayCheck


@dataclass(frozen=True)
class XrayGaps:
    """What the view could not read: the refusals and the names of what is not known."""

    refusals: tuple[str, ...]
    not_known: tuple[str, ...]


@dataclass(frozen=True)
class XraySourceKindInfo:
    """One source kind the coding agent has: its key, label, the letter the page marks it with and whether its
    sources are usually under a thousand tokens."""

    key: SourceKind
    label: str
    letter: str
    small: bool


@dataclass(frozen=True)
class XrayAgentTypeInfo:
    """One agent type the page can draw: its key as the transcript names it, a short label, a colour and an icon
    path in a 24-unit box."""

    key: str
    label: str
    colour: str
    icon: str


@dataclass(frozen=True)
class XrayNodeKindInfo:
    """One node kind: its key, label, whether the page may open one to show what is inside and whether its nodes
    carry a spine of loads and calls."""

    key: NodeKind
    label: str
    opens: bool
    has_spine: bool


@dataclass(frozen=True)
class XrayCategoryInfo:
    """One tool category the page counts: its label and whether its calls sit on the side track."""

    key: ToolCategory
    label: str
    track: bool


@dataclass(frozen=True)
class XrayRoot:
    """The root node's type key and name."""

    type: str
    name: str


@dataclass(frozen=True)
class XrayNesting:
    """Whether the coding agent nests subagents and how deep."""

    enabled: bool
    max_depth: int | None


@dataclass(frozen=True)
class AdapterVocabulary:
    """What a coding agent calls things: its tool name, its root, source kinds, agent types, node kinds, tool
    categories and nesting."""

    tool: str
    root: XrayRoot
    source_kinds: tuple[XraySourceKindInfo, ...]
    agent_types: tuple[XrayAgentTypeInfo, ...]
    node_kinds: tuple[XrayNodeKindInfo, ...]
    categories: tuple[XrayCategoryInfo, ...]
    nesting: XrayNesting

    def to_json(self) -> JsonObject:
        """The vocabulary as a JSON object."""
        return {
            "tool": self.tool,
            "root": {"type": self.root.type, "name": self.root.name},
            "source_kinds": objects(
                {"key": item.key, "label": item.label, "letter": item.letter, "small": item.small}
                for item in self.source_kinds
            ),
            "agent_types": objects(
                {"key": item.key, "label": item.label, "colour": item.colour, "icon": item.icon}
                for item in self.agent_types
            ),
            "node_kinds": objects(
                {"key": item.key, "label": item.label, "opens": item.opens, "has_spine": item.has_spine}
                for item in self.node_kinds
            ),
            "categories": objects(
                {"key": item.key, "label": item.label, "track": item.track} for item in self.categories
            ),
            "nesting": {"enabled": self.nesting.enabled, "max_depth": self.nesting.max_depth},
        }


@dataclass(frozen=True)
class XrayView:
    """Everything the session page draws; the window is null until a reply's context shows the size."""

    version: int
    info: XraySessionInfo
    model: str | None
    window: XrayWindow | None
    adapter: AdapterVocabulary
    nodes: tuple[XrayNode, ...]
    edges: tuple[XrayEdge, ...]
    sources: tuple[XraySource, ...]
    stations: tuple[XrayStation, ...]
    tracks: tuple[XrayTrack, ...]
    gaps: XrayGaps
    verdict: XrayVerdict

    def to_json(self) -> JsonObject:
        """The view as a JSON object."""
        return {
            "version": self.version,
            "session": self.info.session,
            "project": self.info.project,
            "started_at": self.info.started_at,
            "length_s": self.info.length_s,
            "model": self.model,
            "window": None if self.window is None else self.window.to_json(),
            "adapter": self.adapter.to_json(),
            "nodes": objects(node.to_json() for node in self.nodes),
            "edges": objects(edge.to_json() for edge in self.edges),
            "sources": objects(source.to_json() for source in self.sources),
            "stations": objects(station.to_json() for station in self.stations),
            "track": objects(track.to_json() for track in self.tracks),
            "funnel": objects(row.to_json() for row in self.verdict.funnel),
            "facts": objects(fact.to_json() for fact in self.verdict.facts),
            "check": self.verdict.check.to_json(),
            "refusals": list(self.gaps.refusals),
            "not_known": list(self.gaps.not_known),
        }
