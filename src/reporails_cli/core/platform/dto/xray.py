"""The session view: one session's agents, the sources they had and the calls they made, as numbers, names and
paths.

A view never holds prompt, tool or file text. A value with no source is `None`, which reads as
"not known here".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeGuard, get_args

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.events import HarnessKind, ToolCategory
from reporails_cli.core.platform.dto.xray_composition import CompositionKey, XrayCompositionLabel
from reporails_cli.core.platform.dto.xray_cost import PriceListInfo
from reporails_cli.core.platform.dto.xray_graph import (
    LoadTrigger,
    NodeKind,
    SourceKind,
    XrayEdge,
    XrayNode,
    XrayStation,
    XrayTrack,
    objects,
)

ArtifactKind = Literal["instructions", "rule", "memory", "skill", "agent", "command", "hook"]
ArtifactScope = Literal["project", "user", "managed", "local", "plugin", "auto", "synced"]
CheckState = Literal["running", "done", "refused"]
FactKind = Literal["memory_unlinked", "repeated_instructions", "kind_absent"]
TargetKind = Literal["path", "node", "kind"]
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

# The kind of artifact that defines a subagent type.
AGENT_ARTIFACT_KINDS: frozenset[ArtifactKind] = frozenset({"agent"})

# Which scope wins when two listed files share a label, highest first. The skills page ranks managed over user over
# project, the sub-agents page managed over project over user; a plugin's file carries its plugin's name in its
# label and never competes.
SCOPE_PRECEDENCE: dict[ArtifactKind, tuple[ArtifactScope, ...]] = {
    "skill": ("managed", "user", "project"),
    "command": ("managed", "user", "project"),
    "agent": ("managed", "project", "user"),
}

# The source kind an artifact kind is shown as; hook configs are no source.
SOURCE_KIND_OF_ARTIFACT: dict[ArtifactKind, SourceKind] = {
    "instructions": "instructions",
    "rule": "rule",
    "memory": "memory",
    "skill": "skill",
    "command": "skill",
    "agent": "agent",
}


def is_artifact_scope(precedence: str) -> TypeGuard[ArtifactScope]:
    """Whether a config scope's precedence is one of the scopes the view shows."""
    return precedence in get_args(ArtifactScope)


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
class XrayHarnessItem:
    """One piece of the harness's own context at an agent's start, sized by an estimate."""

    kind: HarnessKind
    label: str
    count: int | None
    tokens_est: int | None


@dataclass(frozen=True)
class SourceFacts:
    """What a source is before any node's context is known: its id, kind, name, path (None for an MCP server or a
    hook), size and findings."""

    id: str
    kind: SourceKind
    name: str
    path: str | None
    tokens_est: int | None
    findings: FindingTally | None


@dataclass(frozen=True)
class SourceEntry(SourceFacts):
    """A source with whether the page may check or fix it, whether the harness listed it by name (None when no
    listing names its kind) and whether the memory index links it (None for any other kind)."""

    actionable: bool
    advertised: bool | None
    linked: bool | None


@dataclass(frozen=True)
class XraySource(SourceFacts):
    """One thing that can enter a context: its source facts, whether it loaded, was only listed or sat on disk, the
    nodes whose context it entered, and whether the page may check or fix it."""

    availability: Availability
    had_by: tuple[str, ...]
    actionable: bool
    # How many agents ran from an agent definition (None for any other kind).
    launches: int | None
    # What the source cost across every reply that carried it, an estimate; None when no priced reply carried it.
    cost_usd_est: float | None

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
            "launches": self.launches,
            "cost_usd_est": self.cost_usd_est,
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


SessionPick = Literal["named", "current", "current_unknown", "newest"]


@dataclass(frozen=True)
class XraySessionInfo:
    """Which session and project the page shows, when the session began (the time of its first record), how
    long it ran, in seconds, and how the session was chosen."""

    session: str
    project: str
    started_at: str | None
    length_s: float | None
    picked: SessionPick


@dataclass(frozen=True)
class XraySessionEntry:
    """One session of a project as the switcher lists it: its id, when it began, how long it ran, in seconds, and
    how many subagents it started."""

    session: str
    started_at: str | None
    length_s: float | None
    subagents: int

    def to_json(self) -> JsonObject:
        """The entry as a JSON object."""
        return {
            "session": self.session,
            "started_at": self.started_at,
            "length_s": self.length_s,
            "subagents": self.subagents,
        }


@dataclass(frozen=True)
class XrayPage:
    """A running x-ray page: the process serving it, its port and the id of its launch."""

    pid: int
    port: int
    launch: str


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
    note: str | None = None
    # Its sources are definitions that subagents are launched from.
    definitions: bool = False


@dataclass(frozen=True)
class XrayAgentTypeInfo:
    """One agent type the page can draw: its key as the transcript names it, a short label, a colour and an icon
    path in a 24-unit box."""

    key: str
    label: str
    colour: str
    icon: str


@dataclass(frozen=True)
class XrayTriggerInfo:
    """What brought a source into a context, as the coding agent words it for a tooltip."""

    key: LoadTrigger
    label: str


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
class XrayBurstSettings:
    """When children launched close together count as a burst: the window in seconds, its share of the launching
    node's span (the larger of the two applies) and the fewest children."""

    window_s: float
    window_share: float
    min_size: int


@dataclass(frozen=True)
class AdapterVocabulary:
    """What a coding agent calls things: its tool name, its root, source kinds, agent types, node kinds, tool
    categories, nesting, load triggers and fact notes."""

    tool: str
    root: XrayRoot
    source_kinds: tuple[XraySourceKindInfo, ...]
    agent_types: tuple[XrayAgentTypeInfo, ...]
    node_kinds: tuple[XrayNodeKindInfo, ...]
    categories: tuple[XrayCategoryInfo, ...]
    nesting: XrayNesting
    triggers: tuple[XrayTriggerInfo, ...]
    # A sentence template per annotated fact kind, filled from the fact's numbers and the source kind's label.
    fact_notes: dict[FactKind, str]
    # The categories a context is split into, in row order, and the one that takes what the estimates leave.
    composition: tuple[XrayCompositionLabel, ...]
    composition_remainder: CompositionKey
    burst: XrayBurstSettings

    def to_json(self) -> JsonObject:
        """The vocabulary as a JSON object."""
        notes: dict[str, JsonValue] = {str(kind): text for kind, text in self.fact_notes.items()}
        return {
            "tool": self.tool,
            "root": {"type": self.root.type, "name": self.root.name},
            "source_kinds": objects(
                {
                    "key": item.key,
                    "label": item.label,
                    "letter": item.letter,
                    "small": item.small,
                    "note": item.note,
                    "definitions": item.definitions,
                }
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
            "triggers": objects({"key": item.key, "label": item.label} for item in self.triggers),
            "fact_notes": notes,
            "composition": objects({"key": item.key, "label": item.label} for item in self.composition),
            "composition_remainder": self.composition_remainder,
            "burst": {
                "window_s": self.burst.window_s,
                "window_share": self.burst.window_share,
                "min_size": self.burst.min_size,
            },
        }


@dataclass(frozen=True)
class Graph:
    """The session graph: nodes in producer order, their edges, the sources with who had them, and the station and
    track of each node with a spine."""

    nodes: tuple[XrayNode, ...]
    edges: tuple[XrayEdge, ...]
    sources: tuple[XraySource, ...]
    stations: tuple[XrayStation, ...]
    tracks: tuple[XrayTrack, ...]


@dataclass(frozen=True)
class XrayView(Graph):
    """Everything the session page draws, the graph first; the window is null until a reply's context shows the
    size."""

    version: int
    info: XraySessionInfo
    model: str | None
    window: XrayWindow | None
    adapter: AdapterVocabulary
    price_list: PriceListInfo
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
            "picked": self.info.picked,
            "model": self.model,
            "window": None if self.window is None else self.window.to_json(),
            "adapter": self.adapter.to_json(),
            "price_list": self.price_list.to_json(),
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
