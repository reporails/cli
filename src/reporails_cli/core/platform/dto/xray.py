"""The session view: one session's agents, the sources they had and the calls they made, as numbers, names and
paths.

A view never holds prompt, tool or file text. A value with no source is `None`, which reads as
"not known here".
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.events import HarnessKind, ToolCategory
from reporails_cli.core.platform.dto.xray_composition import CompositionKey, XrayCompositionLabel
from reporails_cli.core.platform.dto.xray_cost import PriceListInfo, XraySessionCost
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
from reporails_cli.core.platform.dto.xray_sources import XrayBuiltin, XrayBuiltinInfo, XrayContextText, XraySource

CheckState = Literal["running", "done", "refused"]
FactKind = Literal["memory_unlinked", "repeated_instructions", "kind_absent"]
TargetKind = Literal["path", "node", "kind"]


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


SessionPick = Literal["named", "current", "current_unknown", "current_ambiguous", "newest"]


@dataclass(frozen=True)
class PickedSession:
    """The session the x-ray shows: the folder Claude Code holds it under, its transcript and how it was chosen."""

    root: Path
    transcript: Path
    picked: SessionPick


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
    """A running x-ray page: its port and the id of its launch."""

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
    # What a source of the kind being used means (loaded, launched, read, connected, fired) and the noun the graph's
    # eye button hides it under.
    verb: str
    graph_label: str
    note: str | None = None
    # Its sources are definitions that subagents are launched from.
    definitions: bool = False
    # Files of the kind count as "instructions in context" at a call.
    instructions: bool = False
    # The kind's loads stay on the spine as stations of their own.
    spine: bool = False


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
    """One tool category the page counts: its label, whether its calls sit on the side track, its colour and
    whether its calls carry a shell command the page can fetch."""

    key: ToolCategory
    label: str
    track: bool
    colour: str
    command: bool = False


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
class XrayCompositionVocabulary:
    """The categories a context is split into, in row order, and the one that takes what the estimates leave."""

    labels: tuple[XrayCompositionLabel, ...]
    remainder: CompositionKey


@dataclass(frozen=True)
class XrayContextVocabulary:
    """The built-in items of the coding agent's context in display order, and the words of the "in context" rows
    that are no source."""

    builtin: tuple[XrayBuiltinInfo, ...]
    texts: tuple[XrayContextText, ...]


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
    composition: XrayCompositionVocabulary
    burst: XrayBurstSettings
    context: XrayContextVocabulary

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
                    "verb": item.verb,
                    "graph_label": item.graph_label,
                    "note": item.note,
                    "definitions": item.definitions,
                    "instructions": item.instructions,
                    "spine": item.spine,
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
                {
                    "key": item.key,
                    "label": item.label,
                    "track": item.track,
                    "colour": item.colour,
                    "command": item.command,
                }
                for item in self.categories
            ),
            "nesting": {"enabled": self.nesting.enabled, "max_depth": self.nesting.max_depth},
            "triggers": objects({"key": item.key, "label": item.label} for item in self.triggers),
            "fact_notes": notes,
            "composition": objects({"key": item.key, "label": item.label} for item in self.composition.labels),
            "composition_remainder": self.composition.remainder,
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
    builtin: tuple[XrayBuiltin, ...]
    session_cost: XraySessionCost


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
            "builtin": objects(item.to_json() for item in self.builtin),
            "session_cost": self.session_cost.to_json(),
            "funnel": objects(row.to_json() for row in self.verdict.funnel),
            "facts": objects(fact.to_json() for fact in self.verdict.facts),
            "check": self.verdict.check.to_json(),
            "refusals": list(self.gaps.refusals),
            "not_known": list(self.gaps.not_known),
        }
