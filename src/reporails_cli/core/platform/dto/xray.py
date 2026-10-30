"""The session view: one session's loads, turns, subagents and files as numbers, names and paths.

A view never holds prompt, tool or file text. A value with no source is `None`, which reads as
"not known here".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue

LoadKind = Literal["project", "memory", "user", "local", "managed", "nested", "other"]
CompactionTrigger = Literal["manual", "auto"]
ArtifactKind = Literal["instructions", "memory", "skill", "agent", "hook"]

# The kind of an instruction-file load as the transcript names it, to the view's load kind.
LOAD_KIND_OF_MEMORY_TYPE: dict[str, LoadKind] = {
    "Project": "project",
    "AutoMem": "memory",
    "User": "user",
    "Local": "local",
    "Managed": "managed",
    "nested": "nested",
}


def _objects(items: list[JsonObject]) -> JsonValue:
    values: list[JsonValue] = list(items)
    return values


@dataclass(frozen=True)
class XrayLoad:
    """One instruction file loaded into a context."""

    path: str
    kind: LoadKind
    t: float | None
    tokens_est: int | None
    findings: int | None

    def to_json(self) -> JsonObject:
        """The load as a JSON object."""
        return {
            "path": self.path,
            "kind": self.kind,
            "t": self.t,
            "tokens_est": self.tokens_est,
            "findings": self.findings,
        }


@dataclass(frozen=True)
class XrayCompaction:
    """One compaction: when, what started it and the context before and after."""

    t: float
    trigger: CompactionTrigger | None
    before: int | None
    after: int | None

    def to_json(self) -> JsonObject:
        """The compaction as a JSON object."""
        return {"t": self.t, "trigger": self.trigger, "before": self.before, "after": self.after}


@dataclass(frozen=True)
class XrayTurn:
    """The replies between two turn ends, the last turn open while the session runs."""

    n: int
    t: float
    context_start: int | None
    context: int | None
    replies: int
    loads: tuple[XrayLoad, ...]
    reads: tuple[str, ...] | None
    subagents: tuple[str, ...]
    compaction: XrayCompaction | None

    def to_json(self) -> JsonObject:
        """The turn as a JSON object."""
        reads: JsonValue = None if self.reads is None else list(self.reads)
        return {
            "n": self.n,
            "t": self.t,
            "context_start": self.context_start,
            "context": self.context,
            "replies": self.replies,
            "loads": _objects([load.to_json() for load in self.loads]),
            "reads": reads,
            "subagents": list(self.subagents),
            "compaction": None if self.compaction is None else self.compaction.to_json(),
        }


@dataclass(frozen=True)
class XraySubagent:
    """One subagent run: its type, where it started and its own context over time."""

    id: str
    type: str | None
    turn: int | None
    start: float | None
    end: float | None
    series: tuple[tuple[float, int], ...]
    loads: tuple[XrayLoad, ...]

    def to_json(self) -> JsonObject:
        """The subagent as a JSON object."""
        series: list[JsonValue] = [[t, context] for t, context in self.series]
        return {
            "id": self.id,
            "type": self.type,
            "turn": self.turn,
            "start": self.start,
            "end": self.end,
            "series": series,
            "loads": _objects([load.to_json() for load in self.loads]),
        }


@dataclass(frozen=True)
class XrayArtifact:
    """A file the session could load, whether it did, the turns it sat in context and whether the page may
    check or fix it (a file of the project that exists)."""

    path: str
    kind: ArtifactKind
    loaded: bool
    turns: tuple[int, ...]
    findings: int | None
    actionable: bool

    def to_json(self) -> JsonObject:
        """The artifact as a JSON object."""
        return {
            "path": self.path,
            "kind": self.kind,
            "loaded": self.loaded,
            "turns": list(self.turns),
            "findings": self.findings,
            "actionable": self.actionable,
        }


@dataclass(frozen=True)
class XrayView:
    """Everything the session page draws; the context window size is never known here, so it is always null."""

    version: int
    session: str
    project: str
    started_at: str | None
    length_s: float | None
    first_context: int | None
    start: tuple[XrayLoad, ...]
    turns: tuple[XrayTurn, ...]
    subagents: tuple[XraySubagent, ...]
    artifacts: tuple[XrayArtifact, ...]
    refusals: tuple[str, ...]
    not_known: tuple[str, ...]

    def to_json(self) -> JsonObject:
        """The view as a JSON object."""
        return {
            "version": self.version,
            "session": self.session,
            "project": self.project,
            "started_at": self.started_at,
            "length_s": self.length_s,
            "window": None,
            "first_context": self.first_context,
            "start": _objects([load.to_json() for load in self.start]),
            "turns": _objects([turn.to_json() for turn in self.turns]),
            "subagents": _objects([sub.to_json() for sub in self.subagents]),
            "artifacts": _objects([artifact.to_json() for artifact in self.artifacts]),
            "refusals": list(self.refusals),
            "not_known": list(self.not_known),
        }
