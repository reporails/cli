"""The session view: one session's loads, turns, subagents and files as numbers, names and paths.

A view never holds prompt, tool or file text. A value with no source is `None`, which reads as
"not known here".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeGuard, get_args

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.events import HarnessKind, NoteKind

LoadKind = Literal["project", "memory", "user", "local", "managed", "nested", "other"]
CompactionTrigger = Literal["manual", "auto"]
ArtifactKind = Literal["instructions", "rule", "memory", "skill", "agent", "command", "hook"]
ArtifactScope = Literal["project", "user", "managed", "local", "plugin", "auto"]

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

# The kind of an instruction-file load as the transcript names it, to the view's load kind.
LOAD_KIND_OF_MEMORY_TYPE: dict[str, LoadKind] = {
    "Project": "project",
    "AutoMem": "memory",
    "User": "user",
    "Local": "local",
    "Managed": "managed",
    "nested": "nested",
}


def is_artifact_scope(precedence: str) -> TypeGuard[ArtifactScope]:
    """Whether a config scope's precedence is one of the scopes the view shows."""
    return precedence in get_args(ArtifactScope)


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
class XrayPrompt:
    """One prompt a person typed in a turn: the id the page asks the text by, when, its size and whether it was
    queued while the agent worked. Never the text."""

    id: str
    t: float
    chars: int
    queued: bool

    def to_json(self) -> JsonObject:
        """The prompt as a JSON object."""
        return {"id": self.id, "t": self.t, "chars": self.chars, "queued": self.queued}


@dataclass(frozen=True)
class XrayNote:
    """One note a hook put into a turn: a hook's added context or a Stop block, sized by an estimate."""

    kind: NoteKind
    event: str
    label: str
    t: float
    tokens_est: int

    def to_json(self) -> JsonObject:
        """The note as a JSON object."""
        return {
            "kind": self.kind,
            "event": self.event,
            "label": self.label,
            "t": self.t,
            "tokens_est": self.tokens_est,
        }


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
    series: tuple[tuple[float, int], ...]
    prompts: tuple[XrayPrompt, ...]
    notes: tuple[XrayNote, ...]

    def to_json(self) -> JsonObject:
        """The turn as a JSON object."""
        reads: JsonValue = None if self.reads is None else list(self.reads)
        series: list[JsonValue] = [[t, context] for t, context in self.series]
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
            "series": series,
            "prompts": _objects([prompt.to_json() for prompt in self.prompts]),
            "notes": _objects([note.to_json() for note in self.notes]),
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
    """A file the session could load, whether it did, the turns it sat in context and whether the page may
    check or fix it (a file of the project that exists)."""

    loaded: bool
    turns: tuple[int, ...]
    findings: int | None
    actionable: bool
    tokens_est: int | None

    def to_json(self) -> JsonObject:
        """The artifact as a JSON object."""
        return {
            "path": self.path,
            "kind": self.kind,
            "scope": self.scope,
            "plugin": self.plugin,
            "label": self.label,
            "memory_type": self.memory_type,
            "linked": self.linked,
            "loaded": self.loaded,
            "turns": list(self.turns),
            "findings": self.findings,
            "actionable": self.actionable,
            "tokens_est": self.tokens_est,
        }


@dataclass(frozen=True)
class XrayHarnessItem:
    """One piece of the harness's own context at session start, sized by an estimate."""

    kind: HarnessKind
    label: str
    count: int | None
    tokens_est: int | None

    def to_json(self) -> JsonObject:
        """The item as a JSON object."""
        return {
            "kind": self.kind,
            "label": self.label,
            "count": self.count,
            "tokens_est": self.tokens_est,
        }


@dataclass(frozen=True)
class XraySpan:
    """When the session began (the time of its first record) and how long it ran, in seconds."""

    started_at: str | None
    length_s: float | None


@dataclass(frozen=True)
class XrayView:
    """Everything the session page draws; the context window size is never known here, so it is always null."""

    version: int
    session: str
    project: str
    span: XraySpan
    first_context: int | None
    start: tuple[XrayLoad, ...]
    turns: tuple[XrayTurn, ...]
    subagents: tuple[XraySubagent, ...]
    artifacts: tuple[XrayArtifact, ...]
    refusals: tuple[str, ...]
    not_known: tuple[str, ...]
    harness: tuple[XrayHarnessItem, ...] | None

    def to_json(self) -> JsonObject:
        """The view as a JSON object."""
        return {
            "version": self.version,
            "session": self.session,
            "project": self.project,
            "started_at": self.span.started_at,
            "length_s": self.span.length_s,
            "window": None,
            "first_context": self.first_context,
            "start": _objects([load.to_json() for load in self.start]),
            "turns": _objects([turn.to_json() for turn in self.turns]),
            "subagents": _objects([sub.to_json() for sub in self.subagents]),
            "artifacts": _objects([artifact.to_json() for artifact in self.artifacts]),
            "refusals": list(self.refusals),
            "not_known": list(self.not_known),
            "harness": None if self.harness is None else _objects([item.to_json() for item in self.harness]),
        }
