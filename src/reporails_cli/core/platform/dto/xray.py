"""The session view: one session's loads, turns, subagents and files as numbers, names and paths.

A view never holds prompt, tool or file text. A value with no source is `None`, which reads as
"not known here".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeGuard, get_args

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.events import HarnessKind, NoteKind

LoadKind = Literal["project", "memory", "user", "local", "managed", "nested", "other"]
CompactionTrigger = Literal["manual", "auto"]
TurnOpener = Literal["prompt", "stop_hook", "session_start"]
ArtifactKind = Literal["instructions", "rule", "memory", "skill", "agent", "command", "hook"]
ArtifactScope = Literal["project", "user", "managed", "local", "plugin", "auto", "synced"]
CheckState = Literal["running", "done", "refused"]
FactKind = Literal[
    "file_findings", "funnel_drop", "memory_unlinked", "compaction_loss", "repeated_instructions", "kind_absent"
]
TargetKind = Literal["path", "turn", "subagent", "kind"]

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
    """One instruction file loaded into a context."""

    path: str
    kind: LoadKind
    t: float | None
    tokens_est: int | None
    findings: FindingTally | None

    def to_json(self) -> JsonObject:
        """The load as a JSON object."""
        return {
            "path": self.path,
            "kind": self.kind,
            "t": self.t,
            "tokens_est": self.tokens_est,
            "findings": _tally_json(self.findings),
        }


@dataclass(frozen=True)
class XrayCompaction:
    """One compaction: the turn it ran in, when, what started it, the context before and after, and when the band
    it opens ends (the next compaction, else the session's end)."""

    turn: int
    t: float
    trigger: CompactionTrigger | None
    before: int | None
    after: int | None
    band_end: float

    def to_json(self) -> JsonObject:
        """The compaction as a JSON object."""
        return {
            "turn": self.turn,
            "t": self.t,
            "trigger": self.trigger,
            "before": self.before,
            "after": self.after,
            "band_end": self.band_end,
        }


@dataclass(frozen=True)
class XrayPrompt:
    """One prompt a person typed in a turn: its number in the session, the id the page asks the text by, when, its
    size and whether it was queued while the agent worked. Never the text."""

    no: int
    id: str
    t: float
    chars: int
    queued: bool

    def to_json(self) -> JsonObject:
        """The prompt as a JSON object."""
        return {"no": self.no, "id": self.id, "t": self.t, "chars": self.chars, "queued": self.queued}


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
class XrayRun:
    """One skill or command run: its name, when, whether it ran in a subagent of its own, and for a listed file its
    project-relative path and size; a run whose name matches no listed file has neither."""

    name: str
    t: float
    forked: bool
    path: str | None
    tokens_est: int | None

    def to_json(self) -> JsonObject:
        """The run as a JSON object."""
        return {
            "name": self.name,
            "t": self.t,
            "forked": self.forked,
            "path": self.path,
            "tokens_est": self.tokens_est,
        }


@dataclass(frozen=True)
class XrayTurn:
    """The replies between two turn ends, the last turn open while the session runs: when it began, what opened it,
    how many Stop blocks it held and how far its context moved from the last one known."""

    n: int
    start: float
    opened_by: TurnOpener | None
    stop_blocks: int
    delta: int | None
    t: float
    context_start: int | None
    context: int | None
    loads: tuple[XrayLoad, ...]
    reads: tuple[str, ...] | None
    subagents: tuple[str, ...]
    series: tuple[tuple[float, int], ...]
    prompts: tuple[XrayPrompt, ...]
    notes: tuple[XrayNote, ...]
    skill_runs: tuple[XrayRun, ...]

    def to_json(self) -> JsonObject:
        """The turn as a JSON object."""
        reads: JsonValue = None if self.reads is None else list(self.reads)
        series: list[JsonValue] = [[t, context] for t, context in self.series]
        return {
            "n": self.n,
            "start": self.start,
            "opened_by": self.opened_by,
            "stop_blocks": self.stop_blocks,
            "delta": self.delta,
            "t": self.t,
            "context_start": self.context_start,
            "context": self.context,
            "replies": len(self.series),
            "loads": _objects([load.to_json() for load in self.loads]),
            "reads": reads,
            "subagents": list(self.subagents),
            "series": series,
            "prompts": _objects([prompt.to_json() for prompt in self.prompts]),
            "notes": _objects([note.to_json() for note in self.notes]),
            "skill_runs": _objects([run.to_json() for run in self.skill_runs]),
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
    skill_runs: tuple[XrayRun, ...]
    peak: int | None
    has_project_instructions: bool

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
            "skill_runs": _objects([run.to_json() for run in self.skill_runs]),
            "peak": self.peak,
            "has_project_instructions": self.has_project_instructions,
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
    """A file the session could load, whether the harness listed it by name (`advertised`, None when no listing
    names its kind), whether it loaded, the turns it sat in context, whether the page may check or fix it (a file
    of the project that exists), and how many contexts (the main session's and each subagent's) it entered, with
    its size over all of them."""

    loaded: bool
    turns: tuple[int, ...]
    findings: FindingTally | None
    actionable: bool
    tokens_est: int | None
    advertised: bool | None
    contexts: int
    session_tokens_est: int | None

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
            "findings": _tally_json(self.findings),
            "actionable": self.actionable,
            "tokens_est": self.tokens_est,
            "advertised": self.advertised,
            "contexts": self.contexts,
            "session_tokens_est": self.session_tokens_est,
        }


@dataclass(frozen=True)
class XrayFunnelRow:
    """How many artifacts of a kind sit on disk, are advertised by the harness, load and are used; a count with
    no source is None."""

    kind: ArtifactKind
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
    """What a fact points at on the page: a file path, a turn number, a subagent id or an artifact kind."""

    kind: TargetKind
    value: str | int

    def to_json(self) -> JsonObject:
        """The target as a JSON object."""
        return {"kind": self.kind, "value": self.value}


@dataclass(frozen=True)
class XrayFact:
    """One headline fact of the session: its kind, the artifact kind it is about, its named counts and its target."""

    kind: FactKind
    artifact_kind: ArtifactKind | None
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
    """Everything the session page draws; the window is null until a reply's context shows the size."""

    version: int
    session: str
    project: str
    span: XraySpan
    first_context: int | None
    peak: int | None
    preload_tokens_est: int | None
    start: tuple[XrayLoad, ...]
    turns: tuple[XrayTurn, ...]
    compactions: tuple[XrayCompaction, ...]
    subagents: tuple[XraySubagent, ...]
    artifacts: tuple[XrayArtifact, ...]
    refusals: tuple[str, ...]
    not_known: tuple[str, ...]
    harness: tuple[XrayHarnessItem, ...] | None
    model: str | None
    window: XrayWindow | None
    funnel: tuple[XrayFunnelRow, ...]
    check: XrayCheck
    facts: tuple[XrayFact, ...]

    def to_json(self) -> JsonObject:
        """The view as a JSON object."""
        return {
            "version": self.version,
            "session": self.session,
            "project": self.project,
            "started_at": self.span.started_at,
            "length_s": self.span.length_s,
            "model": self.model,
            "window": None if self.window is None else self.window.to_json(),
            "funnel": _objects([row.to_json() for row in self.funnel]),
            "first_context": self.first_context,
            "peak": self.peak,
            "preload_tokens_est": self.preload_tokens_est,
            "start": _objects([load.to_json() for load in self.start]),
            "turns": _objects([turn.to_json() for turn in self.turns]),
            "compactions": _objects([compaction.to_json() for compaction in self.compactions]),
            "subagents": _objects([sub.to_json() for sub in self.subagents]),
            "artifacts": _objects([artifact.to_json() for artifact in self.artifacts]),
            "refusals": list(self.refusals),
            "not_known": list(self.not_known),
            "harness": None if self.harness is None else _objects([item.to_json() for item in self.harness]),
            "check": self.check.to_json(),
            "facts": _objects([fact.to_json() for fact in self.facts]),
        }
