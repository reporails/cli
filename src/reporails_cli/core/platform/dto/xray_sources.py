"""The sources of a session view: the files, built-in context items and other things that can enter a context,
as numbers, names and paths. Never prompt, tool or file text beyond a peek the user asks for."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, TypeGuard, get_args

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.events import HarnessKind
from reporails_cli.core.platform.dto.exclusion import FileLeftOut
from reporails_cli.core.platform.dto.xray_graph import ContextKey, SourceKind

ArtifactKind = Literal["instructions", "rule", "memory", "skill", "agent", "command", "hook"]


ArtifactScope = Literal["project", "user", "managed", "local", "plugin", "auto", "synced"]


# `unrecorded`: the session holds no load record of the source's kind, so "not loaded" cannot be told.
Availability = Literal["loaded", "listed", "on_disk", "unrecorded"]


MemoryRole = Literal["index", "item"]


# Whether a built-in context item's text can be read in the transcript.
Visibility = Literal["hidden", "partial", "shown"]


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
class XrayBuiltin:
    """One item of the coding agent's own context: its key, label, estimated size, a note on what it holds, whether
    its text can be read in the transcript and whether its size carries what the estimates leave of the total."""

    key: HarnessKind
    label: str
    tokens_est: int
    note: str | None
    visible: Visibility
    remainder: bool

    def to_json(self) -> JsonObject:
        """The item as a JSON object."""
        return {
            "key": self.key,
            "label": self.label,
            "tokens_est": self.tokens_est,
            "note": self.note,
            "visible": self.visible,
            "remainder": self.remainder,
        }


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
    # A rule's path patterns, and an MCP server's tools with the calls each received.
    scopes: tuple[str, ...] = ()
    tools: tuple[tuple[str, int], ...] = ()
    # What keeps the file out of a project-wide check or fix, and where a link out of the project leads.
    excluded: FileLeftOut = field(default_factory=FileLeftOut)


@dataclass(frozen=True)
class AgentLaunch:
    """What the first launch of an agent type that recorded a request was sent with: its system prompt size in
    tokens, and each tool the type's launches were sent with and how many launches had it."""

    system_tokens_est: int
    tools: tuple[tuple[str, int], ...]
    # What the launches were set up with, as (label, value) lines the page lists as written.
    settings: tuple[tuple[str, str], ...] = ()


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
    # The name the page shows the source by.
    label: str
    # A rule's path patterns (empty for any other kind) and an MCP server's tools with their call counts (likewise).
    scopes: tuple[str, ...] = ()
    tools: tuple[tuple[str, int], ...] = ()
    # What keeps the file out of a project-wide check or fix, and where a link out of the project leads.
    excluded: FileLeftOut = field(default_factory=FileLeftOut)
    # The type key of an agent source.
    agent_type: str | None = None
    # Whether a memory file is the memory index or an item (None for any other kind).
    memory_role: MemoryRole | None = None
    # What an agent source's launches were sent with (None when no launch recorded a request).
    launch: AgentLaunch | None = None

    @property
    def builtin(self) -> bool:
        """Whether the source is an agent type the coding agent ships with no definition file."""
        return self.agent_type is not None and self.path is None

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
            "excluded": self.excluded.to_json(),
            "launches": self.launches,
            "cost_usd_est": self.cost_usd_est,
            "label": self.label,
            "scopes": list(self.scopes),
            "tools": [[tool, calls] for tool, calls in self.tools],
            "launch_tools": [[tool, launches] for tool, launches in (self.launch.tools if self.launch else ())],
            "agent_type": self.agent_type,
            "builtin": self.builtin,
            "memory_role": self.memory_role,
            "system_tokens_est": self.launch.system_tokens_est if self.launch else None,
            "launch_settings": [[label, value] for label, value in (self.launch.settings if self.launch else ())],
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
    scopes: tuple[str, ...]
    excluded: FileLeftOut


@dataclass(frozen=True)
class XrayPeek:
    """A listed file's text cut at the peek limit, whether it was cut, its frontmatter block's text (None when it
    has none) and the text after that block."""

    text: str
    truncated: bool
    frontmatter: str | None
    body: str


@dataclass(frozen=True)
class XrayBuiltinInfo:
    """One built-in context item of the coding agent: its harness kind, label, whether its text can be read in the
    transcript and a note template filled from the item's count (`{count}`); a template that needs a count the
    item lacks gives no note; `note_once` words a count of one."""

    key: HarnessKind
    label: str
    visible: Visibility
    note: str | None
    note_once: str | None = None
    # The note when the size is measured from the recorded request.
    measured_note: str | None = None


@dataclass(frozen=True)
class XrayContextText:
    """The label and reason the coding agent words one kind of "in context" row with; a reason may hold the
    fire count as `{count}`; `reason_once` words a count of one."""

    key: ContextKey
    label: str
    reason: str
    reason_once: str | None = None
