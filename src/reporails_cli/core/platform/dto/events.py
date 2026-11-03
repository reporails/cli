"""The event record: one hook event of an agent session, reduced to ids, names and paths.

A record never holds prompt text, tool input text or tool output.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, TypeGuard, get_args

from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    JsonValue,
    as_object,
    as_str,
    opt_int,
    opt_str,
    str_list,
)

if TYPE_CHECKING:
    from hashlib import _Hash

EventKind = Literal[
    "session_start",
    "session_end",
    "prompt_submit",
    "pre_tool",
    "post_tool",
    "stop",
    "subagent_stop",
    "pre_compact",
    "post_compact",
    "refusal",
    "assistant_usage",
    "turn_end",
    "subagent_run",
    "skill_run",
    "instruction_load",
    "harness",
    "tool_call",
    "tool_result",
    "assistant_text",
    "api_request",
]

# What a tool call does, as the side track and the inspector group it; `handback` is a subagent handing its result
# back to the agent that launched it.
ToolCategory = Literal["read", "edit", "run", "mcp", "agent", "handback", "other"]

# Whether the calls of each category target a file.
TARGETS_FILE: dict[ToolCategory, bool] = {
    "read": True,
    "edit": True,
    "run": False,
    "mcp": False,
    "agent": False,
    "handback": False,
    "other": False,
}

NoteKind = Literal["hook_note", "stop_block"]

HarnessKind = (
    Literal[
        "system_prompt",
        "skill_list",
        "agent_list",
        "mcp_instructions",
        "deferred_tools",
        "tool_definitions",
        "session_context",
    ]
    | NoteKind
)

# The harness kinds whose records are changes to a list, so a session's total is their sum.
DELTA_KINDS: frozenset[HarnessKind] = frozenset({"skill_list", "agent_list", "mcp_instructions", "deferred_tools"})


# The records an assistant row yields besides its usage: its text and its tool calls.
ASSISTANT_ROW_KINDS: frozenset[EventKind] = frozenset({"assistant_text", "tool_call"})


def is_event_kind(value: str) -> TypeGuard[EventKind]:
    """Whether `value` is one of the event kinds."""
    return value in get_args(EventKind)


def is_note_kind(kind: HarnessKind) -> TypeGuard[NoteKind]:
    """Whether a harness kind is a hook's note rather than a piece of the session's own context."""
    return kind in get_args(NoteKind)


_USAGE_KEYS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
# The counts a reply may leave out; a stored or written one that is present must be a whole number.
_OPTIONAL_USAGE_KEYS = ("output_tokens", "cache_write_5m_tokens", "cache_write_1h_tokens")


@dataclass(frozen=True)
class TokenUsage:
    """One assistant reply: the id of the API response and its token counts (fresh input, cache writes, cache reads,
    and where the row carries them the output and the cache writes by lifetime)."""

    message_id: str
    input_tokens: int
    cache_creation_input_tokens: int
    cache_read_input_tokens: int
    # The model that wrote the reply; None when the row names none.
    model: str | None = None
    # None when the row does not carry the count.
    output_tokens: int | None = None
    cache_write_5m_tokens: int | None = None
    cache_write_1h_tokens: int | None = None
    # The id of the API request this reply answers; None when the row names none.
    request_ref: str | None = None

    def counts_json(self) -> JsonObject:
        """The counts and the model as a JSON object."""
        return {
            "model": self.model,
            "input_tokens": self.input_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
            "output_tokens": self.output_tokens,
            "cache_write_5m_tokens": self.cache_write_5m_tokens,
            "cache_write_1h_tokens": self.cache_write_1h_tokens,
            "request_ref": self.request_ref,
        }

    @classmethod
    def from_json(cls, message_id: str | None, counts: JsonObject) -> TokenUsage | None:
        """The usage of reply `message_id` with the counts a stored object holds, or None when the id is missing,
        any of the three input counts is not a whole number, or a present optional count is not one."""
        values = [opt_int(counts.get(key)) for key in _USAGE_KEYS]
        optional = [opt_int(counts.get(key)) for key in _OPTIONAL_USAGE_KEYS]
        malformed = any(
            counts.get(key) is not None and got is None for key, got in zip(_OPTIONAL_USAGE_KEYS, optional, strict=True)
        )
        if message_id is None or malformed or any(value is None for value in values):
            return None
        first, second, third = (value or 0 for value in values)
        return cls(
            message_id,
            first,
            second,
            third,
            model=opt_str(counts.get("model")),
            output_tokens=optional[0],
            cache_write_5m_tokens=optional[1],
            cache_write_1h_tokens=optional[2],
            request_ref=opt_str(counts.get("request_ref")),
        )


@dataclass(frozen=True)
class ToolUse:
    """One tool call or its result: the tool's name, the call id and the file it targets; never the call's input or
    output text."""

    name: str | None = None
    use_id: str | None = None
    path: str | None = None
    # The MCP server a call goes to; None for a tool that is not an MCP server's.
    server: str | None = None
    category: ToolCategory | None = None
    # A size in characters: a hand-back's message, or a result's content.
    chars: int | None = None
    # A hash of a shell command, so repeats of one command are found without keeping its text.
    fingerprint: str | None = None
    # Whether a result reports an error; None on a call.
    error: bool | None = None
    # Whether a result is only the acknowledgement that a background agent was launched.
    launch_ack: bool = False


@dataclass(frozen=True)
class InstructionLoad:
    """One instruction file the agent loaded: its path and its kind as the agent names it, or "nested"."""

    path: str
    memory_type: str | None = None


@dataclass(frozen=True)
class SkillRun:
    """One skill or command the agent ran: its name as the session shows it and whether it ran in a subagent of
    its own (`context: fork`); never its output."""

    name: str
    forked: bool


@dataclass(frozen=True)
class SubagentMeta:
    """What a subagent's meta file and first row say about its launch: the task's short description, the subagent
    that launched it (None for the main agent), the id of the launching call, its nesting depth, the size of its brief
    in characters (None when its first row holds no text), whether the person stopped it and whether it ran in the
    background."""

    description: str | None
    parent_id: str | None
    tool_use_id: str | None
    depth: int | None
    brief_chars: int | None
    stopped: bool
    background: bool


@dataclass(frozen=True)
class ReplyText:
    """The text an assistant row carries: its size in characters, never the text, and whether Claude Code wrote the
    reply itself for an API error or an interrupt."""

    chars: int
    synthetic: bool


@dataclass(frozen=True)
class HarnessEntry:
    """One piece of what the harness put into a session's context: its kind, a label, how many items it holds
    (None when it is not a list) and its size in characters."""

    kind: HarnessKind
    label: str
    count: int | None
    chars: int
    # The hook event a note came from; None for a piece of the session's own context.
    event: str | None = None
    # A list row's added items with their sizes in characters, and the names it removed; names only, no text.
    added: tuple[tuple[str, int], ...] = ()
    removed: tuple[str, ...] = ()
    # Names a row re-added whose text was sent before.
    readded: tuple[str, ...] = ()
    # The names a skill listing row names; None when the row carries none.
    names: tuple[str, ...] | None = None


@dataclass(frozen=True)
class PromptEntry:
    """One prompt a person typed: the id of its transcript row, its size in characters and whether it was
    queued while the agent worked."""

    id: str
    chars: int
    queued: bool


@dataclass(frozen=True)
class MessageSize:
    """The size in characters of one message of an API request, by part; never its text."""

    user_text: int = 0
    notes: int = 0
    assistant_text: int = 0
    thinking: int = 0
    tool_calls: int = 0
    tool_results: int = 0

    def __add__(self, other: MessageSize) -> MessageSize:
        return MessageSize(
            self.user_text + other.user_text,
            self.notes + other.notes,
            self.assistant_text + other.assistant_text,
            self.thinking + other.thinking,
            self.tool_calls + other.tool_calls,
            self.tool_results + other.tool_results,
        )


@dataclass(frozen=True)
class RequestSize:
    """One API request: its id, the characters of its system blocks and its tool definitions, the tool count, the
    summed parts of its messages, the message count and how many of the tail hashes named no known message."""

    request_id: str
    system_chars: int
    tools_chars: int
    tool_count: int
    user_text: int
    notes: int
    assistant_text: int
    thinking: int
    tool_calls: int
    tool_results: int
    messages: int
    unresolved: int


@dataclass
class RequestChain:
    """What a read of one transcript file knows to size its API requests: each recorded shape as its system
    characters, tool characters and tool count, each known message's size under its hash, the running sums of the
    previous request's messages (`prefix[i]` is the size of its first `i` messages) and
    the assistant message being merged from its rows. Sizes only, no message text."""

    shapes: dict[str, tuple[int, int, int]] = field(default_factory=dict)
    pool: dict[str, MessageSize] = field(default_factory=dict)
    prefix: list[MessageSize] = field(default_factory=lambda: [MessageSize()])
    merge_id: str | None = None
    merge_with_caller: _Hash | None = None
    merge_without_caller: _Hash | None = None
    merge_size: MessageSize = field(default_factory=MessageSize)
    merge_blocks: int = 0


@dataclass(frozen=True)
class FileCursor:
    """Where a transcript read stopped in one file: the byte offset, the last assistant message id and, for a
    subagent file, whether its run record is settled (emitted, or refused for its meta file)."""

    subagent_id: str | None
    offset: int = 0
    last_message_id: str | None = None
    run_settled: bool = False
    requests: RequestChain = field(default_factory=RequestChain, compare=False)


@dataclass(frozen=True)
class TranscriptCursor:
    """Where a transcript read stopped in every file of a session; empty before the first read."""

    files: tuple[FileCursor, ...] = ()

    def of(self, subagent_id: str | None) -> FileCursor | None:
        """The cursor of the main file (`None`) or one subagent's file, or None when it was never read."""
        return next((cursor for cursor in self.files if cursor.subagent_id == subagent_id), None)

    def with_file(self, cursor: FileCursor) -> TranscriptCursor:
        """These cursors with `cursor` replacing the one for the same file."""
        rest = tuple(item for item in self.files if item.subagent_id != cursor.subagent_id)
        return TranscriptCursor(files=(*rest, cursor))


@dataclass(frozen=True)
class EventRecord:
    """One event of an agent session; ids, names and paths only."""

    agent: str
    event: EventKind
    session_id: str
    time: str
    subagent_id: str | None = None
    cwd: str | None = None
    # The session-start source or the compaction trigger.
    source: str | None = None
    tool: ToolUse | None = None
    # The reason, set only when `event == "refusal"`.
    refusal: str | None = None
    # The reply of an `assistant_usage` record.
    usage: TokenUsage | None = None
    # The agent type of a `subagent_run` record.
    subagent_type: str | None = None
    # The file of an `instruction_load` record, the piece of the harness's context a `harness` record names, the
    # prompt a transcript's `prompt_submit` record sizes, the skill a `skill_run` record names, or the launch a
    # `subagent_run` record describes, the size of the text an `assistant_text` record carries, or the sizes of
    # an `api_request` record's request.
    item: InstructionLoad | HarnessEntry | PromptEntry | SkillRun | SubagentMeta | ReplyText | RequestSize | None = None

    @property
    def load(self) -> InstructionLoad | None:
        """The file an `instruction_load` record names."""
        return self.item if isinstance(self.item, InstructionLoad) else None

    @property
    def harness(self) -> HarnessEntry | None:
        """The piece of the harness's context a `harness` record names."""
        return self.item if isinstance(self.item, HarnessEntry) else None

    @property
    def prompt(self) -> PromptEntry | None:
        """The typed prompt a transcript's `prompt_submit` record names."""
        return self.item if isinstance(self.item, PromptEntry) else None

    @property
    def skill(self) -> SkillRun | None:
        """The skill or command a `skill_run` record names."""
        return self.item if isinstance(self.item, SkillRun) else None

    @property
    def launch(self) -> SubagentMeta | None:
        """The launch a `subagent_run` record describes."""
        return self.item if isinstance(self.item, SubagentMeta) else None

    @property
    def reply(self) -> ReplyText | None:
        """The text size an `assistant_text` record carries."""
        return self.item if isinstance(self.item, ReplyText) else None

    @property
    def request(self) -> RequestSize | None:
        """The sizes of the request an `api_request` record describes."""
        return self.item if isinstance(self.item, RequestSize) else None

    def to_json(self) -> JsonObject:
        """The record as a JSON object."""
        paths: list[JsonValue] = [path for path in (self._path(),) if path]
        return {
            "agent": self.agent,
            "event": self.event,
            "session_id": self.session_id,
            "subagent_id": self.subagent_id,
            "cwd": self.cwd,
            "time": self.time,
            "source": self.source,
            "tool_name": self.tool.name if self.tool else None,
            "tool_use_id": self.tool.use_id if self.tool else None,
            "paths": paths,
            "refusal": self.refusal,
            "usage": None if self.usage is None else self.usage.counts_json(),
            "message_id": None if self.usage is None else self.usage.message_id,
            "subagent_type": self.subagent_type,
            "memory_type": self.load.memory_type if self.load else None,
        }

    def _path(self) -> str | None:
        """The file path the record names: the tool's target or the loaded instruction file."""
        if self.tool is not None:
            return self.tool.path
        return None if self.load is None else self.load.path

    @classmethod
    def from_json(cls, obj: JsonObject) -> EventRecord:
        """The record a stored object holds; raises `ValueError` on a missing or unknown required field."""
        event = obj.get("event")
        if not isinstance(event, str) or not is_event_kind(event):
            raise ValueError(f"unknown event kind: {event!r}")
        agent, session_id, time = as_str(obj.get("agent")), as_str(obj.get("session_id")), as_str(obj.get("time"))
        if not (agent and session_id and time):
            raise ValueError("record needs agent, session_id and time")
        paths = str_list(obj.get("paths"))
        path = paths[0] if paths else None
        tool = ToolUse(opt_str(obj.get("tool_name")), opt_str(obj.get("tool_use_id")), path)
        is_load = event == "instruction_load"
        return cls(
            agent=agent,
            event=event,
            session_id=session_id,
            time=time,
            subagent_id=opt_str(obj.get("subagent_id")),
            cwd=opt_str(obj.get("cwd")),
            source=opt_str(obj.get("source")),
            tool=None if is_load or tool == ToolUse() else tool,
            refusal=opt_str(obj.get("refusal")),
            usage=TokenUsage.from_json(opt_str(obj.get("message_id")), as_object(obj.get("usage"))),
            subagent_type=opt_str(obj.get("subagent_type")),
            item=InstructionLoad(path, opt_str(obj.get("memory_type"))) if is_load and path else None,
        )


@dataclass(frozen=True)
class HarnessAttachment:
    """Where one harness attachment keeps its item count and its text: the key, and whether it holds a whole
    number or text rather than a list of strings."""

    kind: HarnessKind
    label: str
    count_key: str
    count_is_number: bool
    chars_key: str
    chars_is_text: bool
    removed_key: str | None = None


@dataclass(frozen=True)
class CallDetail:
    """What one tool call said when asked for: its tool, the shell command (None for a call that is not a shell
    one), its input as indented JSON, an excerpt of its result (None without one) and whether any of the three
    was cut."""

    tool: str
    text: str | None
    input: str
    result: str | None
    truncated: bool
