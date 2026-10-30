"""The event record: one hook event of an agent session, reduced to ids, names and paths.

A record never holds prompt text, tool input text or tool output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeGuard, get_args

from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    JsonValue,
    as_object,
    as_str,
    opt_int,
    opt_str,
    str_list,
)

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
    "instruction_load",
]


def is_event_kind(value: str) -> TypeGuard[EventKind]:
    """Whether `value` is one of the event kinds."""
    return value in get_args(EventKind)


_USAGE_KEYS = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


@dataclass(frozen=True)
class TokenUsage:
    """One assistant reply: the id of the API response and its token counts (fresh input, cache writes, cache reads)."""

    message_id: str
    input_tokens: int
    cache_creation_input_tokens: int
    cache_read_input_tokens: int

    def counts_json(self) -> JsonObject:
        """The three counts as a JSON object."""
        return {
            "input_tokens": self.input_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
        }

    @classmethod
    def from_json(cls, message_id: str | None, counts: JsonObject) -> TokenUsage | None:
        """The usage of reply `message_id` with the counts a stored object holds, or None when the id is missing
        or any of the three is not a whole number."""
        values = [opt_int(counts.get(key)) for key in _USAGE_KEYS]
        if message_id is None or any(value is None for value in values):
            return None
        return cls(message_id, *(value or 0 for value in values))


@dataclass(frozen=True)
class ToolUse:
    """One tool call of a pre-tool or post-tool event: the tool's name, the call id and the file it targets."""

    name: str | None = None
    use_id: str | None = None
    path: str | None = None


@dataclass(frozen=True)
class InstructionLoad:
    """One instruction file the agent loaded: its path and its kind as the agent names it, or "nested"."""

    path: str
    memory_type: str | None = None


@dataclass(frozen=True)
class FileCursor:
    """Where a transcript read stopped in one file: the byte offset and the last assistant message id."""

    subagent_id: str | None
    offset: int = 0
    last_message_id: str | None = None


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
    # The file of an `instruction_load` record.
    load: InstructionLoad | None = None

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
            load=InstructionLoad(path, opt_str(obj.get("memory_type"))) if is_load and path else None,
        )
