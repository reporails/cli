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
    """The token counts of one assistant turn: fresh input, cache writes and cache reads."""

    input_tokens: int
    cache_creation_input_tokens: int
    cache_read_input_tokens: int

    def to_json(self) -> JsonObject:
        """The counts as a JSON object."""
        return {
            "input_tokens": self.input_tokens,
            "cache_creation_input_tokens": self.cache_creation_input_tokens,
            "cache_read_input_tokens": self.cache_read_input_tokens,
        }

    @classmethod
    def from_json(cls, obj: JsonObject) -> TokenUsage | None:
        """The counts a stored object holds, or None when any of the three is not a whole number."""
        counts = [opt_int(obj.get(key)) for key in _USAGE_KEYS]
        if any(count is None for count in counts):
            return None
        return cls(*(count or 0 for count in counts))


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
    tool_name: str | None = None
    tool_use_id: str | None = None
    paths: tuple[str, ...] = ()
    # The reason, set only when `event == "refusal"`.
    refusal: str | None = None
    # The token counts of an `assistant_usage` record, and the id of the API response that carried them.
    usage: TokenUsage | None = None
    message_id: str | None = None
    # The agent type of a `subagent_run` record.
    subagent_type: str | None = None
    # The kind of an `instruction_load` record's file as the agent names it, or "nested".
    memory_type: str | None = None

    def to_json(self) -> JsonObject:
        """The record as a JSON object."""
        paths: list[JsonValue] = list(self.paths)
        return {
            "agent": self.agent,
            "event": self.event,
            "session_id": self.session_id,
            "subagent_id": self.subagent_id,
            "cwd": self.cwd,
            "time": self.time,
            "source": self.source,
            "tool_name": self.tool_name,
            "tool_use_id": self.tool_use_id,
            "paths": paths,
            "refusal": self.refusal,
            "usage": None if self.usage is None else self.usage.to_json(),
            "message_id": self.message_id,
            "subagent_type": self.subagent_type,
            "memory_type": self.memory_type,
        }

    @classmethod
    def from_json(cls, obj: JsonObject) -> EventRecord:
        """The record a stored object holds; raises `ValueError` on a missing or unknown required field."""
        event = obj.get("event")
        if not isinstance(event, str) or not is_event_kind(event):
            raise ValueError(f"unknown event kind: {event!r}")
        agent, session_id, time = as_str(obj.get("agent")), as_str(obj.get("session_id")), as_str(obj.get("time"))
        if not (agent and session_id and time):
            raise ValueError("record needs agent, session_id and time")
        return cls(
            agent=agent,
            event=event,
            session_id=session_id,
            time=time,
            subagent_id=opt_str(obj.get("subagent_id")),
            cwd=opt_str(obj.get("cwd")),
            source=opt_str(obj.get("source")),
            tool_name=opt_str(obj.get("tool_name")),
            tool_use_id=opt_str(obj.get("tool_use_id")),
            paths=tuple(str_list(obj.get("paths"))),
            refusal=opt_str(obj.get("refusal")),
            usage=TokenUsage.from_json(as_object(obj.get("usage"))),
            message_id=opt_str(obj.get("message_id")),
            subagent_type=opt_str(obj.get("subagent_type")),
            memory_type=opt_str(obj.get("memory_type")),
        )
