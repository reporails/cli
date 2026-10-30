"""The event record: one hook event of an agent session, reduced to ids, names and paths.

A record never holds prompt text, tool input text or tool output.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, TypeGuard, get_args

from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_str, str_list

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
]


def is_event_kind(value: str) -> TypeGuard[EventKind]:
    """Whether `value` is one of the event kinds."""
    return value in get_args(EventKind)


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
            subagent_id=_opt(obj.get("subagent_id")),
            cwd=_opt(obj.get("cwd")),
            source=_opt(obj.get("source")),
            tool_name=_opt(obj.get("tool_name")),
            tool_use_id=_opt(obj.get("tool_use_id")),
            paths=tuple(str_list(obj.get("paths"))),
            refusal=_opt(obj.get("refusal")),
        )


def _opt(value: JsonValue | None) -> str | None:
    return value if isinstance(value, str) else None
