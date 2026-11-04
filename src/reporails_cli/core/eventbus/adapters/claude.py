"""The Claude Code adapter: hook payloads to event records.

Vendor source for every field read: https://code.claude.com/docs/en/hooks

- `hook_event_name`, `session_id`, `cwd`: common input fields of every event, listed at each of
  `#sessionstart-input`, `#userpromptsubmit-input`, `#pretooluse-input`, `#posttooluse-input`,
  `#stop-input`, `#subagentstop-input`, `#precompact-input`, `#postcompact-input`, `#sessionend-input`.
- `source`: the SessionStart input (`#sessionstart-input`).
- `trigger`: the PreCompact and PostCompact input (`#precompact-input`, `#postcompact-input`).
- `tool_name`, `tool_use_id`: the PreToolUse and PostToolUse input (`#pretooluse-input`, `#posttooluse-input`).
- `agent_id`: present when the event fires inside a subagent (`#pretooluse-input`, `#subagentstop-input`).
- `tool_input.file_path`: Read, Edit and Write carry it, always absolute (`#pretooluse-input`).
  NotebookEdit has no documented path field, so it gets none.

Never read: `prompt`, the rest of `tool_input`, `tool_response`, `last_assistant_message`, `compact_summary`.
"""

from __future__ import annotations

from reporails_cli.core.eventbus.port import PayloadRefused, utc_now
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object, opt_str
from reporails_cli.core.platform.dto.events import EventKind, EventRecord, ToolUse
from reporails_cli.core.platform.policy.host_hooks import HEAL_TOOLS

_KINDS: dict[str, EventKind] = {
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
    "UserPromptSubmit": "prompt_submit",
    "PreToolUse": "pre_tool",
    "PostToolUse": "post_tool",
    "Stop": "stop",
    "SubagentStop": "subagent_stop",
    "PreCompact": "pre_compact",
    "PostCompact": "post_compact",
}


class ClaudeAdapter:  # pylint: disable=too-few-public-methods  # an adapter is one `resolve`
    """Resolves a Claude Code hook payload."""

    agent = "claude"

    def resolve(self, payload: JsonObject) -> list[EventRecord]:
        """The one record a hook payload carries; refuses an unknown event or a missing session id."""
        name = payload.get("hook_event_name")
        kind = _KINDS.get(name) if isinstance(name, str) else None
        if kind is None:
            raise PayloadRefused(f"unknown event: {name!r}")
        session_id = opt_str(payload.get("session_id")) or None
        if session_id is None:
            raise PayloadRefused("payload has no session_id")
        tool_name = opt_str(payload.get("tool_name")) or None
        path = (
            (opt_str(as_object(payload.get("tool_input")).get("file_path")) or None)
            if tool_name in HEAL_TOOLS
            else None
        )
        tool_use = ToolUse(tool_name, opt_str(payload.get("tool_use_id")) or None, path)
        tool = None if tool_use == ToolUse() else tool_use
        return [
            EventRecord(
                agent=self.agent,
                event=kind,
                session_id=session_id,
                time=utc_now(),
                subagent_id=opt_str(payload.get("agent_id")) or None,
                cwd=opt_str(payload.get("cwd")) or None,
                source=opt_str(payload.get("source")) or opt_str(payload.get("trigger")) or None,
                tool=tool,
            )
        ]
