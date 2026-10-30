"""The Claude Code transcript adapter: session transcript rows to event records.

Documented by the vendor:

- Where a transcript lives, `~/.claude/projects/<project>/<session-id>.jsonl`:
  https://code.claude.com/docs/en/sessions#where-transcripts-are-stored
- A subagent's transcript, `<session-id>/subagents/agent-<agentId>.jsonl`:
  https://code.claude.com/docs/en/sub-agents#resume-subagents
- The token counts `input_tokens`, `cache_creation_input_tokens` and `cache_read_input_tokens`:
  https://code.claude.com/docs/en/prompt-caching#check-cache-performance
- The instruction-file load events, `InstructionsLoaded` with `file_path`, `memory_type` and `load_reason`:
  https://code.claude.com/docs/en/hooks

Undocumented: the row layout. The sessions page calls the entry format "internal to Claude Code" and says
it changes between versions. These are shapes recorded on Claude Code 2.1.292, 2.1.301 and 2.1.308, and
the adapter refuses any other shape of a row type it reads:

- an assistant row: `type: "assistant"`, `timestamp`, `message.id` and `message.usage` holding the three
  counts above; one row is written per content block, so the rows of one response repeat `message.id`.
- a turn end: `type: "system"` with `subtype: "turn_duration"` and `timestamp`.
- an instruction load: `type: "attachment"` with `attachment.type: "instructions"` and
  `attachment.files[].path` / `.type`, or `attachment.type: "nested_memory"` and `attachment.path`. The
  `InstructionsLoaded` hook does not fire for auto memory or for a subagent's session-start loads (probe on
  Claude Code 2.1.308, 2026-10-30), which is why the transcript is the source.
- a subagent file: its `sessionId`-carrying first row's `timestamp`, and the `agentType` of
  `agent-<id>.meta.json`.

Never read: message content, tool input and output, `description`, `content`, `displayPath`.
"""

from __future__ import annotations

from dataclasses import replace

from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object, opt_str
from reporails_cli.core.platform.dto.events import EventKind, EventRecord, InstructionLoad, TokenUsage

NESTED_MARKER = "nested"


def _text(row: JsonObject, key: str, what: str) -> str:
    value = opt_str(row.get(key))
    if not value:
        raise PayloadRefused(f"{what} has no {key}")
    return value


class ClaudeTranscriptAdapter:
    """Resolves the rows of a Claude Code session transcript."""

    agent = "claude"

    def resolve_row(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        """The records one row carries; refuses a known row type whose fields are not the pinned shape."""
        kind = row.get("type")
        if kind == "assistant":
            return [self._usage(row, subagent_id)]
        if kind == "system" and row.get("subtype") == "turn_duration":
            return [self._record(row, "turn_end", subagent_id)]
        if kind == "attachment":
            return self._instructions(row, subagent_id)
        return []

    def resolve_subagent(self, subagent_id: str, meta: JsonObject, first_row: JsonObject) -> EventRecord:
        """The `subagent_run` record of a subagent file; refuses a meta file without `agentType`."""
        agent_type = opt_str(meta.get("agentType"))
        if not agent_type:
            raise PayloadRefused(f"subagent {subagent_id} meta has no agentType")
        return replace(self._record(first_row, "subagent_run", subagent_id), subagent_type=agent_type)

    def _record(self, row: JsonObject, event: EventKind, subagent_id: str | None) -> EventRecord:
        what = f"{row.get('type')} row"
        return EventRecord(
            agent=self.agent,
            event=event,
            session_id=_text(row, "sessionId", what),
            time=_text(row, "timestamp", what),
            subagent_id=subagent_id,
        )

    def _usage(self, row: JsonObject, subagent_id: str | None) -> EventRecord:
        message = as_object(row.get("message"))
        message_id = _text(message, "id", "assistant message")
        usage = TokenUsage.from_json(message_id, as_object(message.get("usage")))
        if usage is None:
            raise PayloadRefused("assistant usage counts are not whole numbers")
        return replace(self._record(row, "assistant_usage", subagent_id), usage=usage)

    def _instructions(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        attachment = as_object(row.get("attachment"))
        kind = attachment.get("type")
        if kind == "nested_memory":
            return [self._load(row, _text(attachment, "path", "nested_memory attachment"), NESTED_MARKER, subagent_id)]
        if kind != "instructions":
            return []
        loads: list[EventRecord] = []
        for item in as_list(attachment.get("files")):
            entry = as_object(item)
            path = _text(entry, "path", "instructions file")
            loads.append(self._load(row, path, opt_str(entry.get("type")), subagent_id))
        return loads

    def _load(self, row: JsonObject, path: str, memory_type: str | None, subagent_id: str | None) -> EventRecord:
        return replace(self._record(row, "instruction_load", subagent_id), load=InstructionLoad(path, memory_type))
