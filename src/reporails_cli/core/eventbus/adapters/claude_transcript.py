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
- a harness record: `type: "attachment"` with one of these `attachment.type` values, each sized by character
  count and then dropped: `prompt_snapshot` (`systemPrompt`, a list of strings), `skill_listing` (`skillCount`,
  a whole number, and `content`, a string), `agent_listing_delta` (`addedTypes` and `addedLines`, lists of
  strings), `mcp_instructions_delta` (`addedNames` and `addedBlocks`, lists of strings), `deferred_tools_delta`
  (`addedNames` and `addedLines`, lists of strings, or in a subagent file `content`, a string),
  `session_context` (`context`, an object of strings) and
  `hook_additional_context` (`hookEvent`, `hookName` and `content`, a list of strings), read only when
  `hookEvent` is `SessionStart`.
- a subagent brief: the first row of a subagent file, `type: "user"` with `message.content` a string or a
  list of blocks whose `type: "text"` blocks hold `text`.
- every row the adapter reads (assistant, system, attachment) carries `sessionId` and `timestamp`; a row
  without either is refused.
- a subagent file: its first row's `timestamp`, and the `agentType` of `agent-<id>.meta.json`.

Never read, except for the sizes and the brief above: message content, tool input and output, `description`,
`content`, `displayPath`.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    JsonValue,
    as_list,
    as_object,
    opt_int,
    opt_str,
)
from reporails_cli.core.platform.dto.events import (
    EventKind,
    EventRecord,
    HarnessEntry,
    HarnessKind,
    InstructionLoad,
    TokenUsage,
)

NESTED_MARKER = "nested"
BRIEF_BLOCK_SEPARATOR = "\n\n"


@dataclass(frozen=True)
class _Harness:
    """Where one harness attachment keeps its item count and its text: the key, and whether it holds a whole
    number or text rather than a list of strings."""

    kind: HarnessKind
    label: str
    count_key: str
    count_is_number: bool
    chars_key: str
    chars_is_text: bool


_HARNESS: dict[str, _Harness] = {
    "prompt_snapshot": _Harness("system_prompt", "system prompt", "systemPrompt", False, "systemPrompt", False),
    "skill_listing": _Harness("skill_list", "skills", "skillCount", True, "content", True),
    "agent_listing_delta": _Harness("agent_list", "agents", "addedTypes", False, "addedLines", False),
    "mcp_instructions_delta": _Harness(
        "mcp_instructions", "MCP server instructions", "addedNames", False, "addedBlocks", False
    ),
}


def _strings(value: JsonValue, field: str, what: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PayloadRefused(f"{what} {field} is not a list of strings")
    return [item for item in value if isinstance(item, str)]


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
            return self._attachment(row, subagent_id)
        return []

    def resolve_brief(self, first_row: JsonObject) -> str:
        """The brief a subagent was given, the text of its first row; refuses a first row that is not a user
        row holding text."""
        if first_row.get("type") != "user":
            raise PayloadRefused("subagent file does not open with a user row")
        content = as_object(first_row.get("message")).get("content")
        if isinstance(content, str):
            return content
        blocks = [as_object(block) for block in as_list(content)]
        texts = [block.get("text") for block in blocks if block.get("type") == "text"]
        if not texts or not all(isinstance(text, str) for text in texts):
            raise PayloadRefused("subagent first row holds no text content")
        return BRIEF_BLOCK_SEPARATOR.join(text for text in texts if isinstance(text, str))

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

    def _attachment(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        attachment = as_object(row.get("attachment"))
        kind = attachment.get("type")
        if kind == "nested_memory":
            return [self._load(row, _text(attachment, "path", "nested_memory attachment"), NESTED_MARKER, subagent_id)]
        if kind == "instructions":
            return self._instructions(row, attachment, subagent_id)
        if kind == "hook_additional_context":
            return self._hook_note(row, attachment, subagent_id)
        entry = self._harness_entry(attachment, kind)
        if entry is None:
            return []
        return [self._harness(row, entry, subagent_id)]

    def _instructions(self, row: JsonObject, attachment: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        loads: list[EventRecord] = []
        for item in as_list(attachment.get("files")):
            entry = as_object(item)
            path = _text(entry, "path", "instructions file")
            loads.append(self._load(row, path, opt_str(entry.get("type")), subagent_id))
        return loads

    def _harness_entry(self, attachment: JsonObject, kind: object) -> HarnessEntry | None:
        if kind == "session_context":
            return self._session_context(attachment)
        if kind == "deferred_tools_delta":
            return self._deferred_tools(attachment)
        if isinstance(kind, str) and kind in _HARNESS:
            return self._listing(attachment, kind)
        return None

    def _load(self, row: JsonObject, path: str, memory_type: str | None, subagent_id: str | None) -> EventRecord:
        return replace(self._record(row, "instruction_load", subagent_id), item=InstructionLoad(path, memory_type))

    def _harness(self, row: JsonObject, entry: HarnessEntry, subagent_id: str | None) -> EventRecord:
        return replace(self._record(row, "harness", subagent_id), item=entry)

    def _listing(self, attachment: JsonObject, kind: str) -> HarnessEntry:
        spec = _HARNESS[kind]
        what = f"{kind} attachment"
        if spec.count_is_number:
            count = opt_int(attachment.get(spec.count_key))
            if count is None:
                raise PayloadRefused(f"{what} {spec.count_key} is not a whole number")
        else:
            count = len(_strings(attachment.get(spec.count_key), spec.count_key, what))
        text = attachment.get(spec.chars_key)
        if spec.chars_is_text:
            if not isinstance(text, str):
                raise PayloadRefused(f"{what} {spec.chars_key} is not a string")
            chars = len(text)
        else:
            chars = sum(len(item) for item in _strings(text, spec.chars_key, what))
        return HarnessEntry(spec.kind, spec.label, count, chars)

    def _deferred_tools(self, attachment: JsonObject) -> HarnessEntry:
        what = "deferred_tools_delta attachment"
        if "content" in attachment:
            content = attachment.get("content")
            if not isinstance(content, str):
                raise PayloadRefused(f"{what} content is not a string")
            return HarnessEntry("deferred_tools", "deferred tools", None, len(content))
        names = _strings(attachment.get("addedNames"), "addedNames", what)
        lines = _strings(attachment.get("addedLines"), "addedLines", what)
        return HarnessEntry("deferred_tools", "deferred tools", len(names), sum(len(item) for item in lines))

    def _session_context(self, attachment: JsonObject) -> HarnessEntry:
        context = attachment.get("context")
        if not isinstance(context, dict):
            raise PayloadRefused("session_context attachment context is not an object")
        chars = sum(len(value) for value in context.values() if isinstance(value, str))
        return HarnessEntry("session_context", "session context", None, chars)

    def _hook_note(self, row: JsonObject, attachment: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        if attachment.get("hookEvent") != "SessionStart":
            return []
        what = "hook_additional_context attachment"
        label = _text(attachment, "hookName", what)
        chars = sum(len(item) for item in _strings(attachment.get("content"), "content", what))
        return [self._harness(row, HarnessEntry("hook_note", label, None, chars), subagent_id)]
