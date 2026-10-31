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
  `session_context` (`context`, an object of strings). The three delta rows may also carry `removedTypes` or
  `removedNames`, lists of strings, counted off their item count; each added item's size is kept under its
  name (never its text) and each removed name is kept, so a later removal takes its size off too.
- a hook note: `type: "attachment"` with `hookEvent` and `hookName` strings and one of `attachment.type`
  `hook_additional_context` (`content`, a list of strings), `hook_success` (`content`, a string, read only when
  it is not empty and its `hookEvent` is one of `UserPromptSubmit`, `UserPromptExpansion`, `SessionStart` or
  `PostModelSwitch`: https://code.claude.com/docs/en/hooks says Claude Code writes a hook's stdout to the
  debug log for every other event and adds it to the context only for those four) or `hook_blocking_error`
  (`blockingError`, an object whose `blockingError` is a string; a Stop block), each sized by character count
  and then dropped.
- a typed prompt: a `user` row with `uuid`, `promptSource: "typed"`, `origin.kind: "human"` and
  `message.content` a string or a list of blocks whose `type: "text"` blocks hold `text`; or an attachment row
  with `uuid` and `attachment.type: "queued_command"`, `commandMode: "prompt"`, `origin.kind: "human"` and
  `prompt`, a string or a list of blocks as a user row's content. Every other user row yields nothing. The
  prompt's text is read for its size and by `resolve_prompt` for the route that shows it, never stored.
- a compaction: `type: "system"` with `subtype: "compact_boundary"` and `compactMetadata.trigger`.
- a subagent brief: the first row of a subagent file, `type: "user"` with `message.content` a string or a
  list of blocks whose `type: "text"` blocks hold `text`.
- every row the adapter reads (assistant, system, attachment) carries `sessionId` and `timestamp`; a row
  without either is refused.
- a subagent file: its first row's `timestamp`, and the `agentType` of `agent-<id>.meta.json`.

Never read, except for the sizes, the brief and the prompts above: message content, tool input and output,
`description`, `content`, `displayPath`.
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
    strict_str_list,
)
from reporails_cli.core.platform.dto.events import (
    EventKind,
    EventRecord,
    HarnessEntry,
    HarnessKind,
    InstructionLoad,
    PromptEntry,
    TokenUsage,
)

NESTED_MARKER = "nested"
BRIEF_BLOCK_SEPARATOR = "\n\n"
HOOK_NOTE_ATTACHMENTS = ("hook_additional_context", "hook_success", "hook_blocking_error")
# The hook events whose plain-text stdout Claude Code adds to the context.
HOOK_STDOUT_CONTEXT_EVENTS = ("UserPromptSubmit", "UserPromptExpansion", "SessionStart", "PostModelSwitch")


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
    removed_key: str | None = None


def _sized_by_name(names: list[str], items: list[str], what: str) -> tuple[tuple[str, int], ...]:
    """Each added item's size under its name; the names and the items must pair up one to one."""
    if len(names) != len(items):
        raise PayloadRefused(f"{what} lists {len(names)} names for {len(items)} items")
    return tuple((name, len(item)) for name, item in zip(names, items, strict=True))


_HARNESS: dict[str, _Harness] = {
    "prompt_snapshot": _Harness("system_prompt", "system prompt", "systemPrompt", False, "systemPrompt", False),
    "skill_listing": _Harness("skill_list", "skills", "skillCount", True, "content", True),
    "agent_listing_delta": _Harness("agent_list", "agents", "addedTypes", False, "addedLines", False, "removedTypes"),
    "mcp_instructions_delta": _Harness(
        "mcp_instructions", "MCP server instructions", "addedNames", False, "addedBlocks", False, "removedNames"
    ),
}


def _strings(value: JsonValue, field: str, what: str) -> list[str]:
    items = strict_str_list(value)
    if items is None:
        raise PayloadRefused(f"{what} {field} is not a list of strings")
    return items


def _text(row: JsonObject, key: str, what: str) -> str:
    value = opt_str(row.get(key))
    if not value:
        raise PayloadRefused(f"{what} has no {key}")
    return value


def _blocks_text(content: JsonValue, what: str) -> list[str] | None:
    """The texts of a message's content: the string itself, or each `text` block's; None when it is neither."""
    if isinstance(content, str):
        return [content]
    if not isinstance(content, list):
        return None
    texts = [as_object(block).get("text") for block in content if as_object(block).get("type") == "text"]
    if not all(isinstance(text, str) for text in texts):
        raise PayloadRefused(f"{what} has a text block with no text")
    return [text for text in texts if isinstance(text, str)]


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
        if kind == "system" and row.get("subtype") == "compact_boundary":
            return [self._compaction(row, subagent_id)]
        if kind == "attachment":
            return self._attachment(row, subagent_id)
        if kind == "user":
            return self._prompt(row, subagent_id)
        return []

    def resolve_brief(self, first_row: JsonObject) -> str:
        """The brief a subagent was given, the text of its first row; refuses a first row that is not a user
        row holding text."""
        if first_row.get("type") != "user":
            raise PayloadRefused("subagent file does not open with a user row")
        content = as_object(first_row.get("message")).get("content")
        if isinstance(content, str):
            return content
        texts = _blocks_text(content, "subagent first row")
        if not texts:
            raise PayloadRefused("subagent first row holds no text content")
        return BRIEF_BLOCK_SEPARATOR.join(texts)

    def resolve_prompt(self, row: JsonObject) -> str:
        """The text of a typed prompt row, for the route that shows it; refuses a row that is not one."""
        text = self._typed_text(row)
        if text is None:
            raise PayloadRefused("row is not a typed prompt")
        return text

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

    def _compaction(self, row: JsonObject, subagent_id: str | None) -> EventRecord:
        trigger = opt_str(as_object(row.get("compactMetadata")).get("trigger"))
        return replace(self._record(row, "post_compact", subagent_id), source=trigger)

    def _typed_text(self, row: JsonObject) -> str | None:
        """The text of a row a person typed, None for any other row."""
        if row.get("type") == "user":
            if row.get("promptSource") != "typed" or as_object(row.get("origin")).get("kind") != "human":
                return None
            texts = _blocks_text(as_object(row.get("message")).get("content"), "user row")
            if texts is None:
                raise PayloadRefused("user row message content is neither text nor a list of blocks")
            return "".join(texts)
        attachment = as_object(row.get("attachment"))
        if attachment.get("type") != "queued_command" or attachment.get("commandMode") != "prompt":
            return None
        if as_object(attachment.get("origin")).get("kind") != "human":
            return None
        texts = _blocks_text(attachment.get("prompt"), "queued_command attachment prompt")
        if texts is None:
            raise PayloadRefused("queued_command attachment prompt is neither text nor a list of blocks")
        return "".join(texts)

    def _prompt(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        text = self._typed_text(row)
        if text is None:
            return []
        entry = PromptEntry(_text(row, "uuid", f"{row.get('type')} row"), len(text), row.get("type") == "attachment")
        return [replace(self._record(row, "prompt_submit", subagent_id), item=entry)]

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
        if kind in HOOK_NOTE_ATTACHMENTS:
            return self._hook_note(row, attachment, subagent_id)
        if kind == "queued_command":
            return self._prompt(row, subagent_id)
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
            names: list[str] = []
        else:
            names = _strings(attachment.get(spec.count_key), spec.count_key, what)
            count = len(names)
        text = attachment.get(spec.chars_key)
        added: tuple[tuple[str, int], ...] = ()
        if spec.chars_is_text:
            if not isinstance(text, str):
                raise PayloadRefused(f"{what} {spec.chars_key} is not a string")
            chars = len(text)
        else:
            items = _strings(text, spec.chars_key, what)
            chars = sum(len(item) for item in items)
            if spec.removed_key is not None:
                added = _sized_by_name(names, items, what)
        removed = self._removed_names(attachment, spec.removed_key, what)
        return HarnessEntry(spec.kind, spec.label, count - len(removed), chars, added=added, removed=removed)

    def _removed_names(self, attachment: JsonObject, key: str | None, what: str) -> tuple[str, ...]:
        """The names a delta row removed; none when the row does not carry the list."""
        if key is None or key not in attachment:
            return ()
        return tuple(_strings(attachment.get(key), key, what))

    def _deferred_tools(self, attachment: JsonObject) -> HarnessEntry:
        what = "deferred_tools_delta attachment"
        if "content" in attachment:
            content = attachment.get("content")
            if not isinstance(content, str):
                raise PayloadRefused(f"{what} content is not a string")
            return HarnessEntry("deferred_tools", "deferred tools", None, len(content))
        names = _strings(attachment.get("addedNames"), "addedNames", what)
        lines = _strings(attachment.get("addedLines"), "addedLines", what)
        removed = self._removed_names(attachment, "removedNames", what)
        return HarnessEntry(
            "deferred_tools",
            "deferred tools",
            len(names) - len(removed),
            sum(len(item) for item in lines),
            added=_sized_by_name(names, lines, what),
            removed=removed,
        )

    def _session_context(self, attachment: JsonObject) -> HarnessEntry:
        context = attachment.get("context")
        if not isinstance(context, dict):
            raise PayloadRefused("session_context attachment context is not an object")
        values = strict_str_list(list(context.values()))
        if values is None:
            raise PayloadRefused("session_context attachment context is not an object of strings")
        chars = sum(len(value) for value in values)
        return HarnessEntry("session_context", "session context", None, chars)

    def _hook_note(self, row: JsonObject, attachment: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        kind = attachment.get("type")
        what = f"{kind} attachment"
        label = _text(attachment, "hookName", what)
        event = _text(attachment, "hookEvent", what)
        if kind == "hook_blocking_error":
            blocked = as_object(attachment.get("blockingError")).get("blockingError")
            if not isinstance(blocked, str):
                raise PayloadRefused(f"{what} blockingError is not an object holding a string")
            return [self._harness(row, HarnessEntry("stop_block", label, None, len(blocked), event), subagent_id)]
        if kind == "hook_success":
            content = attachment.get("content")
            if content is None or content == "" or event not in HOOK_STDOUT_CONTEXT_EVENTS:
                return []
            if not isinstance(content, str):
                raise PayloadRefused(f"{what} content is not a string")
            return [self._harness(row, HarnessEntry("hook_note", label, None, len(content), event), subagent_id)]
        chars = sum(len(item) for item in _strings(attachment.get("content"), "content", what))
        return [self._harness(row, HarnessEntry("hook_note", label, None, chars, event), subagent_id)]
