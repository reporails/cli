"""The Claude Code transcript adapter: session transcript rows to event records.

Documented by the vendor:

- Where a transcript lives, `~/.claude/projects/<project>/<session-id>.jsonl`:
  https://code.claude.com/docs/en/sessions#where-transcripts-are-stored
- A subagent's transcript, `<session-id>/subagents/agent-<agentId>.jsonl`:
  https://code.claude.com/docs/en/sub-agents#resume-subagents
- The token counts `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens` and
  the cache-write split `cache_creation.ephemeral_5m_input_tokens` / `ephemeral_1h_input_tokens`:
  https://code.claude.com/docs/en/prompt-caching#check-cache-performance
- The instruction-file load events, `InstructionsLoaded` with `file_path`, `memory_type` and `load_reason`:
  https://code.claude.com/docs/en/hooks

Undocumented: the row layout. The sessions page calls the entry format "internal to Claude Code" and says
it changes between versions. These are shapes recorded on Claude Code 2.1.292, 2.1.301 and 2.1.308, and
the adapter refuses any other shape of a row type it reads:

- an assistant row: `type: "assistant"`, `timestamp`, `message.id`, `message.usage` holding the three
  input counts above, optionally `output_tokens` and `cache_creation` (an object holding the 5-minute and 1-hour
  cache-write counts), and optionally `message.model`, a string, read as no model when it is `<synthetic>` (the value
  Claude Code writes for an API error or an interrupt); one row is written per content block, so the rows of
  one response repeat `message.id`.
- a turn end: `type: "system"` with `subtype: "turn_duration"` and `timestamp`.
- an instruction load: `type: "attachment"` with `attachment.type: "instructions"` and
  `attachment.files[].path` / `.type`, or `attachment.type: "nested_memory"` and `attachment.path`. The
  `InstructionsLoaded` hook does not fire for auto memory or for a subagent's session-start loads (probe on
  Claude Code 2.1.308, 2026-10-30), which is why the transcript is the source.
- a harness record: `type: "attachment"` with one of these `attachment.type` values, each sized by character
  count and then dropped: `prompt_snapshot` (`systemPrompt`, a list of strings), `skill_listing` (`skillCount`,
  a whole number, `content`, a string, and optionally `names`, a list of strings), `agent_listing_delta`
  (`addedTypes` and `addedLines`, lists of strings), `mcp_instructions_delta`
  (`addedNames` and `addedBlocks`, lists of strings), `deferred_tools_delta`
  (`addedNames` and `addedLines`, lists of strings, or in a subagent file `content`, a string),
  `session_context` (`context`, an object of strings). The three delta rows may also carry `removedTypes` or
  `removedNames`, lists of strings, counted off their item count; a deferred-tools delta row whose
  added items list is empty names tools re-added by name: `readdedNames`, a list of strings, must name every
  added name, and each counts with size 0 and is recorded as re-added; any other row whose added names and
  items differ in length, empty items included, is refused; each added item's size is kept under its
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
- a skill run: a `user` row whose `toolUseResult` is an object with `commandName`, a string, and `success`, a
  boolean (the skill's name as the session shows it, `cloudflare:agents-sdk` for a plugin's), and optionally
  `status`, a string, which is `forked` when the skill ran in a subagent of its own (`context: fork`); no other
  key of the object is read. A `success: false` run, and a `toolUseResult` that is not an object or has no
  `commandName`, yield nothing.
- a compaction: `type: "system"` with `subtype: "compact_boundary"` and `compactMetadata.trigger`.
- a subagent brief: the first row of a subagent file, `type: "user"` with `message.content` a string or a
  list of blocks whose `type: "text"` blocks hold `text`.
- every row the adapter reads (assistant, system, attachment) carries `sessionId` and `timestamp`; a row
  without either is refused.
- a tool call: an `assistant` row whose `message.content` is a list holding `{"type": "tool_use", "id", "name",
  "input"}` blocks, `id` and `name` strings and `input` an object. `name` is `mcp__<server>__<tool>` for an MCP
  server's tool. From `input` only these are read: the path (`file_path`, else `notebook_path`, else `path`, a
  string) of a read or edit tool, a hand-back's `message` (a string, for its size), a Bash or PowerShell call's
  `command` (a string, for its hash; its text only through `resolve_call`).
- an assistant reply's text: an `assistant` row whose `message.content` is a list holding `{"type": "text",
  "text"}` blocks, `text` a string; only the characters of the text blocks are kept. A subagent that ends on such a row
  returns that text to its parent.
- a hand-back: a tool call named `SubagentHandback`, with `input.message`.
- a tool result: a `user` row whose `message.content` is a list holding `{"type": "tool_result", "tool_use_id",
  "content", "is_error"?}` blocks, `tool_use_id` a string, `is_error` a boolean when present and `content` a string
  or a list of blocks, sized by the characters of its text; a block of any other type counts nothing.
- a subagent file: its first row's `timestamp`, the `agentType` of `agent-<id>.meta.json` and, when present, the
  meta fields `description`, `parentAgentId`, `toolUseId`, `requestShape` (strings; `background` marks a background
  run), `spawnDepth` (a whole number) and `stoppedByUser` (a boolean).
- a request blob: `type: "api-request-blob"` repeats request content; not read (tool calls come from `assistant` rows).

Never read, except for the sizes (a reply's text included), the brief and the prompts above: message content,
tool output, `content`, `displayPath`. Tool input is read only for the path, the MCP server, a hand-back message's
size and a command's hash, and a command's text on request. The meta `description` is read.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

from reporails_cli.core.eventbus.adapters.claude_calls import (
    blocks_text,
    call_command,
    call_input,
    command_of,
    content_blocks,
    holds_call,
    holds_result,
    result_text,
)
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
    TARGETS_FILE,
    EventKind,
    EventRecord,
    HarnessAttachment,
    HarnessEntry,
    InstructionLoad,
    PromptEntry,
    ReplyText,
    SkillRun,
    SubagentMeta,
    TokenUsage,
    ToolCategory,
    ToolUse,
)

# The `message.model` Claude Code writes on a reply it made itself, for an API error or an interrupt.
SYNTHETIC_MODEL = "<synthetic>"
NESTED_MARKER = "nested"
BRIEF_BLOCK_SEPARATOR = "\n\n"
HOOK_NOTE_ATTACHMENTS = ("hook_additional_context", "hook_success", "hook_blocking_error")
# The hook events whose plain-text stdout Claude Code adds to the context.
HOOK_STDOUT_CONTEXT_EVENTS = ("UserPromptSubmit", "UserPromptExpansion", "SessionStart", "PostModelSwitch")
MCP_PREFIX = "mcp__"
MCP_SEPARATOR = "__"
FINGERPRINT_CHARS = 16
BACKGROUND_SHAPE = "background"
# How the result of a launched background agent opens: an acknowledgement, not the agent's answer.
LAUNCH_ACK_PREFIX = "Async agent launched"
# The tool names of each category the side track and the inspector group by; an MCP tool is told by its prefix.
TOOL_CATEGORY: dict[str, ToolCategory] = {
    **dict.fromkeys(("Read", "Grep", "Glob", "LS", "NotebookRead", "WebFetch", "WebSearch"), "read"),
    **dict.fromkeys(("Edit", "MultiEdit", "Write", "NotebookEdit"), "edit"),
    **dict.fromkeys(("Bash", "PowerShell"), "run"),
    **dict.fromkeys(("Agent", "Task"), "agent"),
    "SubagentHandback": "handback",
}
PATH_KEYS = ("file_path", "notebook_path", "path")


def mcp_server(name: str) -> str | None:
    """The server of an `mcp__<server>__<tool>` tool name; None for any other name."""
    if not name.startswith(MCP_PREFIX):
        return None
    server = name.removeprefix(MCP_PREFIX).split(MCP_SEPARATOR, 1)[0]
    return server or None


def tool_category(name: str) -> ToolCategory:
    """The category a tool name falls in."""
    if mcp_server(name) is not None:
        return "mcp"
    return TOOL_CATEGORY.get(name, "other")


def _call_path(tool_input: JsonObject) -> str | None:
    for key in PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
    return None


def _tool_call(block: JsonObject) -> ToolUse:
    """The call one `tool_use` block makes; refuses a block without string `id` and `name` or an object `input`."""
    use_id, name, tool_input = block.get("id"), block.get("name"), block.get("input")
    if not isinstance(use_id, str) or not isinstance(name, str):
        raise PayloadRefused("tool_use block has no string id and name")
    if not isinstance(tool_input, dict):
        raise PayloadRefused(f"{name} call input is not an object")
    category = tool_category(name)
    path = _call_path(tool_input) if TARGETS_FILE[category] else None
    chars: int | None = None
    fingerprint: str | None = None
    if category == "handback":
        message = tool_input.get("message")
        if not isinstance(message, str):
            raise PayloadRefused("SubagentHandback call has no string message")
        chars = len(message)
    elif category == "run":
        fingerprint = hashlib.sha256(command_of(tool_input, name).encode()).hexdigest()[:FINGERPRINT_CHARS]
    return ToolUse(name, use_id, path, server=mcp_server(name), category=category, chars=chars, fingerprint=fingerprint)


def _tool_result(block: JsonObject) -> ToolUse:
    """The result one `tool_result` block reports: its call id, the size of its content and whether it failed."""
    use_id, failed = block.get("tool_use_id"), block.get("is_error")
    if not isinstance(use_id, str):
        raise PayloadRefused("tool_result block has no string tool_use_id")
    if failed is not None and not isinstance(failed, bool):
        raise PayloadRefused("tool_result is_error is not a boolean")
    texts = blocks_text(block.get("content"), "tool_result")
    if texts is None:
        raise PayloadRefused("tool_result content is neither text nor a list of blocks")
    return ToolUse(
        use_id=use_id,
        chars=sum(len(text) for text in texts),
        error=bool(failed),
        launch_ack=next((text for text in texts if text), "").startswith(LAUNCH_ACK_PREFIX),
    )


def _meta_field[Field: (str, int, bool)](meta: JsonObject, key: str, kind: type[Field]) -> Field | None:
    """A meta field that must be of type `kind` when present; None when absent."""
    value = meta.get(key)
    if value is None:
        return None
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise PayloadRefused(f"subagent meta {key} is not a {kind.__name__}")
    return value


def _sized_by_name(
    names: list[str], items: list[str], readded: tuple[str, ...], what: str
) -> tuple[tuple[str, int], ...]:
    """Each added item's size under its name; the names and the items must pair up one to one. With no items every
    name must be one the row re-added, and none is sized."""
    if not items:
        stray = [name for name in names if name not in readded]
        if stray:
            raise PayloadRefused(
                f"{what} lists names with no items that readdedNames does not name: {', '.join(stray)}"
            )
        return ()
    if len(names) != len(items):
        raise PayloadRefused(f"{what} lists {len(names)} names for {len(items)} items")
    return tuple((name, len(item)) for name, item in zip(names, items, strict=True))


_HARNESS: dict[str, HarnessAttachment] = {
    "prompt_snapshot": HarnessAttachment(
        "system_prompt", "system prompt", "systemPrompt", False, "systemPrompt", False
    ),
    "skill_listing": HarnessAttachment("skill_list", "skills", "skillCount", True, "content", True),
    "agent_listing_delta": HarnessAttachment(
        "agent_list", "agents", "addedTypes", False, "addedLines", False, "removedTypes"
    ),
    "mcp_instructions_delta": HarnessAttachment(
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


def _brief_text(first_row: JsonObject) -> str | None:
    """The text of a subagent file's first row, None when it holds none; refuses a first row that is not a user row."""
    if first_row.get("type") != "user":
        raise PayloadRefused("subagent file does not open with a user row")
    content = as_object(first_row.get("message")).get("content")
    if isinstance(content, str):
        return content or None
    texts = blocks_text(content, "subagent first row")
    return BRIEF_BLOCK_SEPARATOR.join(texts) if texts else None


def _usage_counts(usage: JsonObject) -> JsonObject:
    """A row's usage object with the cache-write split lifted to the keys the usage record reads; a present
    `cache_creation` that is not an object refuses the row."""
    creation = usage.get("cache_creation")
    if creation is not None and not isinstance(creation, dict):
        raise PayloadRefused("assistant usage cache_creation is not an object")
    split = creation or {}
    return {
        **usage,
        "cache_write_5m_tokens": split.get("ephemeral_5m_input_tokens"),
        "cache_write_1h_tokens": split.get("ephemeral_1h_input_tokens"),
    }


class ClaudeTranscriptAdapter:
    """Resolves the rows of a Claude Code session transcript."""

    agent = "claude"
    session_env = "CLAUDE_CODE_SESSION_ID"  # https://code.claude.com/docs/en/env-vars

    def resolve_row(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        """The records one row carries; refuses a known row type whose fields are not the pinned shape."""
        kind = row.get("type")
        if kind == "assistant":
            return [
                self._usage(row, subagent_id),
                *self._reply_text(row, subagent_id),
                *self._tool_calls(row, subagent_id),
            ]
        if kind == "system" and row.get("subtype") == "turn_duration":
            return [self._record(row, "turn_end", subagent_id)]
        if kind == "system" and row.get("subtype") == "compact_boundary":
            return [self._compaction(row, subagent_id)]
        if kind == "attachment":
            return self._attachment(row, subagent_id)
        if kind == "user":
            return [
                *self._prompt(row, subagent_id),
                *self._skill_run(row, subagent_id),
                *self._tool_results(row, subagent_id),
            ]
        return []

    def resolve_call(self, row: JsonObject, use_id: str) -> str:
        """The command of the tool call `use_id` in an assistant row, for the route that shows it; refuses a row
        with no such call or a call with no string command."""
        return call_command(row, use_id)

    def resolve_call_input(self, row: JsonObject, use_id: str) -> JsonObject:
        """The input of the tool call `use_id` in an assistant row, for the route that shows it."""
        return call_input(row, use_id)

    def holds_result(self, row: JsonObject, use_id: str) -> bool:
        """Whether `row` is a user row holding the result of the tool call `use_id`."""
        return holds_result(row, use_id)

    def resolve_result(self, row: JsonObject, use_id: str) -> str:
        """The text of the result of the tool call `use_id` in a user row, for the route that shows it."""
        return result_text(row, use_id)

    def resolve_brief(self, first_row: JsonObject) -> str:
        """The brief a subagent was given, the text of its first row; refuses a first row that is not a user
        row holding text."""
        if first_row.get("type") != "user":
            raise PayloadRefused("subagent file does not open with a user row")
        text = _brief_text(first_row)
        if text is None:
            raise PayloadRefused("subagent first row holds no text content")
        return text

    def holds_call(self, row: JsonObject, use_id: str) -> bool:
        """Whether `row` is an assistant row holding the tool call `use_id`."""
        return holds_call(row, use_id)

    def resolve_prompt(self, row: JsonObject) -> str:
        """The text of a typed prompt row, for the route that shows it; refuses a row that is not one."""
        text = self._typed_text(row)
        if text is None:
            raise PayloadRefused("row is not a typed prompt")
        return text

    def resolve_subagent(self, subagent_id: str, meta: JsonObject, first_row: JsonObject) -> EventRecord:
        """The `subagent_run` record of a subagent file; refuses a meta file without `agentType` or a first row that
        is not a user row. A first row with no text leaves the brief size unknown."""
        agent_type = opt_str(meta.get("agentType"))
        if not agent_type:
            raise PayloadRefused(f"subagent {subagent_id} meta has no agentType")
        brief = _brief_text(first_row)
        launch = SubagentMeta(
            description=_meta_field(meta, "description", str),
            parent_id=_meta_field(meta, "parentAgentId", str),
            tool_use_id=_meta_field(meta, "toolUseId", str),
            depth=_meta_field(meta, "spawnDepth", int),
            brief_chars=None if brief is None else len(brief),
            stopped=_meta_field(meta, "stoppedByUser", bool) is True,
            background=_meta_field(meta, "requestShape", str) == BACKGROUND_SHAPE,
        )
        return replace(self._record(first_row, "subagent_run", subagent_id), subagent_type=agent_type, item=launch)

    def _tool_calls(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        return [
            replace(self._record(row, "tool_call", subagent_id), tool=_tool_call(block))
            for block in content_blocks(row, "tool_use")
        ]

    def _reply_text(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        """One record sizing the text blocks of an assistant row; none when the row holds no text block."""
        blocks = content_blocks(row, "text")
        if not blocks:
            return []
        texts = [block.get("text") for block in blocks]
        if not all(isinstance(text, str) for text in texts):
            raise PayloadRefused("assistant text block has no text")
        chars = sum(len(text) for text in texts if isinstance(text, str))
        synthetic = as_object(row.get("message")).get("model") == SYNTHETIC_MODEL
        return [replace(self._record(row, "assistant_text", subagent_id), item=ReplyText(chars, synthetic))]

    def _tool_results(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        return [
            replace(self._record(row, "tool_result", subagent_id), tool=_tool_result(block))
            for block in content_blocks(row, "tool_result")
        ]

    def _record(self, row: JsonObject, event: EventKind, subagent_id: str | None) -> EventRecord:
        what = f"{row.get('type')} row"
        session_id, time = _text(row, "sessionId", what), _text(row, "timestamp", what)
        return EventRecord(self.agent, event, session_id, time, subagent_id, opt_str(row.get("cwd")) or None)

    def _compaction(self, row: JsonObject, subagent_id: str | None) -> EventRecord:
        trigger = opt_str(as_object(row.get("compactMetadata")).get("trigger"))
        return replace(self._record(row, "post_compact", subagent_id), source=trigger)

    def _typed_text(self, row: JsonObject) -> str | None:
        """The text of a row a person typed, None for any other row."""
        if row.get("type") == "user":
            if row.get("promptSource") != "typed" or as_object(row.get("origin")).get("kind") != "human":
                return None
            texts = blocks_text(as_object(row.get("message")).get("content"), "user row")
            if texts is None:
                raise PayloadRefused("user row message content is neither text nor a list of blocks")
            return "".join(texts)
        attachment = as_object(row.get("attachment"))
        if attachment.get("type") != "queued_command" or attachment.get("commandMode") != "prompt":
            return None
        if as_object(attachment.get("origin")).get("kind") != "human":
            return None
        texts = blocks_text(attachment.get("prompt"), "queued_command attachment prompt")
        if texts is None:
            raise PayloadRefused("queued_command attachment prompt is neither text nor a list of blocks")
        return "".join(texts)

    def _skill_run(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        result = row.get("toolUseResult")
        if not isinstance(result, dict) or "commandName" not in result:
            return []
        what = "toolUseResult"
        name, success = result.get("commandName"), result.get("success")
        if not isinstance(name, str) or not name:
            raise PayloadRefused(f"{what} commandName is not a string")
        if not isinstance(success, bool):
            raise PayloadRefused(f"{what} success is not a boolean")
        status = result.get("status")
        if status is not None and not isinstance(status, str):
            raise PayloadRefused(f"{what} status is not a string")
        if not success:
            return []
        return [replace(self._record(row, "skill_run", subagent_id), item=SkillRun(name, status == "forked"))]

    def _prompt(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        text = self._typed_text(row)
        if text is None:
            return []
        entry = PromptEntry(_text(row, "uuid", f"{row.get('type')} row"), len(text), row.get("type") == "attachment")
        return [replace(self._record(row, "prompt_submit", subagent_id), item=entry)]

    def _usage(self, row: JsonObject, subagent_id: str | None) -> EventRecord:
        message = as_object(row.get("message"))
        message_id = _text(message, "id", "assistant message")
        usage = TokenUsage.from_json(message_id, _usage_counts(as_object(message.get("usage"))))
        if usage is None:
            raise PayloadRefused("assistant usage counts are not whole numbers")
        model = message.get("model")
        if model is not None and not isinstance(model, str):
            raise PayloadRefused("assistant message model is not a string")
        named = None if model == SYNTHETIC_MODEL else model
        return replace(self._record(row, "assistant_usage", subagent_id), usage=replace(usage, model=named))

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
                added = _sized_by_name(names, items, (), what)
        removed = self._removed_names(attachment, spec.removed_key, what)
        listed = (
            tuple(_strings(attachment["names"], "names", what))
            if kind == "skill_listing" and "names" in attachment
            else None
        )
        return HarnessEntry(
            spec.kind, spec.label, count - len(removed), chars, added=added, removed=removed, names=listed
        )

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
        readded = self._removed_names(attachment, "readdedNames", what)
        added = _sized_by_name(names, lines, readded, what)
        return HarnessEntry(
            "deferred_tools",
            "deferred tools",
            len(names) - len(removed),
            sum(len(item) for item in lines),
            added=added,
            removed=removed,
            readded=() if added else tuple(names),
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
