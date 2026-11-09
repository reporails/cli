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
  (`addedNames` and `addedLines`, lists of strings, or in a subagent file `content`, a string; and optionally
  `pendingMcpServers`, a list of strings, and `failedMcpServers`, a list of objects each with a string
  `name` and optionally string `errorCode` and `error`),
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
  (`blockingError`, an object whose `blockingError` is a string and whose `command` is a string; a Stop
  block), each sized by character count and then dropped. Every hook row also yields a firing with the row's
  `uuid` when it has one, the hook's `command`, `exitCode` and `durationMs` where the row has them, the size of
  its output and what it decided: a `hook_system_message` row (`content`, a string) shows a message, a
  `hook_success` row holds its `stdout` and `stderr` strings.
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
  run), `model` (a string), `launchedWithDefaults` (a boolean), `spawnDepth` (a whole number) and
  `stoppedByUser` (a boolean).
- API request rows, recorded on Claude Code 2.1.309 and later: `api-request-shape`, `api-request-blob` and
  `api-request`, sized and dropped by `claude_requests` when `resolve_row` is given a request chain, ignored
  otherwise; their fields are listed there.
- an assistant row's `requestRef`: a string naming the API request that produced the reply, when present.

Never read, except for the sizes (a reply's text included), the brief and the prompts above: message content,
tool output, `content`, `displayPath`. Tool input is read only for the path, the MCP server, a hand-back message's
size and a command's hash, and a command's text on request. The meta `description` is read.
"""

from __future__ import annotations

from dataclasses import replace

from reporails_cli.core.eventbus.adapters.claude_calls import (
    blocks_text,
    call_command,
    call_input,
    content_blocks,
    holds_call,
    holds_result,
    result_text,
    tool_call,
    tool_result,
)
from reporails_cli.core.eventbus.adapters.claude_hooks import (
    HOOK_NOTE_ATTACHMENTS,
    hook_firing,
    hook_note,
    hook_output,
)
from reporails_cli.core.eventbus.adapters.claude_requests import (
    feed_row,
    request_shape_hash,
    shape_system_text,
)
from reporails_cli.core.eventbus.adapters.claude_rows import (
    brief_text,
    meta_field,
    required_text,
    sized_by_name,
    string_list,
    usage_counts,
)
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    as_list,
    as_object,
    opt_int,
    opt_str,
    strict_str_list,
)
from reporails_cli.core.platform.dto.events import (
    EventKind,
    EventRecord,
    HarnessAttachment,
    HarnessEntry,
    InstructionLoad,
    PromptEntry,
    ReplyText,
    RequestChain,
    SkillRun,
    SubagentMeta,
    TokenUsage,
)

# The `message.model` Claude Code writes on a reply it made itself, for an API error or an interrupt.
SYNTHETIC_MODEL = "<synthetic>"
NESTED_MARKER = "nested"
BACKGROUND_SHAPE = "background"


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


# The command row a `/clear` opens the new session's transcript with.
_CLEAR_COMMAND = "<command-name>/clear</command-name>"


class ClaudeTranscriptAdapter:
    """Resolves the rows of a Claude Code session transcript."""

    agent = "claude"
    session_env = "CLAUDE_CODE_SESSION_ID"  # https://code.claude.com/docs/en/env-vars

    def resolve_row(
        self, row: JsonObject, subagent_id: str | None, requests: RequestChain | None = None
    ) -> list[EventRecord]:
        """The records one row carries; refuses a known row type whose fields are not the pinned shape. With
        `requests`, every row is also fed to that chain and an `api-request` row yields its sized request."""
        kind = row.get("type")
        if requests is not None:
            size = feed_row(requests, row)
            if size is not None:
                return [replace(self._record(row, "api_request", subagent_id), item=size)]
        if kind == "assistant":
            return [
                self._usage(row, subagent_id),
                *self._reply_text(row, subagent_id),
                *self._tool_calls(row, subagent_id),
            ]
        if kind == "system":
            return self._system(row, subagent_id)
        if kind == "attachment":
            return self._attachment(row, subagent_id)
        if kind == "user":
            return [
                *self._prompt(row, subagent_id),
                *self._skill_run(row, subagent_id),
                *self._tool_results(row, subagent_id),
            ]
        return []

    def _system(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        subtype = row.get("subtype")
        if subtype == "turn_duration":
            return [self._record(row, "turn_end", subagent_id)]
        if subtype == "compact_boundary":
            return [self._compaction(row, subagent_id)]
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
        text = brief_text(first_row)
        if text is None:
            raise PayloadRefused("subagent first row holds no text content")
        return text

    def resolve_request_shape(self, row: JsonObject) -> str | None:
        """The hash of the request shape an `api-request` row names; None for any other row."""
        return request_shape_hash(row)

    def resolve_system(self, row: JsonObject, shape_hash: str) -> str | None:
        """The system prompt of the `api-request-shape` row recorded under `shape_hash`, for the route that shows
        it; None for any other row."""
        return shape_system_text(row, shape_hash)

    def holds_call(self, row: JsonObject, use_id: str) -> bool:
        """Whether `row` is an assistant row holding the tool call `use_id`."""
        return holds_call(row, use_id)

    def resolve_prompt(self, row: JsonObject) -> str:
        """The text of a typed prompt row, for the route that shows it; refuses a row that is not one."""
        text = self._typed_text(row)
        if text is None:
            raise PayloadRefused("row is not a typed prompt")
        return text

    def resolve_compact_summary(self, row: JsonObject) -> str | None:
        """The summary text of a compaction summary row (`type: "user"`, `isCompactSummary: true`, string
        `message.content`); None for any other row."""
        if row.get("type") != "user" or row.get("isCompactSummary") is not True:
            return None
        content = as_object(row.get("message")).get("content")
        return content if isinstance(content, str) else None

    def opens_with_clear(self, row: JsonObject) -> bool | None:
        """For a user row that is not a harness note, whether it is the `/clear` command row; None for any other
        row."""
        if row.get("type") != "user" or row.get("isMeta") is True:
            return None
        content = as_object(row.get("message")).get("content")
        return isinstance(content, str) and content.lstrip().startswith(_CLEAR_COMMAND)

    def row_time(self, row: JsonObject) -> str | None:
        """The `timestamp` of a row; None for a row without one."""
        return opt_str(row.get("timestamp")) or None

    def resolve_subagent(self, subagent_id: str, meta: JsonObject, first_row: JsonObject) -> EventRecord:
        """The `subagent_run` record of a subagent file; refuses a meta file without `agentType` or a first row that
        is not a user row. A first row with no text leaves the brief size unknown."""
        agent_type = opt_str(meta.get("agentType"))
        if not agent_type:
            raise PayloadRefused(f"subagent {subagent_id} meta has no agentType")
        brief = brief_text(first_row)
        launch = SubagentMeta(
            description=meta_field(meta, "description", str),
            parent_id=meta_field(meta, "parentAgentId", str),
            tool_use_id=meta_field(meta, "toolUseId", str),
            depth=meta_field(meta, "spawnDepth", int),
            brief_chars=None if brief is None else len(brief),
            stopped=meta_field(meta, "stoppedByUser", bool) is True,
            background=meta_field(meta, "requestShape", str) == BACKGROUND_SHAPE,
            asked_model=meta_field(meta, "model", str),
            with_defaults=meta_field(meta, "launchedWithDefaults", bool),
        )
        return replace(self._record(first_row, "subagent_run", subagent_id), subagent_type=agent_type, item=launch)

    def _tool_calls(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        return [
            replace(self._record(row, "tool_call", subagent_id), tool=tool_call(block))
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
            replace(self._record(row, "tool_result", subagent_id), tool=tool_result(block))
            for block in content_blocks(row, "tool_result")
        ]

    def _record(self, row: JsonObject, event: EventKind, subagent_id: str | None) -> EventRecord:
        what = f"{row.get('type')} row"
        session_id, time = required_text(row, "sessionId", what), required_text(row, "timestamp", what)
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
        entry = PromptEntry(
            required_text(row, "uuid", f"{row.get('type')} row"), len(text), row.get("type") == "attachment"
        )
        return [replace(self._record(row, "prompt_submit", subagent_id), item=entry)]

    def _usage(self, row: JsonObject, subagent_id: str | None) -> EventRecord:
        message = as_object(row.get("message"))
        message_id = required_text(message, "id", "assistant message")
        usage = TokenUsage.from_json(message_id, usage_counts(as_object(message.get("usage"))))
        if usage is None:
            raise PayloadRefused("assistant usage counts are not whole numbers")
        model = message.get("model")
        if model is not None and not isinstance(model, str):
            raise PayloadRefused("assistant message model is not a string")
        named = None if model == SYNTHETIC_MODEL else model
        request_ref = row.get("requestRef")
        if request_ref is not None and not isinstance(request_ref, str):
            raise PayloadRefused("assistant row requestRef is not a string")
        return replace(
            self._record(row, "assistant_usage", subagent_id),
            usage=replace(usage, model=named, request_ref=request_ref),
        )

    def _attachment(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        attachment = as_object(row.get("attachment"))
        kind = attachment.get("type")
        if kind == "nested_memory":
            return [
                self._load(
                    row, required_text(attachment, "path", "nested_memory attachment"), NESTED_MARKER, subagent_id
                )
            ]
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
            path = required_text(entry, "path", "instructions file")
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
            names = string_list(attachment.get(spec.count_key), spec.count_key, what)
            count = len(names)
        text = attachment.get(spec.chars_key)
        added: tuple[tuple[str, int], ...] = ()
        if spec.chars_is_text:
            if not isinstance(text, str):
                raise PayloadRefused(f"{what} {spec.chars_key} is not a string")
            chars = len(text)
        else:
            items = string_list(text, spec.chars_key, what)
            chars = sum(len(item) for item in items)
            if spec.removed_key is not None:
                added = sized_by_name(names, items, (), what)
        removed = self._removed_names(attachment, spec.removed_key, what)
        listed = (
            tuple(string_list(attachment["names"], "names", what))
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
        return tuple(string_list(attachment.get(key), key, what))

    def _failed_servers(self, attachment: JsonObject, what: str) -> tuple[str, ...]:
        """The names of the servers that failed to connect; each entry is an object with a string name."""
        if "failedMcpServers" not in attachment:
            return ()
        entries = attachment["failedMcpServers"]
        if not isinstance(entries, list):
            raise PayloadRefused(f"{what} failedMcpServers is not a list of objects")
        names: list[str] = []
        for entry in entries:
            fields = as_object(entry)
            name = opt_str(fields.get("name"))
            if not name:
                raise PayloadRefused(f"{what} failedMcpServers entry has no string name")
            for key in ("errorCode", "error"):
                if key in fields and opt_str(fields[key]) is None:
                    raise PayloadRefused(f"{what} failedMcpServers entry {key} is not a string")
            names.append(name)
        return tuple(names)

    def _deferred_tools(self, attachment: JsonObject) -> HarnessEntry:
        what = "deferred_tools_delta attachment"
        if "content" in attachment:
            content = attachment.get("content")
            if not isinstance(content, str):
                raise PayloadRefused(f"{what} content is not a string")
            return HarnessEntry("deferred_tools", "deferred tools", None, len(content))
        names = string_list(attachment.get("addedNames"), "addedNames", what)
        lines = string_list(attachment.get("addedLines"), "addedLines", what)
        removed = self._removed_names(attachment, "removedNames", what)
        readded = self._removed_names(attachment, "readdedNames", what)
        added = sized_by_name(names, lines, readded, what)
        return HarnessEntry(
            "deferred_tools",
            "deferred tools",
            len(names) - len(removed),
            sum(len(item) for item in lines),
            added=added,
            removed=removed,
            readded=() if added else tuple(names),
            pending=self._removed_names(attachment, "pendingMcpServers", what),
            failed=self._failed_servers(attachment, what),
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
        what = f"{attachment.get('type')} attachment"
        label = required_text(attachment, "hookName", what)
        event = required_text(attachment, "hookEvent", what)
        found = hook_note(attachment, event)
        notes = (
            []
            if found is None
            else [self._harness(row, HarnessEntry(found[0], label, None, found[1], event), subagent_id)]
        )
        firing = replace(self._record(row, "hook_firing", subagent_id), item=hook_firing(row, attachment, label, event))
        return [*notes, firing]

    def resolve_hook_output(self, row: JsonObject) -> str:
        """The text a hook row holds, for the route that shows it; refuses a row that is not a hook row."""
        return hook_output(as_object(row.get("attachment")))
