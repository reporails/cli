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
  `name` and optionally string `errorCode` and `error`), `session_context` (`context`, an object of strings). The three
  delta rows may also carry `removedTypes` or `removedNames`, lists of strings, counted off their item count; a
  deferred-tools delta row whose added items list is empty names tools re-added by name: `readdedNames`, a list of
  strings, must name every added name, and each counts with size 0 and is recorded as re-added; any other row whose
  added names and items differ in length, empty items included, is refused; each added item's size is kept under its
  name (never its text) and each removed name is kept, so a later removal takes its size off too.
- a name-only harness record: `type: "attachment"` with an `attachment.type` of `environment`, `auto_mode`,
  `plan_mode`, `task_reminder`, `silent_turn_reminder`, `credential_org` or `date`: kind `unsized`, size 0.
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
- a stop hook summary: `type: "system"` with `subtype: "stop_hook_summary"` and `hookInfos`, a list of objects
  with the `command` that ran and its `durationMs` where it has one; each entry yields one `Stop` firing.
- a compaction: `type: "system"` with `subtype: "compact_boundary"`, `compactMetadata.trigger` and, when present,
  `compactMetadata.preservedMessages.uuids`, a list of the ids of the rows Claude Code kept across it.
- a file attachment: `type: "attachment"` with `attachment.type: "file"` and `attachment.filename`, a string, which
  holds the whole file (its `content` is never read), or `attachment.type: "compact_file_reference"` and
  `attachment.filename`, a string, which names a file read before a compaction whose content was too large to
  include. Both follow a `compact_boundary` row before the next assistant reply.
- an edit snippet, `attachment.type: "edited_text_file"` with `attachment.filename`, a string (`snippet` is never
  read), and recalled notes, `attachment.type: "relevant_memories"` with `attachment.memories`, objects each with a
  `path` string, one file attachment per entry (`content` is never read).
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
  run), `model` (a string), `launchedWithDefaults` (a boolean), `spawnDepth` (a whole number),
  `stoppedByUser` (a boolean) and `workflowPhase` (a string, on an agent a workflow run started). A workflow run's
  record file is read by `claude_workflows`.
- API request rows, recorded on Claude Code 2.1.309 and later: `api-request-shape`, `api-request-blob` and
  `api-request`, sized and dropped by `claude_requests` when `resolve_row` is given a request chain, ignored
  otherwise; their fields are listed there.
- an assistant row's `requestRef`: a string naming the API request that produced the reply, when present.

Never read, except for the sizes (a reply's text included), the brief and the prompts above: message content,
tool output, `content`, `displayPath`. Tool input is read only for the path, the MCP server, a hand-back message's
size and a command's hash; on request, a command's text, a hand-back's message and an assistant row's text. The meta
`description` is read.
"""

from __future__ import annotations

from dataclasses import replace
from typing import ClassVar

from reporails_cli.core.eventbus.adapters.claude_calls import (
    blocks_text,
    call_command,
    call_input,
    content_blocks,
    handback_message,
    holds_call,
    holds_result,
    reply_blocks,
    reply_text,
    result_text,
    tool_call,
    tool_result,
)
from reporails_cli.core.eventbus.adapters.claude_harness import ClaudeContextReader, harness_parts
from reporails_cli.core.eventbus.adapters.claude_hooks import (
    HOOK_NOTE_ATTACHMENTS,
    hook_firing,
    hook_note,
    hook_output,
    stop_summary_firings,
)
from reporails_cli.core.eventbus.adapters.claude_launch import subagent_launch
from reporails_cli.core.eventbus.adapters.claude_requests import (
    feed_row,
    request_blocks,
    request_shape_ref,
    shape_text,
)
from reporails_cli.core.eventbus.adapters.claude_rows import (
    attached_paths,
    brief_text,
    compact_summary_link,
    compact_summary_text,
    required_text,
    usage_counts,
)
from reporails_cli.core.eventbus.adapters.claude_workflows import accepted_output, resolve_workflow_run
from reporails_cli.core.eventbus.port import ContextReader, PayloadRefused
from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    as_list,
    as_object,
    opt_str,
    strict_str_list,
)
from reporails_cli.core.platform.dto.attachments import FileAttachment, is_attachment_kind
from reporails_cli.core.platform.dto.events import (
    CompactionBoundary,
    EventKind,
    EventRecord,
    HarnessEntry,
    InstructionLoad,
    MessageText,
    PromptEntry,
    ReplyText,
    RequestChain,
    SkillRun,
    TokenUsage,
)

# The `message.model` Claude Code writes on a reply it made itself, for an API error or an interrupt.
SYNTHETIC_MODEL = "<synthetic>"
NESTED_MARKER = "nested"


# The command row a `/clear` opens the new session's transcript with.
_CLEAR_COMMAND = "<command-name>/clear</command-name>"


class ClaudeTranscriptAdapter:
    """Resolves the rows of a Claude Code session transcript."""

    agent = "claude"
    session_env = "CLAUDE_CODE_SESSION_ID"  # https://code.claude.com/docs/en/env-vars
    context: ClassVar[ContextReader] = ClaudeContextReader()

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
        if subtype == "stop_hook_summary":
            return [
                replace(self._record(row, "hook_firing", subagent_id), item=firing)
                for firing in stop_summary_firings(row)
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

    def resolve_handback(self, row: JsonObject, agent_id: str) -> str | None:
        """The message of the hand-back call an assistant row holds, or the output a workflow journal `result` row
        says the run accepted from `agent_id`; None for any other row."""
        return handback_message(row) if row.get("type") == "assistant" else accepted_output(row, agent_id)

    def resolve_reply(self, row: JsonObject) -> str | None:
        """The text of an assistant row; None for any other row or a row with no text."""
        return reply_text(row)

    def resolve_brief(self, first_row: JsonObject) -> str:
        """The brief a subagent was given, the text of its first row; refuses a first row that is not a user
        row holding text."""
        if first_row.get("type") != "user":
            raise PayloadRefused("subagent file does not open with a user row")
        text = brief_text(first_row)
        if text is None:
            raise PayloadRefused("subagent first row holds no text content")
        return text

    def resolve_request(self, row: JsonObject) -> tuple[str, str] | None:
        """The id and the request shape hash of an `api-request` row; None for any other row."""
        return request_shape_ref(row)

    def resolve_shape_text(self, row: JsonObject, shape_hash: str, item: str) -> str | None:
        """The system prompt or tool definitions of the shape row recorded under `shape_hash`; None for any other."""
        return shape_text(row, shape_hash, item)

    def request_blocks(self, chain: RequestChain) -> list[MessageText]:
        """The notes and thinking of the messages of the request `chain` last took, in order."""
        return request_blocks(chain)

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
        return compact_summary_text(row)

    def resolve_compact_link(self, row: JsonObject) -> str | None:
        """The `parentUuid` of a compaction summary row, the `uuid` of the boundary row it follows; None for any
        other row or a summary row with no parent."""
        return compact_summary_link(row)

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

    resolve_workflow_run = staticmethod(resolve_workflow_run)

    def resolve_subagent(
        self, subagent_id: str, meta: JsonObject, first_row: JsonObject, workflow_run: str | None = None
    ) -> EventRecord:
        """The `subagent_run` record of a subagent file; refuses a meta file without `agentType` or a first row that
        is not a user row. A first row with no text leaves the brief size unknown. For an agent of a workflow run,
        the record names the run and the meta's `workflowPhase`."""
        agent_type = opt_str(meta.get("agentType"))
        if not agent_type:
            raise PayloadRefused(f"subagent {subagent_id} meta has no agentType")
        brief = brief_text(first_row)
        launch = subagent_launch(meta, brief, workflow_run)
        return replace(self._record(first_row, "subagent_run", subagent_id), subagent_type=agent_type, item=launch)

    def _tool_calls(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        return [
            replace(
                self._record(row, "tool_call", subagent_id),
                tool=replace(tool_call(block), row_id=opt_str(row.get("uuid"))),
            )
            for block in content_blocks(row, "tool_use")
        ]

    def _reply_text(self, row: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        """One record sizing the text blocks of an assistant row; none when the row holds no text block."""
        texts = reply_blocks(row)
        if not texts:
            return []
        chars = sum(len(text) for text in texts)
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
        metadata = as_object(row.get("compactMetadata"))
        trigger = opt_str(metadata.get("trigger"))
        boundary = CompactionBoundary(opt_str(row.get("uuid")) or None, self._kept_messages(metadata))
        return replace(self._record(row, "post_compact", subagent_id), source=trigger, item=boundary)

    @staticmethod
    def _kept_messages(metadata: JsonObject) -> tuple[str, ...]:
        """The ids of the messages a compaction kept: none when `preservedMessages` is absent; refuses one that is
        not an object holding a list of strings under `uuids`."""
        preserved = metadata.get("preservedMessages")
        if preserved is None:
            return ()
        if not isinstance(preserved, dict):
            raise PayloadRefused("compact_boundary row preservedMessages is not an object")
        kept = strict_str_list(preserved.get("uuids"))
        if kept is None:
            raise PayloadRefused("compact_boundary row preservedMessages.uuids is not a list of strings")
        return tuple(kept)

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
        if is_attachment_kind(kind):
            base = self._record(row, "file_attachment", subagent_id)
            return [replace(base, item=FileAttachment(path, kind)) for path in attached_paths(attachment, kind)]
        if kind in HOOK_NOTE_ATTACHMENTS:
            return self._hook_note(row, attachment, subagent_id)
        if kind == "queued_command":
            return self._prompt(row, subagent_id)
        parts = harness_parts(attachment, kind)
        return [] if parts is None else [self._harness(row, parts[0], subagent_id)]

    def _instructions(self, row: JsonObject, attachment: JsonObject, subagent_id: str | None) -> list[EventRecord]:
        loads: list[EventRecord] = []
        for item in as_list(attachment.get("files")):
            entry = as_object(item)
            path = required_text(entry, "path", "instructions file")
            loads.append(self._load(row, path, opt_str(entry.get("type")), subagent_id))
        return loads

    def _load(self, row: JsonObject, path: str, memory_type: str | None, subagent_id: str | None) -> EventRecord:
        return replace(
            self._record(row, "instruction_load", subagent_id),
            item=InstructionLoad(path, memory_type, opt_str(row.get("uuid")) or None),
        )

    def _harness(self, row: JsonObject, entry: HarnessEntry, subagent_id: str | None) -> EventRecord:
        return replace(self._record(row, "harness", subagent_id), item=entry)

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
