"""Reading one hook row of a Claude Code transcript: the note it puts into the context, the firing it records and the
text it holds, for the route that shows that text."""

from __future__ import annotations

from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object, opt_int, opt_str, strict_str_list
from reporails_cli.core.platform.dto.events import HookDecision, HookFiring, NoteKind

HOOK_NOTE_ATTACHMENTS = (
    "hook_additional_context",
    "hook_success",
    "hook_blocking_error",
    "hook_non_blocking_error",
    "hook_system_message",
)
# The hook events whose plain-text stdout Claude Code adds to the context.
HOOK_STDOUT_CONTEXT_EVENTS = ("UserPromptSubmit", "UserPromptExpansion", "SessionStart", "PostModelSwitch")


def _context_items(attachment: JsonObject, what: str) -> list[str]:
    items = strict_str_list(attachment.get("content"))
    if items is None:
        raise PayloadRefused(f"{what} content is not a list of strings")
    return items


def hook_note(attachment: JsonObject, event: str) -> tuple[NoteKind, int] | None:
    """The kind and size in characters of the note a hook row puts into the context; None when it puts none. A
    `hook_success` row's `content` counts only for the events whose stdout Claude Code adds to the context."""
    kind = attachment.get("type")
    what = f"{kind} attachment"
    if kind == "hook_blocking_error":
        blocked = as_object(attachment.get("blockingError")).get("blockingError")
        if not isinstance(blocked, str):
            raise PayloadRefused(f"{what} blockingError is not an object holding a string")
        return "stop_block", len(blocked)
    if kind == "hook_success":
        content = attachment.get("content")
        if content is None or content == "" or event not in HOOK_STDOUT_CONTEXT_EVENTS:
            return None
        if not isinstance(content, str):
            raise PayloadRefused(f"{what} content is not a string")
        return "hook_note", len(content)
    if kind == "hook_additional_context":
        return "hook_note", sum(len(item) for item in _context_items(attachment, what))
    return None


def hook_firing(row: JsonObject, attachment: JsonObject, label: str, event: str) -> HookFiring:
    """The firing a hook row records: its command, exit code and duration where the row has them, what it decided
    (`failed` for a hook that exited non-zero without blocking) and the size of its output."""
    kind = attachment.get("type")
    what = f"{kind} attachment"
    row_id = opt_str(row.get("uuid")) or None
    note = hook_note(attachment, event)
    if kind == "hook_blocking_error":
        command = opt_str(as_object(attachment.get("blockingError")).get("command"))
        return HookFiring(label, event, row_id, command, None, None, "blocked", note[1] if note else 0)
    if kind in ("hook_success", "hook_non_blocking_error"):
        output = len(opt_str(attachment.get("stdout")) or "") + len(opt_str(attachment.get("stderr")) or "")
        decision: HookDecision = "failed" if kind == "hook_non_blocking_error" else "context_added" if note else "ran"
        return HookFiring(
            label,
            event,
            row_id,
            opt_str(attachment.get("command")),
            opt_int(attachment.get("exitCode")),
            opt_int(attachment.get("durationMs")),
            decision,
            output,
        )
    if kind == "hook_system_message":
        content = attachment.get("content")
        if not isinstance(content, str):
            raise PayloadRefused(f"{what} content is not a string")
        return HookFiring(label, event, row_id, None, None, None, "message_shown", len(content))
    return HookFiring(label, event, row_id, None, None, None, "context_added", note[1] if note else 0)


def hook_output(attachment: JsonObject) -> str:
    """The text a hook row holds; refuses a row that is not a hook row."""
    kind = attachment.get("type")
    what = f"{kind} attachment"
    if kind == "hook_blocking_error":
        blocked = as_object(attachment.get("blockingError")).get("blockingError")
        if isinstance(blocked, str):
            return blocked
        raise PayloadRefused(f"{what} blockingError is not an object holding a string")
    if kind in ("hook_success", "hook_non_blocking_error"):
        return "\n".join(
            part for part in (opt_str(attachment.get("stdout")), opt_str(attachment.get("stderr"))) if part
        )
    if kind == "hook_additional_context":
        return "\n".join(_context_items(attachment, what))
    content = attachment.get("content")
    if kind == "hook_system_message" and isinstance(content, str):
        return content
    raise PayloadRefused("row is not a hook row")
