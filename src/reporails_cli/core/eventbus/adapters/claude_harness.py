"""Reading the harness attachments of a Claude Code transcript: how each is sized, the text that size counts, and the
texts other rows of the page count.

`prompt_snapshot` (`systemPrompt`, a list of strings), `skill_listing` (`skillCount`, a whole number, `content`, a
string, and optionally `names`, a list of strings), `agent_listing_delta` (`addedTypes` and `addedLines`, lists of
strings), `mcp_instructions_delta` (`addedNames` and `addedBlocks`, lists of strings), `deferred_tools_delta`
(`addedNames` and `addedLines`, lists of strings, or in a subagent file `content`, a string) and `session_context`
(`context`, an object of strings) are counted; delta rows may also carry `removedTypes` or `removedNames`, lists of
strings, counted off their item count. A field of another shape is refused.
"""

from __future__ import annotations

from reporails_cli.core.eventbus.adapters.claude_hooks import HOOK_NOTE_ATTACHMENTS, hook_note_texts
from reporails_cli.core.eventbus.adapters.claude_requests import note_body
from reporails_cli.core.eventbus.adapters.claude_rows import sized_by_name, string_list
from reporails_cli.core.eventbus.port import ListingPieces, PayloadRefused
from reporails_cli.core.platform.contract.json_value import (
    JsonObject,
    as_list,
    as_object,
    opt_int,
    opt_str,
    strict_str_list,
)
from reporails_cli.core.platform.dto.events import UNLISTED_KINDS, HarnessAttachment, HarnessEntry, HarnessKind

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

_UNSIZED = frozenset(
    {"environment", "auto_mode", "plan_mode", "task_reminder", "silent_turn_reminder", "credential_org", "date"}
)


def _listing(attachment: JsonObject, kind: str) -> tuple[HarnessEntry, ListingPieces]:
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
        pieces: ListingPieces = ((None, text),)
    else:
        items = string_list(text, spec.chars_key, what)
        chars = sum(len(item) for item in items)
        if spec.removed_key is not None:
            added = sized_by_name(names, items, (), what)
        pieces = tuple(zip(names, items, strict=True)) if added else tuple((None, item) for item in items)
    removed = _removed_names(attachment, spec.removed_key, what)
    listed = (
        tuple(string_list(attachment["names"], "names", what))
        if kind == "skill_listing" and "names" in attachment
        else None
    )
    entry = HarnessEntry(spec.kind, spec.label, count - len(removed), chars, added=added, removed=removed, names=listed)
    return entry, pieces


def _removed_names(attachment: JsonObject, key: str | None, what: str) -> tuple[str, ...]:
    """The names a delta row removed; none when the row does not carry the list."""
    if key is None or key not in attachment:
        return ()
    return tuple(string_list(attachment.get(key), key, what))


def _failed_servers(attachment: JsonObject, what: str) -> tuple[str, ...]:
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


def _deferred_tools(attachment: JsonObject) -> tuple[HarnessEntry, ListingPieces]:
    what = "deferred_tools_delta attachment"
    if "content" in attachment:
        content = attachment.get("content")
        if not isinstance(content, str):
            raise PayloadRefused(f"{what} content is not a string")
        return HarnessEntry("deferred_tools", "deferred tools", None, len(content)), ((None, content),)
    names = string_list(attachment.get("addedNames"), "addedNames", what)
    lines = string_list(attachment.get("addedLines"), "addedLines", what)
    removed = _removed_names(attachment, "removedNames", what)
    readded = _removed_names(attachment, "readdedNames", what)
    added = sized_by_name(names, lines, readded, what)
    entry = HarnessEntry(
        "deferred_tools",
        "deferred tools",
        len(names) - len(removed),
        sum(len(item) for item in lines),
        added=added,
        removed=removed,
        readded=() if added else tuple(names),
        pending=_removed_names(attachment, "pendingMcpServers", what),
        failed=_failed_servers(attachment, what),
    )
    return entry, tuple(zip(names, lines, strict=True)) if added else ()


def _session_context(attachment: JsonObject) -> tuple[HarnessEntry, ListingPieces]:
    context = attachment.get("context")
    if not isinstance(context, dict):
        raise PayloadRefused("session_context attachment context is not an object")
    values = strict_str_list(list(context.values()))
    if values is None:
        raise PayloadRefused("session_context attachment context is not an object of strings")
    chars = sum(len(value) for value in values)
    return HarnessEntry("session_context", "session context", None, chars), tuple((None, value) for value in values)


def harness_parts(attachment: JsonObject, kind: object) -> tuple[HarnessEntry, ListingPieces] | None:
    """The harness entry an attachment is sized as and the pieces of text that size counts; None for an attachment
    that is neither."""
    if kind == "session_context":
        return _session_context(attachment)
    if kind == "deferred_tools_delta":
        return _deferred_tools(attachment)
    if isinstance(kind, str) and kind in _HARNESS:
        return _listing(attachment, kind)
    return (HarnessEntry("unsized", kind, None, 0), ()) if isinstance(kind, str) and kind in _UNSIZED else None


class ClaudeContextReader:
    """Reads the text a Claude Code attachment row puts into the agent's own context."""

    def resolve_listing_text(self, row: JsonObject) -> tuple[HarnessKind, ListingPieces] | None:
        """The kind and the pieces of text, each under its name, of an attachment row sized as a harness item;
        None for any other row."""
        attachment = as_object(row.get("attachment"))
        parts = harness_parts(attachment, attachment.get("type"))
        return None if parts is None else (parts[0].kind, parts[1])

    def resolve_claimed(self, row: JsonObject) -> list[str]:
        """The texts an attachment row puts into the context that a row other than the other messages counts: a
        hook's note, an instruction file's content, a listing. Empty for any other row."""
        attachment = as_object(row.get("attachment"))
        kind = attachment.get("type")
        if kind in HOOK_NOTE_ATTACHMENTS:
            found = hook_note_texts(attachment, opt_str(attachment.get("hookEvent")) or "")
            return [] if found is None else [text for text in found[1] if text]
        if kind == "instructions":
            files = (as_object(item).get("content") for item in as_list(attachment.get("files")))
            return [text for text in files if isinstance(text, str) and text]
        if kind == "nested_memory":
            text = as_object(attachment.get("content")).get("content")
            return [text] if isinstance(text, str) and text else []
        listed = self.resolve_listing_text(row)
        if listed is None or listed[0] in UNLISTED_KINDS:
            return []
        return [text for _, text in listed[1] if text]

    def resolve_note_body(self, text: str) -> str:
        """The text of a note without its `<system-reminder>` tags."""
        return note_body(text)
