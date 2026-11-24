"""The recorded text of one item of an agent's own context, read from the transcript file of the agent."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.eventbus.port import TranscriptAdapter
from reporails_cli.core.eventbus.transcript import adapter_for, file_rows, find_row, owner_path
from reporails_cli.core.platform.dto.events import MessageText, RequestChain

# The kinds of text a request's own messages hold; any other kind is a listing, under the item it belongs to.
_MESSAGE_KINDS = ("notes", "thinking")


def _shape_text(adapter: TranscriptAdapter, path: Path, request_id: str, item: str) -> list[str] | None:
    """The system prompt or the tool definitions of the request `request_id` of file `path`, as one text; None when
    the file holds no such request or shape, or the item is neither."""
    request = find_row(path, request_id, lambda row: (adapter.resolve_request(row) or ("", ""))[0] == request_id)
    ref = None if request is None else adapter.resolve_request(request)
    if ref is None:
        return None
    shape = find_row(path, ref[1], lambda row: adapter.resolve_shape_text(row, ref[1], item) is not None)
    text = None if shape is None else adapter.resolve_shape_text(shape, ref[1], item)
    return None if text is None else [text]


def _item_texts(blocks: list[MessageText], item: str) -> list[str]:
    """The texts of `item` among a request's blocks: its own listing, the thinking with text, or, for the other
    messages, the notes that no listing's text is in."""
    if item == "thinking":
        return [text for kind, text in blocks if kind == "thinking" and text]
    if item != "harness_other":
        return [text for kind, text in blocks if kind == item]
    listed = [text for kind, text in blocks if kind not in _MESSAGE_KINDS]
    return [text for kind, text in blocks if kind == "notes" and not any(known in text for known in listed)]


def _chain_text(
    adapter: TranscriptAdapter, path: Path, subagent_id: str | None, request_id: str, item: str
) -> list[str] | None:
    """The text of `item` in the request `request_id` of file `path`, read by walking the file's rows through the
    adapter's request chain up to that request; None when the file holds no such request or cannot be read."""
    chain = RequestChain(texts={})
    for row in file_rows(path):
        sized = [record.request for record in adapter.resolve_row(row, subagent_id, chain)]
        if any(size is not None and size.request_id == request_id for size in sized):
            return _item_texts(adapter.request_blocks(chain), item)
    return None


def context_text(
    agent: str, session_file: Path, subagent_id: str | None, request_id: str, item: str
) -> list[str] | None:
    """The texts of one item of an agent's own context in the request `request_id` its size was measured from, read
    from the agent's own transcript file: the system prompt, the tool definitions (each with its description), a
    listing, the session context, the thinking, or the other messages, each as the characters the request holds. None
    when the file holds no such request or the item has no recorded text; an empty list for thinking with no readable
    text (signed blocks only).

    Raises `PayloadRefused` when the agent is unknown or a row read is not the shape the adapter is pinned to. The
    text is returned, never stored."""
    adapter = adapter_for(agent)
    path = owner_path(session_file, subagent_id)
    match item:
        case "system_prompt" | "tool_definitions":
            return _shape_text(adapter, path, request_id, item)
        case _:
            return _chain_text(adapter, path, subagent_id, request_id, item)
