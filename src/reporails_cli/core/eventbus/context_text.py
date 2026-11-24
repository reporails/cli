"""The recorded text of one item of an agent's own context, read from the transcript file of the agent."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.eventbus.port import ListingPieces, PayloadRefused, TranscriptAdapter
from reporails_cli.core.eventbus.transcript import adapter_for, file_rows, find_row, owner_path
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.events import (
    DELTA_KINDS,
    EventRecord,
    HarnessEntry,
    HarnessKind,
    MessageText,
    RequestChain,
)
from reporails_cli.core.platform.dto.xray_build import HarnessSlot
from reporails_cli.core.platform.dto.xray_own import LISTED

# How much of a message's characters the texts other rows count must make up for the message to be theirs.
_CLAIMED_SHARE = 0.5


class _Listing:
    """The text of one listing as its size counts it: the first row's entries, then the entries of each later row
    up to the first compaction, less the entries a later row removed."""

    def __init__(self, entry: HarnessEntry, pieces: ListingPieces) -> None:
        self.slot = HarnessSlot.of(entry)
        self.known: dict[str, str] = {}
        self.anonymous: list[str] = []
        self.take(pieces)

    def take(self, pieces: ListingPieces) -> None:
        """Keep the text of the entries of one row."""
        for name, text in pieces:
            if name is None:
                self.anonymous.append(text)
            else:
                self.known[name] = text

    def add(self, entry: HarnessEntry, pieces: ListingPieces) -> None:
        """Fold in a later row."""
        self.slot.add(entry)
        self.take(pieces)

    def texts(self) -> list[str]:
        """The text the listing holds now."""
        return [*self.anonymous, *(self.known[name] for name in self.slot.sizes if name in self.known)]


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


def _claimed(adapter: TranscriptAdapter, note: str, claims: set[str]) -> bool:
    """Whether the texts other rows count make up most of `note`."""
    body = adapter.context.resolve_note_body(note)
    return sum(len(claim) for claim in claims if claim in body) >= _CLAIMED_SHARE * len(body)


def _block_texts(adapter: TranscriptAdapter, blocks: list[MessageText], item: str, claims: set[str]) -> list[str]:
    """The texts of `item` among a request's blocks: the thinking with text, or, for the other messages, the notes
    that no row other than the other messages counts."""
    if item == "thinking":
        return [text for kind, text in blocks if kind == "thinking" and text]
    return [text for kind, text in blocks if kind == "notes" and not _claimed(adapter, text, claims)]


def _fold(
    adapter: TranscriptAdapter,
    row: JsonObject,
    records: list[EventRecord],
    listings: dict[HarnessKind, _Listing],
    *,
    compacted: bool,
) -> None:
    """Fold the listing an attachment row holds into `listings`, by the rule the size of a listing follows: the first
    row, then the later rows of a list kind until the first compaction."""
    listed = adapter.context.resolve_listing_text(row)
    if listed is None or listed[0] not in LISTED.values():
        return
    kind, pieces = listed
    entry = next((record.harness for record in records if record.harness and record.harness.kind == kind), None)
    if entry is None:
        return
    held = listings.get(kind)
    if held is None:
        listings[kind] = _Listing(entry, pieces)
    elif kind in DELTA_KINDS and not compacted:
        held.add(entry, pieces)


def _chain_text(
    adapter: TranscriptAdapter, path: Path, subagent_id: str | None, request_id: str, item: str
) -> list[str] | None:
    """The text of `item` in the request `request_id` of file `path`, read by walking the file's rows through the
    adapter's request chain up to that request; None when the file holds no such request or cannot be read. A row
    the adapter refuses is left out, as the view's own read leaves it out."""
    chain = RequestChain(texts={})
    listings: dict[HarnessKind, _Listing] = {}
    claims: set[str] = set()
    compacted = False
    for row in file_rows(path):
        try:
            records = adapter.resolve_row(row, subagent_id, chain)
            claims.update(adapter.context.resolve_claimed(row))
            _fold(adapter, row, records, listings, compacted=compacted)
        except PayloadRefused:
            continue
        compacted = compacted or any(record.event == "post_compact" for record in records)
        if any(record.request is not None and record.request.request_id == request_id for record in records):
            kind = next((listed for key, listed in LISTED.items() if key == item), None)
            if kind is not None:
                return listings[kind].texts() if kind in listings else []
            return _block_texts(adapter, adapter.request_blocks(chain), item, claims)
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
