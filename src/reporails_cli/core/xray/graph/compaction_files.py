"""What each compaction left of the instruction files an agent had loaded before it."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.attachments import (
    NAMED_ATTACHMENT_KINDS,
    WHOLE_FILE_ATTACHMENT_KINDS,
    AttachmentKind,
)
from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.xray_build import SourceTable
from reporails_cli.core.platform.dto.xray_compaction import IN_CONTEXT_FILE_STATES, FileState, XrayFileState
from reporails_cli.core.platform.dto.xray_sources import INSTRUCTION_ARTIFACT_KINDS, SOURCE_KIND_OF_ARTIFACT
from reporails_cli.core.xray.derive import epoch
from reporails_cli.core.xray.graph.sources import for_path

_INSTRUCTION_SOURCE_KINDS = frozenset(SOURCE_KIND_OF_ARTIFACT[kind] for kind in INSTRUCTION_ARTIFACT_KINDS)


def _instruction_source(path: str, sources: SourceTable) -> str | None:
    """The id of the instruction file at `path`; None when it is another kind of source or none."""
    sid = for_path(sources, path)
    entry = sources.get(sid) if sid else None
    return entry.id if entry is not None and entry.kind in _INSTRUCTION_SOURCE_KINDS else None


def _loaded_file(record: EventRecord, sources: SourceTable) -> tuple[str | None, str | None]:
    """The instruction file an `instruction_load` record or a read call names, with the transcript row it came
    from; `(None, None)` for any other record or a file that is not an instruction file."""
    if record.event == "instruction_load" and record.load is not None:
        return _instruction_source(record.load.path, sources), record.load.row_id
    if record.event == "tool_call" and record.tool is not None and record.tool.category == "read" and record.tool.path:
        return _instruction_source(record.tool.path, sources), record.tool.row_id
    return None, None


def _attached_file(record: EventRecord, sources: SourceTable) -> tuple[str | None, AttachmentKind | None]:
    """The instruction file a `file_attachment` record names and how it was attached; `(None, None)` for a record
    with no attachment, a file that is not an instruction file, or an edit snippet, which puts in no more than part of
    the file."""
    attachment = record.attachment
    if attachment is None or attachment.kind not in WHOLE_FILE_ATTACHMENT_KINDS | NAMED_ATTACHMENT_KINDS:
        return None, None
    return _instruction_source(attachment.path, sources), attachment.kind


def _compaction(record: EventRecord, held: set[str]) -> tuple[float, tuple[str, ...], frozenset[str]] | None:
    """A `post_compact` record as its time, the files held before it and the ids of the transcript rows it kept;
    None for a record with no readable time."""
    moment = epoch(record.time)
    if moment is None:
        return None
    return moment, tuple(sorted(held)), frozenset(() if record.boundary is None else record.boundary.kept)


def _state(source: str, reloaded: set[str], whole: set[str], named: set[str], *, waiting: bool) -> FileState:
    """The state of one file after a compaction: loaded again, attached whole or read in a message the compaction kept
    (`whole`), or only named (`named`). A file none of them holds is pending while the agent has not replied since the
    compaction (`waiting`), else summarized."""
    if source in reloaded:
        return "reloaded"
    if source in whole:
        return "restored"
    if source in named:
        return "named"
    return "pending" if waiting else "summarized"


def _attach(
    attached: str | None,
    how: AttachmentKind | None,
    *,
    compacting: bool,
    held: set[str],
    whole: set[str],
    named: set[str],
) -> None:
    """Record a file attachment: a named file as `named`, a whole file as `whole` while a compaction waits for the
    agent's next reply, else as `held`."""
    if attached is None or how is None:
        return
    if how in NAMED_ATTACHMENT_KINDS:
        named.add(attached)
    elif compacting:
        whole.add(attached)
    else:
        held.add(attached)


def _place(records: Sequence[EventRecord], moment: float) -> int:
    """How many compactions among `records` came before the one at `moment`."""
    return sum(
        1
        for record in records
        if record.event == "post_compact" and (found := epoch(record.time)) is not None and found < moment
    )


def file_states(
    records: Sequence[EventRecord], sources: SourceTable, regrouped: Sequence[frozenset[str]]
) -> list[tuple[XrayFileState, ...]]:
    """For each compaction among `records`, in time order, each instruction file loaded before it with its state
    after it. The loads and file attachments that follow the compaction before the agent's next reply settle its
    files, and so do the files read in the messages the compaction kept and the files `regrouped` holds for it (one
    set per compaction, in time order: the loads of a group its restart's hook firing caused, which count as loaded
    again). A file whose content is in the context carries on to the next compaction."""
    held: set[str] = set()
    pending: tuple[float, tuple[str, ...], frozenset[str]] | None = None
    reloaded: set[str] = set()
    whole: set[str] = set()
    named: set[str] = set()
    kept_in: dict[str | None, set[str]] = {}
    done: list[tuple[float, tuple[XrayFileState, ...]]] = []

    def settle(*, waiting: bool = False) -> None:
        nonlocal held
        if pending is None:
            return
        kept = {sid for row_id in kept_in.keys() & pending[2] for sid in kept_in[row_id]}
        back = reloaded | regrouped[_place(records, pending[0])]
        settled = [(src, _state(src, back, whole | kept, named, waiting=waiting)) for src in pending[1]]
        states = tuple(XrayFileState(src, state, state in IN_CONTEXT_FILE_STATES) for src, state in settled)
        done.append((pending[0], states))
        held = {item.source for item in states if item.state in IN_CONTEXT_FILE_STATES} | reloaded | whole

    for record in records:
        sid, row_id = _loaded_file(record, sources)
        if record.event == "post_compact":
            settle()
            pending = _compaction(record, held)
            reloaded, whole, named = set(), set(), set()
        elif record.event == "assistant_usage" and pending is not None:
            settle()
            pending = None
        elif sid is not None:
            kept_in.setdefault(row_id, set()).add(sid)
            if record.event == "instruction_load" and pending is not None:
                reloaded.add(sid)
            elif pending is None:
                held.add(sid)
        elif record.event == "file_attachment":
            _attach(
                *_attached_file(record, sources), compacting=pending is not None, held=held, whole=whole, named=named
            )
    settle(waiting=True)
    return [states for _, states in sorted(done, key=lambda item: item[0])]
