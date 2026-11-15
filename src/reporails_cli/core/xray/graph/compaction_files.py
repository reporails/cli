"""What each compaction left of the instruction files an agent had loaded before it."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.events import CompactionPreserved, EventRecord
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


def _read_before(record: EventRecord, sources: SourceTable) -> set[str]:
    """The instruction file a read call targets, as a set of one source id; empty when it targets none."""
    sid = _instruction_source(record.tool.path, sources) if record.tool and record.tool.path else None
    return {sid} if sid is not None else set()


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


def file_states(records: Sequence[EventRecord], sources: SourceTable) -> list[tuple[XrayFileState, ...]]:
    """For each compaction among `records`, in time order, each instruction file loaded before it with its state
    after it. The loads and file attachments that follow the compaction before the agent's next reply settle its
    files, and so do the files read in the messages the compaction kept. A file whose content is in the context carries
    on to the next compaction."""
    held: set[str] = set()
    pending: tuple[float, tuple[str, ...], frozenset[str]] | None = None
    reloaded: set[str] = set()
    whole: set[str] = set()
    named: set[str] = set()
    read_in: dict[str, str] = {}
    done: list[tuple[float, tuple[XrayFileState, ...]]] = []

    def settle(*, waiting: bool = False) -> None:
        nonlocal held
        if pending is None:
            return
        kept = {
            sid
            for row_id in pending[2]
            if (path := read_in.get(row_id)) and (sid := _instruction_source(path, sources))
        }
        states = tuple(
            XrayFileState(src, _state(src, reloaded, whole | kept, named, waiting=waiting)) for src in pending[1]
        )
        done.append((pending[0], states))
        held = {item.source for item in states if item.state in IN_CONTEXT_FILE_STATES} | reloaded

    for record in records:
        if record.event == "post_compact":
            settle()
            moment = epoch(record.time)
            preserved = record.item.row_ids if isinstance(record.item, CompactionPreserved) else ()
            pending = None if moment is None else (moment, tuple(sorted(held)), frozenset(preserved))
            reloaded, whole, named = set(), set(), set()
        elif record.event == "assistant_usage" and pending is not None:
            settle()
            pending = None
        elif record.event == "instruction_load" and record.load is not None:
            sid = _instruction_source(record.load.path, sources)
            if sid is not None:
                (reloaded if pending is not None else held).add(sid)
        elif record.event == "file_attachment" and record.attachment is not None and pending is not None:
            sid = _instruction_source(record.attachment.path, sources)
            if sid is not None:
                (whole if record.attachment.whole else named).add(sid)
        elif record.event == "tool_call" and record.tool is not None and record.tool.category == "read":
            if record.tool.row_id and record.tool.path:
                read_in[record.tool.row_id] = record.tool.path
            held |= _read_before(record, sources) if pending is None else set()
    settle(waiting=True)
    return [states for _, states in sorted(done, key=lambda item: item[0])]
