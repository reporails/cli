"""What each compaction did to the instruction files an agent had loaded before it."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.events import EventRecord, RequestSize
from reporails_cli.core.platform.dto.xray_build import SourceTable
from reporails_cli.core.platform.dto.xray_compaction import HELD_FILE_STATES, FileState, XrayFileState
from reporails_cli.core.platform.dto.xray_sources import INSTRUCTION_ARTIFACT_KINDS, SOURCE_KIND_OF_ARTIFACT
from reporails_cli.core.xray.derive import epoch
from reporails_cli.core.xray.graph.sources import for_path

_INSTRUCTION_SOURCE_KINDS = frozenset(SOURCE_KIND_OF_ARTIFACT[kind] for kind in INSTRUCTION_ARTIFACT_KINDS)


def _instruction_source(path: str, sources: SourceTable) -> str | None:
    """The id of the instruction file at `path`; None when it is another kind of source or none."""
    sid = for_path(sources, path)
    entry = sources.get(sid) if sid else None
    return entry.id if entry is not None and entry.kind in _INSTRUCTION_SOURCE_KINDS else None


def _state(
    source: str, reloaded: set[str], request: RequestSize | None, read: set[str], indirect: set[str]
) -> FileState:
    """The state of one file after a compaction: loaded again, its read result in the first request after it, or
    gone. A request that names a message the file never recorded, or no request at all, cannot settle it, nor can
    one settle a file that arrived beside the read of another file (`indirect`): the request holds no read result
    of its own path for it, kept or not."""
    if source in reloaded:
        return "reloaded"
    if request is None or request.unresolved:
        return "unknown"
    if source in indirect and source not in read:
        return "unknown"
    return "kept" if source in read else "dropped"


def file_states(records: Sequence[EventRecord], sources: SourceTable) -> list[tuple[XrayFileState, ...]]:
    """For each compaction among `records`, in time order, each instruction file loaded before it with its state
    after it. The loads that follow the compaction before the agent's next reply are its reloads; the first request
    after it holds the read results that survived. A file left in the context carries on to the next compaction."""
    held: set[str] = set()
    pending: tuple[float, tuple[str, ...]] | None = None
    reloaded: set[str] = set()
    indirect: set[str] = set()
    request: RequestSize | None = None
    done: list[tuple[float, tuple[XrayFileState, ...]]] = []

    def settle() -> None:
        nonlocal held
        if pending is None:
            return
        read = {sid for path in (request.reads if request else ()) if (sid := _instruction_source(path, sources))}
        states = tuple(XrayFileState(src, _state(src, reloaded, request, read, indirect)) for src in pending[1])
        done.append((pending[0], states))
        held = {item.source for item in states if item.state in HELD_FILE_STATES} | reloaded

    for record in records:
        if record.event == "post_compact":
            settle()
            moment = epoch(record.time)
            pending = None if moment is None else (moment, tuple(sorted(held)))
            reloaded, request = set(), None
        elif record.event == "assistant_usage" and pending is not None:
            settle()
            pending = None
        elif record.event == "api_request" and pending is not None and request is None:
            request = record.request
        elif record.event == "instruction_load" and record.load is not None:
            sid = _instruction_source(record.load.path, sources)
            if sid is not None:
                (reloaded if pending is not None else held).add(sid)
                (indirect.add if record.load.memory_type == "nested" else indirect.discard)(sid)
        elif record.event == "tool_call" and record.tool is not None and record.tool.category == "read":
            sid = _instruction_source(record.tool.path, sources) if record.tool.path and pending is None else None
            if sid is not None:
                held.add(sid)
                indirect.discard(sid)
    settle()
    return [states for _, states in sorted(done, key=lambda item: item[0])]
