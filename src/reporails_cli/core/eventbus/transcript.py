"""Read a session transcript and its subagent files from byte offsets into event records."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import claude_project_dir
from reporails_cli.core.eventbus.adapters.claude_transcript import ClaudeTranscriptAdapter
from reporails_cli.core.eventbus.port import (
    PayloadRefused,
    TranscriptAdapter,
    get_transcript_adapter,
    register_transcript,
    utc_now,
)
from reporails_cli.core.eventbus.tail import read_appended_lines
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object
from reporails_cli.core.platform.dto.events import EventRecord, FileCursor, TranscriptCursor

_SUBAGENT_PREFIX = "agent-"

register_transcript(ClaudeTranscriptAdapter())


def session_transcript(project_root: Path, session_id: str) -> Path:
    """The transcript file of one session of the project."""
    return claude_project_dir(project_root) / f"{session_id}.jsonl"


def newest_session(project_root: Path) -> Path | None:
    """The most recently written transcript of the project, or None when it has none."""
    folder = claude_project_dir(project_root)
    try:
        files = [path for path in folder.glob("*.jsonl") if path.is_file()]
        return max(files, key=lambda path: path.stat().st_mtime, default=None)
    except OSError:
        return None


def read_transcript(
    agent: str, session_file: Path, offsets: TranscriptCursor
) -> tuple[list[EventRecord], TranscriptCursor]:
    """The records the transcript and its subagent files hold past `offsets`, and the cursor to pass next.

    Each file is read through `read_appended_lines`, so a torn last line waits. An undecodable line is
    skipped; a row the adapter refuses becomes one `refusal` record."""
    session_id = session_file.stem
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        return [_refusal(agent, session_id, f"unknown agent: {agent}")], offsets
    records: list[EventRecord] = []
    cursor = offsets
    for subagent_id, path in _files(session_file):
        before = cursor.of(subagent_id) or FileCursor(subagent_id)
        fresh, after = _read_file(adapter, agent, session_id, path, before=before)
        records.extend(fresh)
        cursor = cursor.with_file(after)
    return records, cursor


def _files(session_file: Path) -> list[tuple[str | None, Path]]:
    """The main transcript (`None`) and each subagent file below it, with the subagent's id."""
    files: list[tuple[str | None, Path]] = [(None, session_file)]
    subagents = session_file.with_suffix("") / "subagents"
    with contextlib.suppress(OSError):
        files.extend(
            (path.stem.removeprefix(_SUBAGENT_PREFIX), path)
            for path in sorted(subagents.glob(f"{_SUBAGENT_PREFIX}*.jsonl"))
        )
    return files


def _read_file(
    adapter: TranscriptAdapter, agent: str, session_id: str, path: Path, *, before: FileCursor
) -> tuple[list[EventRecord], FileCursor]:
    """The records one file holds past `before`, a reply already recorded dropped, and where the read stopped."""
    lines, offset = read_appended_lines(path, before.offset)
    rows = _rows(lines)
    records: list[EventRecord] = []
    run = (
        None
        if before.run_settled or before.subagent_id is None
        else _run_record(adapter, agent, session_id, path, before=before, rows=rows)
    )
    if run is not None:
        records.append(run)
    last_id = before.last_message_id
    for row in rows:
        try:
            resolved = adapter.resolve_row(row, before.subagent_id)
        except PayloadRefused as err:
            records.append(_refusal(agent, session_id, err.reason))
            continue
        for record in resolved:
            if record.usage is not None:
                if record.usage.message_id == last_id:
                    continue
                last_id = record.usage.message_id
            records.append(record)
    return records, FileCursor(
        before.subagent_id, offset, last_id, before.run_settled or before.subagent_id is None or run is not None
    )


def _run_record(
    adapter: TranscriptAdapter, agent: str, session_id: str, path: Path, *, before: FileCursor, rows: list[JsonObject]
) -> EventRecord | None:
    """The `subagent_run` record of a subagent file, the refusal the adapter raises for its meta file, or
    None while the first row or the meta file is not there yet."""
    first_row = rows[0] if before.offset == 0 and rows else _first_row(path)
    meta = _meta(path)
    if first_row is None or meta is None:
        return None
    try:
        return adapter.resolve_subagent(before.subagent_id or "", meta, first_row)
    except PayloadRefused as err:
        return _refusal(agent, session_id, err.reason)


def _rows(lines: list[bytes]) -> list[JsonObject]:
    rows: list[JsonObject] = []
    for line in lines:
        with contextlib.suppress(ValueError):
            rows.append(as_object(json.loads(line)))
    return rows


def _first_row(path: Path) -> JsonObject | None:
    """The first row of a file, None when it cannot be read."""
    try:
        with path.open("rb") as handle:
            return as_object(json.loads(handle.readline()))
    except (OSError, ValueError):
        return None


def _meta(path: Path) -> JsonObject | None:
    """The subagent's `agent-<id>.meta.json` object; None while the file is absent or not yet whole JSON."""
    try:
        return as_object(json.loads(path.with_suffix(".meta.json").read_bytes()))
    except (OSError, ValueError):
        return None


def _refusal(agent: str, session_id: str, reason: str) -> EventRecord:
    return EventRecord(agent=agent, event="refusal", session_id=session_id, time=utc_now(), refusal=reason)
