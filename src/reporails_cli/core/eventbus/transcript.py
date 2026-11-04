"""Read a session transcript and its subagent files from byte offsets into event records."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable, Iterator
from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import claude_project_dir, claude_projects_dir
from reporails_cli.core.eventbus.adapters.claude_transcript import ClaudeTranscriptAdapter
from reporails_cli.core.eventbus.port import (
    PayloadRefused,
    TranscriptAdapter,
    get_transcript_adapter,
    register_transcript,
    utc_now,
)
from reporails_cli.core.eventbus.store import UNSAFE_ID_CHARS
from reporails_cli.core.eventbus.tail import read_appended_lines
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object
from reporails_cli.core.platform.dto.events import CallDetail, EventRecord, FileCursor, TranscriptCursor

_SUBAGENT_PREFIX = "agent-"
# How many of a project's transcripts the session listing keeps.
RECENT_SESSIONS = 20
# How many characters of a call's input and of its result a call lookup returns.
CALL_INPUT_CHARS = 4000
CALL_RESULT_CHARS = 4000

register_transcript(ClaudeTranscriptAdapter())


def session_transcript(project_root: Path, session_id: str) -> Path:
    """The transcript file of one session of the project."""
    return claude_project_dir(project_root) / f"{session_id}.jsonl"


def known_session(project_root: Path, session_id: str) -> Path | None:
    """The transcript of session `session_id` of the project; None unless the id holds only letters, digits,
    `_` and `-` and its transcript is a file."""
    if not session_id or UNSAFE_ID_CHARS.search(session_id):
        return None
    path = session_transcript(project_root, session_id)
    return path if path.is_file() else None


def session_anywhere(session_id: str) -> Path | None:
    """The transcript of session `session_id` in any project folder of the agent; None unless the id holds only
    letters, digits, `_` and `-` and a folder holds its transcript."""
    if not session_id or UNSAFE_ID_CHARS.search(session_id):
        return None
    try:
        return next((path for path in claude_projects_dir().glob(f"*/{session_id}.jsonl") if path.is_file()), None)
    except OSError:
        # Best-effort lookup: an unreadable session folder means no session.
        return None


def recent_sessions(project_root: Path) -> list[Path]:
    """The project's transcripts, the most recently written first, at most `RECENT_SESSIONS`."""
    try:
        files = [path for path in claude_project_dir(project_root).glob("*.jsonl") if path.is_file()]
    except OSError:
        return []
    written = {path: last_write(path) or 0.0 for path in files}
    return sorted(files, key=lambda path: written[path], reverse=True)[:RECENT_SESSIONS]


def newest_session(project_root: Path) -> Path | None:
    """The most recently written transcript of the project, or None when it has none."""
    return next(iter(recent_sessions(project_root)), None)


def subagent_count(session_file: Path) -> int:
    """How many subagent files the session has."""
    return len(_files(session_file)) - 1


def _main_rows(path: Path) -> Iterator[JsonObject]:
    """The rows of the main transcript in order, from the head; an undecodable line is skipped."""
    with contextlib.suppress(OSError), path.open("rb") as handle:
        for line in handle:
            with contextlib.suppress(ValueError):
                yield as_object(json.loads(line))


def session_start(agent: str, session_file: Path) -> str | None:
    """The time of the first record the main transcript's rows resolve to; None when the agent is unknown or no
    row resolves to a timed record."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        return None
    for row in _main_rows(session_file):
        with contextlib.suppress(PayloadRefused):
            timed = next((record.time for record in adapter.resolve_row(row, None) if record.time), None)
            if timed is not None:
                return timed
    return None


def session_cwd(agent: str, session_file: Path) -> str | None:
    """The folder the session's first row that records one says the agent ran in; None when the agent is unknown
    or no row records one."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        return None
    for row in _main_rows(session_file):
        with contextlib.suppress(PayloadRefused):
            folder = next((record.cwd for record in adapter.resolve_row(row, None) if record.cwd), None)
            if folder is not None:
                return folder
    return None


def first_prompt_text(agent: str, session_file: Path) -> str | None:
    """The text of the first typed prompt of the main transcript; None when the agent is unknown or there is
    none. A row the adapter refuses is skipped. The text is returned, never stored."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        return None
    for row in _main_rows(session_file):
        try:
            if any(record.prompt is not None for record in adapter.resolve_row(row, None)):
                return adapter.resolve_prompt(row)
        except PayloadRefused:
            continue
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


def _subagent_dir(session_file: Path) -> Path:
    return session_file.with_suffix("") / "subagents"


def _files(session_file: Path) -> list[tuple[str | None, Path]]:
    """The main transcript (`None`) and each subagent file below it, with the subagent's id."""
    files: list[tuple[str | None, Path]] = [(None, session_file)]
    with contextlib.suppress(OSError):
        files.extend(
            (path.stem.removeprefix(_SUBAGENT_PREFIX), path)
            for path in sorted(_subagent_dir(session_file).glob(f"{_SUBAGENT_PREFIX}*.jsonl"))
        )
    return files


def last_write(session_file: Path) -> float | None:
    """When the transcript or any of its subagent files was last written, in seconds since 1970; None when none can
    be read."""
    written: list[float] = []
    for _, path in _files(session_file):
        with contextlib.suppress(OSError):
            written.append(path.stat().st_mtime)
    return max(written, default=None)


def subagent_brief(agent: str, session_file: Path, subagent_id: str) -> str | None:
    """The brief one subagent was given, or None when the session has no such subagent file.

    Raises `PayloadRefused` when the agent is unknown or the file's first row is not the shape the
    adapter is pinned to. The text is returned, never stored."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        raise PayloadRefused(f"unknown agent: {agent}")
    first_row = _first_row(_subagent_dir(session_file) / f"{_SUBAGENT_PREFIX}{subagent_id}.jsonl")
    return None if first_row is None else adapter.resolve_brief(first_row)


def subagent_system(agent: str, session_file: Path, subagent_id: str | None) -> str | None:
    """The system prompt the first request of one subagent was sent with, or None when the session has no such
    subagent file or the file records no request with its shape. With no subagent id, the system prompt of the
    last request the main transcript records.

    Raises `PayloadRefused` when the agent is unknown or a request or shape row is not the shape the adapter is
    pinned to. The text is returned, never stored."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        raise PayloadRefused(f"unknown agent: {agent}")
    path = (
        session_file if subagent_id is None else _subagent_dir(session_file) / f"{_SUBAGENT_PREFIX}{subagent_id}.jsonl"
    )
    request = _find_row(
        path,
        '"api-request"',
        lambda row: adapter.resolve_request_shape(row) is not None,
        latest=subagent_id is None,
    )
    shape_hash = None if request is None else adapter.resolve_request_shape(request)
    if shape_hash is None:
        return None
    shape = _find_row(path, shape_hash, lambda row: adapter.resolve_system(row, shape_hash) is not None)
    return None if shape is None else adapter.resolve_system(shape, shape_hash)


def prompt_text(agent: str, session_file: Path, prompt_id: str) -> str | None:
    """The text of the typed prompt written as row `prompt_id` of the main transcript, or None when the file
    holds no such row.

    Raises `PayloadRefused` when the agent is unknown or the row is not a typed prompt of the pinned shape.
    The text is returned, never stored."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        raise PayloadRefused(f"unknown agent: {agent}")
    row = _find_row(session_file, prompt_id, lambda row: row.get("uuid") == prompt_id)
    return None if row is None else adapter.resolve_prompt(row)


def hook_output_text(agent: str, session_file: Path, subagent_id: str | None, row_id: str) -> str | None:
    """The text the hook row `row_id` holds, from the main transcript (`subagent_id` None) or that subagent's
    file, or None when the file holds no such row.

    Raises `PayloadRefused` when the agent is unknown or the row is not a hook row of the pinned shape. The text is
    returned, never stored."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        raise PayloadRefused(f"unknown agent: {agent}")
    path = (
        session_file if subagent_id is None else _subagent_dir(session_file) / f"{_SUBAGENT_PREFIX}{subagent_id}.jsonl"
    )
    row = _find_row(path, row_id, lambda found: found.get("uuid") == row_id)
    return None if row is None else adapter.resolve_hook_output(row)


def call_detail(
    agent: str, session_file: Path, subagent_id: str | None, use_id: str, tool: str, *, shell: bool
) -> CallDetail | None:
    """Tool call `use_id` as the page asks for it, from the main transcript (`subagent_id` None) or that
    subagent's file: its input as indented JSON, its result as an excerpt, and for a `shell` call its command.
    Input and result are cut at `CALL_INPUT_CHARS` and `CALL_RESULT_CHARS`. None when the file holds no
    assistant row with such a call.

    Raises `PayloadRefused` when the agent is unknown or the call or its result is not the pinned shape. The text
    is returned, never stored."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        raise PayloadRefused(f"unknown agent: {agent}")
    path = (
        session_file if subagent_id is None else _subagent_dir(session_file) / f"{_SUBAGENT_PREFIX}{subagent_id}.jsonl"
    )
    row, answer = _find_call_rows(
        path, use_id, lambda found: adapter.holds_call(found, use_id), lambda found: adapter.holds_result(found, use_id)
    )
    if row is None:
        return None
    text = adapter.resolve_call(row, use_id) if shell else None
    full_input = json.dumps(adapter.resolve_call_input(row, use_id), indent=2, ensure_ascii=False)
    full_result = None if answer is None else adapter.resolve_result(answer, use_id)
    cut = len(full_input) > CALL_INPUT_CHARS or (full_result is not None and len(full_result) > CALL_RESULT_CHARS)
    shown_result = None if full_result is None else full_result[:CALL_RESULT_CHARS]
    return CallDetail(tool, text, full_input[:CALL_INPUT_CHARS], shown_result, cut)


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
            resolved = adapter.resolve_row(row, before.subagent_id, before.requests)
        except PayloadRefused as err:
            records.append(_refusal(agent, session_id, f"{path.name}: {err.reason}"))
            continue
        for record in resolved:
            if record.usage is not None:
                if record.usage.message_id == last_id:
                    continue
                last_id = record.usage.message_id
            records.append(record)
    return records, FileCursor(
        before.subagent_id,
        offset,
        last_id,
        before.run_settled or before.subagent_id is None or run is not None,
        before.requests,
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


def _find_row(
    path: Path, needle: str, matches: Callable[[JsonObject], bool], *, latest: bool = False
) -> JsonObject | None:
    """The first row of a file that holds `needle` and that `matches` accepts, or the last when `latest`; None
    when none does or the file cannot be read."""
    raw = needle.encode()
    found: JsonObject | None = None
    try:
        with path.open("rb") as handle:
            for line in handle:
                if raw not in line:
                    continue
                with contextlib.suppress(ValueError):
                    row = as_object(json.loads(line))
                    if matches(row):
                        if not latest:
                            return row
                        found = row
    except OSError:
        return None
    return found


def _find_call_rows(
    path: Path, needle: str, is_call: Callable[[JsonObject], bool], is_result: Callable[[JsonObject], bool]
) -> tuple[JsonObject | None, JsonObject | None]:
    """The first row of a file that holds `needle` and `is_call` accepts, and the first row after it that `is_result`
    accepts, found in one pass; either is None when the file holds none or cannot be read."""
    raw = needle.encode()
    call: JsonObject | None = None
    try:
        with path.open("rb") as handle:
            for line in handle:
                if raw not in line:
                    continue
                with contextlib.suppress(ValueError):
                    row = as_object(json.loads(line))
                    if call is None and is_call(row):
                        call = row
                    elif call is not None and is_result(row):
                        return call, row
    except OSError:
        return None, None
    return call, None


def _meta(path: Path) -> JsonObject | None:
    """The subagent's `agent-<id>.meta.json` object; None while the file is absent or not yet whole JSON."""
    try:
        return as_object(json.loads(path.with_suffix(".meta.json").read_bytes()))
    except (OSError, ValueError):
        return None


def _refusal(agent: str, session_id: str, reason: str) -> EventRecord:
    return EventRecord(agent=agent, event="refusal", session_id=session_id, time=utc_now(), refusal=reason)
