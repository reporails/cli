"""Read a session transcript and its subagent files from byte offsets into event records."""

from __future__ import annotations

import contextlib
import json
from collections.abc import Callable, Iterator
from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import claude_project_dir, claude_projects_dir
from reporails_cli.core.eventbus.adapters.claude_calls import HANDBACK_TOOL
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
from reporails_cli.core.platform.dto.events import (
    ASSISTANT_ROW_KINDS,
    EventKind,
    EventRecord,
    FileCursor,
    TranscriptCursor,
)
from reporails_cli.core.platform.dto.transcript import CallDetail, SummarySpan
from reporails_cli.core.platform.dto.workflows import WorkflowRefused, WorkflowRun
from reporails_cli.core.platform.dto.xray_graph import OutputSource

_SUBAGENT_PREFIX = "agent-"
_WORKFLOWS = "workflows"
_JOURNAL = "journal.jsonl"
# How many of a project's transcripts the session listing keeps.
RECENT_SESSIONS = 20
# How many characters of a call's input and of its result a call lookup returns.
CALL_INPUT_CHARS = 4000
CALL_RESULT_CHARS = 4000

register_transcript(ClaudeTranscriptAdapter())


def adapter_for(agent: str) -> TranscriptAdapter:
    """The transcript adapter registered for `agent`; raises `PayloadRefused` for an unknown agent."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        raise PayloadRefused(f"unknown agent: {agent}")
    return adapter


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


def file_rows(path: Path) -> Iterator[JsonObject]:
    """The rows of a transcript file in order, from the head; an undecodable line is skipped."""
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
    for row in file_rows(session_file):
        with contextlib.suppress(PayloadRefused):
            timed = next((record.time for record in adapter.resolve_row(row, None) if record.time), None)
            if timed is not None:
                return timed
    return None


def first_row_time(agent: str, session_file: Path) -> str | None:
    """The time of the first row of the main transcript that records one; None when the agent is unknown or no row
    records one."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        return None
    return next((timed for timed in map(adapter.row_time, file_rows(session_file)) if timed is not None), None)


def session_cwd(agent: str, session_file: Path) -> str | None:
    """The folder the session's first row that records one says the agent ran in; None when the agent is unknown
    or no row records one."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        return None
    for row in file_rows(session_file):
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
    for row in file_rows(session_file):
        try:
            if any(record.prompt is not None for record in adapter.resolve_row(row, None)):
                return adapter.resolve_prompt(row)
        except PayloadRefused:
            continue
    return None


def opens_with_clear(agent: str, session_file: Path) -> bool:
    """Whether the first row of the main transcript that the agent's adapter reads as opening the conversation is
    its `/clear` command; False when the agent is unknown or the transcript has no such row."""
    adapter = get_transcript_adapter(agent)
    if adapter is None:
        return False
    opened = (adapter.opens_with_clear(row) for row in file_rows(session_file))
    return next((verdict for verdict in opened if verdict is not None), False)


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


def _run_dirs(session_file: Path) -> list[Path]:
    """The folders of the session's workflow runs, each named by its run id."""
    with contextlib.suppress(OSError):
        return sorted(path for path in (_subagent_dir(session_file) / _WORKFLOWS).iterdir() if path.is_dir())
    return []


def _run_records(session_file: Path) -> list[Path]:
    """The run record files of the session's workflow runs, each named `<run id>.json`."""
    with contextlib.suppress(OSError):
        return sorted((session_file.with_suffix("") / _WORKFLOWS).glob("*.json"))
    return []


def _files(session_file: Path) -> list[tuple[str | None, Path]]:
    """The main transcript (`None`) and each subagent file below it, with the subagent's id: the session's own
    subagents, then the agents of each workflow run."""
    files: list[tuple[str | None, Path]] = [(None, session_file)]
    pattern = f"{_SUBAGENT_PREFIX}*.jsonl"
    with contextlib.suppress(OSError):
        folders = [_subagent_dir(session_file), *_run_dirs(session_file)]
        files.extend(
            (path.stem.removeprefix(_SUBAGENT_PREFIX), path)
            for folder in folders
            for path in sorted(folder.glob(pattern))
        )
    return files


def _workflow_of(path: Path) -> str | None:
    """The id of the workflow run whose folder holds the subagent file `path`; None for any other file."""
    return path.parent.name if path.parent.parent.name == _WORKFLOWS else None


def last_write(session_file: Path, *, main_only: bool = False) -> float | None:
    """When the transcript, any of its subagent files, or any workflow run's journal or record file was last
    written, in seconds since 1970; with `main_only`, the transcript alone. None when none can be read."""
    written: list[float] = []
    runs = (
        [] if main_only else [*(folder / _JOURNAL for folder in _run_dirs(session_file)), *_run_records(session_file)]
    )
    files = _files(session_file)[:1] if main_only else _files(session_file)
    for path in [*(path for _, path in files), *runs]:
        with contextlib.suppress(OSError):
            written.append(path.stat().st_mtime)
    return max(written, default=None)


def subagent_brief(agent: str, session_file: Path, subagent_id: str) -> str | None:
    """The brief one subagent was given, or None when the session has no such subagent file.

    Raises `PayloadRefused` when the agent is unknown or the file's first row is not the shape the
    adapter is pinned to. The text is returned, never stored."""
    adapter = adapter_for(agent)
    first_row = _first_row(owner_path(session_file, subagent_id))
    return None if first_row is None else adapter.resolve_brief(first_row)


def subagent_output(
    agent: str, session_file: Path, subagent_id: str, source: OutputSource, use_id: str | None
) -> str | None:
    """The text one subagent handed back, read from `source`: the first hand-back call of its file, or for an agent
    of a workflow run the output the run's journal says it accepted (`handback`), the text of the last assistant row
    of its file when that row holds no tool call (`reply`), or the result of the launching call `use_id` in the
    transcript file that holds it (`result`). None when the source holds no text.

    For `reply` a row the adapter refuses is skipped, so the last readable reply counts; `handback` and `result`
    raise `PayloadRefused` on a row that is not the shape the adapter is pinned to.

    Raises `PayloadRefused` when the agent is unknown, the source is `result` and no launching call is named, or a
    `handback` or `result` row read is not the shape the adapter is pinned to. The text is returned, never stored."""
    adapter = adapter_for(agent)
    path = owner_path(session_file, subagent_id)
    if source == "handback" and _workflow_of(path) is not None:
        handed = (adapter.resolve_handback(row, subagent_id) for row in _journal(path.parent))
        return next((text for text in handed if text is not None), None)
    if source == "handback":
        row = find_row(path, HANDBACK_TOOL, lambda found: adapter.resolve_handback(found, subagent_id) is not None)
        return None if row is None else adapter.resolve_handback(row, subagent_id)
    if source == "reply":
        return _last_reply(adapter, path, subagent_id)
    if use_id is None:
        raise PayloadRefused("the subagent's launching call is not named")
    for _, file in _files(session_file):
        row = find_row(file, use_id, lambda found: adapter.holds_result(found, use_id))
        if row is not None:
            return adapter.resolve_result(row, use_id)
    return None


def _last_reply(adapter: TranscriptAdapter, path: Path, subagent_id: str) -> str | None:
    """The text of the last assistant row of a subagent file that carries text or a tool call, None when that row
    is a tool call or the file cannot be read. A row the adapter refuses is skipped."""

    def last_kind(row: JsonObject) -> EventKind | None:
        try:
            kinds = [r.event for r in adapter.resolve_row(row, subagent_id) if r.event in ASSISTANT_ROW_KINDS]
        except PayloadRefused:
            return None
        return kinds[-1] if kinds else None

    row = find_row(path, '"assistant"', lambda found: last_kind(found) is not None, latest=True)
    if row is None or last_kind(row) != "assistant_text":
        return None
    return adapter.resolve_reply(row)


def prompt_text(agent: str, session_file: Path, prompt_id: str) -> str | None:
    """The text of the typed prompt written as row `prompt_id` of the main transcript, or None when the file
    holds no such row.

    Raises `PayloadRefused` when the agent is unknown or the row is not a typed prompt of the pinned shape.
    The text is returned, never stored."""
    adapter = adapter_for(agent)
    row = find_row(session_file, prompt_id, lambda row: row.get("uuid") == prompt_id)
    return None if row is None else adapter.resolve_prompt(row)


def scan_compact_summaries(
    agent: str, session_file: Path, subagent_id: str | None, offset: int
) -> tuple[list[SummarySpan], int]:
    """The compaction summaries in the lines of one transcript file appended since byte `offset`, each with the id
    of the boundary row it follows and the byte range of its line, and the offset just past the lines read; a torn
    last line waits for the next read. A summary row that names no boundary is left out.

    Raises `PayloadRefused` when the agent is unknown. Only sizes and positions are returned, never text."""
    adapter = adapter_for(agent)
    lines, end = read_appended_lines(owner_path(session_file, subagent_id), offset)
    spans: list[SummarySpan] = []
    start = offset
    for line in lines:
        stop = start + len(line)
        found = _summary_row(adapter, line)
        if found is not None and found[0] is not None:
            spans.append(SummarySpan(found[0], len(found[1]), start, stop))
        start = stop + 1
    return spans, end


def compact_summary(agent: str, session_file: Path, subagent_id: str | None, span: SummarySpan) -> str | None:
    """The text of the compaction summary at `span` of the main transcript (`subagent_id` None) or that subagent's
    file, reading only that line; None when the file no longer holds a summary there, or one that follows another
    boundary than `span.link`.

    Raises `PayloadRefused` when the agent is unknown. The text is returned, never stored."""
    adapter = adapter_for(agent)
    lines, _ = read_appended_lines(owner_path(session_file, subagent_id), span.start, span.end + 1)
    found = _summary_row(adapter, lines[0]) if lines else None
    return None if found is None or found[0] != span.link else found[1]


def owner_path(session_file: Path, subagent_id: str | None) -> Path:
    """The main transcript, or the file of one subagent: one of the session's own or of a workflow run's agents.
    A subagent id no file has resolves to the path of a session subagent that is not there."""
    if subagent_id is None:
        return session_file
    found = next((path for known, path in _files(session_file) if known == subagent_id), None)
    return found or _subagent_dir(session_file) / f"{_SUBAGENT_PREFIX}{subagent_id}.jsonl"


def _summary_row(adapter: TranscriptAdapter, line: bytes) -> tuple[str | None, str] | None:
    """The boundary id and the text of a transcript line that is a compaction summary row; None for any other
    line."""
    if b'"isCompactSummary"' not in line:
        return None
    with contextlib.suppress(ValueError):
        row = as_object(json.loads(line))
        text = adapter.resolve_compact_summary(row)
        return None if text is None else (adapter.resolve_compact_link(row), text)
    return None


def hook_output_text(agent: str, session_file: Path, subagent_id: str | None, row_id: str) -> str | None:
    """The text the hook row `row_id` holds, from the main transcript (`subagent_id` None) or that subagent's
    file, or None when the file holds no such row.

    Raises `PayloadRefused` when the agent is unknown or the row is not a hook row of the pinned shape. The text is
    returned, never stored."""
    adapter = adapter_for(agent)
    path = owner_path(session_file, subagent_id)
    row = find_row(path, row_id, lambda found: found.get("uuid") == row_id)
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
    adapter = adapter_for(agent)
    path = owner_path(session_file, subagent_id)
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


def workflow_runs(agent: str, session_file: Path) -> tuple[WorkflowRun | WorkflowRefused, ...]:
    """The workflow runs of the session, by run id: each run its record file holds, and each run that has an agent
    folder but no record file yet as a running run built from its journal and its agents' meta files.

    A run whose record file or an agent meta file is not JSON, or whose record is not the shape the adapter is
    pinned to, comes back as a `WorkflowRefused` naming what was wrong; the other runs are still read. A file that
    is absent counts as not written yet. Raises `PayloadRefused` when the agent is unknown."""
    adapter = adapter_for(agent)
    records = {path.stem: path for path in _run_records(session_file)}
    folders = {folder.name: folder for folder in _run_dirs(session_file)}
    runs: list[WorkflowRun | WorkflowRefused] = []
    for run_id in sorted({*records, *folders}):
        try:
            runs.append(_workflow_run(adapter, run_id, records.get(run_id), folders.get(run_id)))
        except PayloadRefused as refused:
            runs.append(WorkflowRefused(run_id, str(refused)))
    return tuple(runs)


def _workflow_run(adapter: TranscriptAdapter, run_id: str, record: Path | None, folder: Path | None) -> WorkflowRun:
    """The run `run_id`, from its record file and its agent folder; raises `PayloadRefused` for a file it cannot
    read."""
    journal = [] if folder is None else _journal(folder)
    paths = (
        {}
        if folder is None
        else {
            path.stem.removeprefix(_SUBAGENT_PREFIX): path for path in sorted(folder.glob(f"{_SUBAGENT_PREFIX}*.jsonl"))
        }
    )
    metas = {
        agent_id: meta
        for agent_id, path in paths.items()
        if (meta := _json_object(path.with_suffix(".meta.json"))) is not None
    }
    return adapter.resolve_workflow_run(run_id, None if record is None else _json_object(record), journal, metas)


def _journal(folder: Path) -> list[JsonObject]:
    """The rows of the journal in a workflow run's agent folder; none while it is not written."""
    return _rows(read_appended_lines(folder / _JOURNAL, 0)[0])


def _json_object(path: Path) -> JsonObject | None:
    """The JSON object a file holds; None while the file is absent. Raises `PayloadRefused` for a file that is not
    JSON or not an object."""
    try:
        return as_object(json.loads(path.read_bytes()))
    except OSError:
        return None
    except ValueError as err:
        raise PayloadRefused(f"{path.name} is not readable JSON: {err}") from err


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
    None while the first row or the meta file is not there yet or not yet whole JSON."""
    first_row = rows[0] if before.offset == 0 and rows else _first_row(path)
    try:
        meta = _json_object(path.with_suffix(".meta.json"))
    except PayloadRefused:
        return None
    if first_row is None or meta is None:
        return None
    try:
        return adapter.resolve_subagent(before.subagent_id or "", meta, first_row, _workflow_of(path))
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


def find_row(
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


def _refusal(agent: str, session_id: str, reason: str) -> EventRecord:
    return EventRecord(agent=agent, event="refusal", session_id=session_id, time=utc_now(), refusal=reason)
