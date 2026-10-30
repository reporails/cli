"""Transcript reading: usage per assistant response, turn ends, subagent runs and instruction loads."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from reporails_cli.core.eventbus.transcript import read_transcript
from reporails_cli.core.platform.dto.events import EventRecord, TranscriptCursor

pytestmark = [pytest.mark.unit, pytest.mark.subsys_eventbus]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript"
VERSIONS = ["2.1.292", "2.1.301", "2.1.308"]
# The id of a response written as several rows, per version, and the counts the first one carries.
MULTI_ROW = {
    "2.1.292": ("msg_011Cg7bKBZpkQVnFBYzNB43E", (2, 23991, 13911)),
    "2.1.301": ("msg_011Cg8ACXPpjbPBiohByzaaQ", (2, 569, 25438)),
    "2.1.308": ("msg_011CgZ2f4i8X3Gk9apbYH945", None),
}
SUB_2_1_308 = "a27081343121455fb"


def _copy(version: str, tmp_path: Path) -> Path:
    shutil.copytree(FIXTURES / version, tmp_path / version)
    return tmp_path / version / "session.jsonl"


def _of(records: list[EventRecord], event: str) -> list[EventRecord]:
    return [record for record in records if record.event == event]


@pytest.mark.parametrize("version", VERSIONS)
def test_one_usage_record_per_response_per_agent(version: str, tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(version, tmp_path), TranscriptCursor())
    usage = _of(records, "assistant_usage")
    main_ids = [r.usage.message_id for r in usage if r.subagent_id is None and r.usage]
    sub_ids = [r.usage.message_id for r in usage if r.subagent_id is not None and r.usage]
    assert len(main_ids) == len(set(main_ids)) >= 2
    assert len(sub_ids) == len(set(sub_ids)) >= 1
    multi_id, counts = MULTI_ROW[version]
    assert main_ids.count(multi_id) == 1
    if counts is not None:
        (hit,) = [r for r in usage if r.usage and r.usage.message_id == multi_id]
        assert hit.usage is not None
        assert (
            hit.usage.input_tokens,
            hit.usage.cache_creation_input_tokens,
            hit.usage.cache_read_input_tokens,
        ) == counts
    assert not _of(records, "refusal")


@pytest.mark.parametrize("version", VERSIONS)
def test_subagent_run_carries_agent_type_from_meta(version: str, tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(version, tmp_path), TranscriptCursor())
    (run,) = _of(records, "subagent_run")
    meta = next((tmp_path / version / "session" / "subagents").glob("*.meta.json"))
    assert run.subagent_type == json.loads(meta.read_text())["agentType"]
    assert run.subagent_id is not None and meta.name == f"agent-{run.subagent_id}.meta.json"


def test_turn_end_reported(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy("2.1.301", tmp_path), TranscriptCursor())
    assert len(_of(records, "turn_end")) == 1


def test_instruction_loads_per_agent_in_2_1_308(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy("2.1.308", tmp_path), TranscriptCursor())
    loads = _of(records, "instruction_load")
    expected = [
        ("/work/proj/CLAUDE.md", "Project"),
        ("/home/user/.claude/projects/-work-proj/memory/MEMORY.md", "AutoMem"),
        ("/work/proj/sub/CLAUDE.md", "nested"),
    ]
    main = [(r.load.path, r.load.memory_type) for r in loads if r.subagent_id is None and r.load]
    sub = [(r.load.path, r.load.memory_type) for r in loads if r.subagent_id == SUB_2_1_308 and r.load]
    assert main == expected
    assert sub == expected


def test_resumed_read_emits_nothing_twice_and_picks_up_appended_rows(tmp_path: Path) -> None:
    session = _copy("2.1.301", tmp_path)
    first, cursor = read_transcript("claude", session, TranscriptCursor())
    again, cursor_again = read_transcript("claude", session, cursor)
    assert first and again == [] and cursor_again == cursor
    rows = [json.loads(line) for line in session.read_text().splitlines()]
    last = next(row for row in reversed(rows) if row["type"] == "assistant")
    usage = {**last["message"]["usage"], "input_tokens": 9}
    new = {**last, "message": {**last["message"], "id": "msg_NEW", "usage": usage}}
    # Another block of the last response, then a new response.
    with session.open("a", encoding="utf-8") as handle:
        handle.write("".join(json.dumps(row) + "\n" for row in (last, new)))
    appended, _ = read_transcript("claude", session, cursor)
    assert [(r.usage.message_id, r.usage.input_tokens) for r in appended] == [("msg_NEW", 9)]


def test_torn_last_line_waits(tmp_path: Path) -> None:
    session = _copy("2.1.301", tmp_path)
    _, cursor = read_transcript("claude", session, TranscriptCursor())
    row = {"type": "system", "subtype": "turn_duration", "timestamp": "2026-10-17T17:00:00.000Z", "sessionId": "s"}
    text = json.dumps(row)
    with session.open("a", encoding="utf-8") as handle:
        handle.write(text[:30])
    waiting, cursor = read_transcript("claude", session, cursor)
    assert waiting == []
    with session.open("a", encoding="utf-8") as handle:
        handle.write(text[30:] + "\n")
    done, _ = read_transcript("claude", session, cursor)
    assert [r.event for r in done] == ["turn_end"]


def test_non_int_usage_is_a_refusal(tmp_path: Path) -> None:
    session = _copy("2.1.301", tmp_path)
    rows = [json.loads(line) for line in session.read_text().splitlines()]
    bad = next(row for row in rows if row["type"] == "assistant")
    bad["message"]["usage"]["cache_read_input_tokens"] = "many"
    session.write_text(json.dumps(bad) + "\n", encoding="utf-8")
    records, _ = read_transcript("claude", session, TranscriptCursor())
    refusals = [r for r in records if r.event == "refusal" and r.subagent_id is None]
    assert len(refusals) == 1 and "usage" in (refusals[0].refusal or "")


def test_unknown_row_type_yields_nothing(tmp_path: Path) -> None:
    session = tmp_path / "s.jsonl"
    row = {"type": "queue-operation", "timestamp": "t", "sessionId": "s"}
    session.write_text(json.dumps(row) + "\n", encoding="utf-8")
    records, _ = read_transcript("claude", session, TranscriptCursor())
    assert records == []


@pytest.mark.parametrize("version", VERSIONS)
def test_no_record_holds_transcript_text(version: str, tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(version, tmp_path), TranscriptCursor())
    dumped = json.dumps([record.to_json() for record in records])
    assert records
    assert "PLACEHOLDER" not in dumped
