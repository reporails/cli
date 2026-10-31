"""Transcript reading: usage per assistant response, turn ends, subagent runs and instruction loads."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.eventbus.transcript import read_transcript, subagent_brief
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


def test_subagent_whose_meta_arrives_late_still_gets_its_run_record(tmp_path: Path) -> None:
    session = _copy("2.1.308", tmp_path)
    meta = next((session.parent / "session" / "subagents").glob("*.meta.json"))
    held = meta.read_bytes()
    meta.unlink()
    records, cursor = read_transcript("claude", session, TranscriptCursor())
    assert not _of(records, "subagent_run")
    assert not [r for r in _of(records, "refusal") if "meta" in (r.refusal or "")]
    meta.write_bytes(held)
    later, cursor = read_transcript("claude", session, cursor)
    (run,) = _of(later, "subagent_run")
    assert run.subagent_type == json.loads(held)["agentType"]
    again, _ = read_transcript("claude", session, cursor)
    assert not _of(again, "subagent_run")


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


HARNESS = "2.1.308-harness"
BRIEF_SUB = "abrief0000000001"


def _text_size(*numbers: int) -> int:
    """The characters of the placeholder texts the harness fixture numbers."""
    return sum(len(f"PLACEHOLDER-TEXT-{number}") for number in numbers)


def test_each_harness_kind_resolves_to_its_count_and_character_size(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(HARNESS, tmp_path), TranscriptCursor())
    got = [(r.harness.kind, r.harness.label, r.harness.count, r.harness.chars) for r in records if r.harness]
    assert got == [
        ("hook_note", "SessionStart", None, _text_size(2)),
        ("session_context", "session context", None, _text_size(4, 5)),
        ("system_prompt", "system prompt", 3, _text_size(6, 7, 8)),
        ("deferred_tools", "deferred tools", 2, _text_size(10, 11)),
        ("agent_list", "agents", 3, _text_size(12, 13, 14)),
        ("mcp_instructions", "MCP server instructions", 1, _text_size(15)),
        ("skill_list", "skills", 7, _text_size(16)),
    ]
    assert not _of(records, "refusal")


def test_a_hook_note_of_another_event_yields_nothing(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(HARNESS, tmp_path), TranscriptCursor())
    assert "UserPromptSubmit" not in [r.harness.label for r in records if r.harness]


@pytest.mark.parametrize(
    ("attachment", "field"),
    [
        ("prompt_snapshot", "systemPrompt"),
        ("skill_listing", "skillCount"),
        ("skill_listing", "content"),
        ("agent_listing_delta", "addedTypes"),
        ("mcp_instructions_delta", "addedBlocks"),
        ("deferred_tools_delta", "addedLines"),
        ("session_context", "context"),
        ("hook_additional_context", "hookName"),
        ("hook_additional_context", "content"),
    ],
)
def test_a_harness_field_of_the_wrong_type_is_refused_naming_the_row_and_field(
    attachment: str, field: str, tmp_path: Path
) -> None:
    session = _copy(HARNESS, tmp_path)
    rows = [json.loads(line) for line in session.read_text().splitlines()]
    hit = next(
        row
        for row in rows
        if row["type"] == "attachment"
        and row["attachment"]["type"] == attachment
        and row["attachment"].get("hookEvent", "SessionStart") == "SessionStart"
    )
    hit["attachment"][field] = 12.5
    session.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    records, _ = read_transcript("claude", session, TranscriptCursor())
    reasons = [r.refusal or "" for r in _of(records, "refusal")]
    assert len(reasons) == 1 and attachment in reasons[0] and field in reasons[0]


def test_a_subagent_brief_is_the_text_of_its_first_user_row(tmp_path: Path) -> None:
    session = _copy(HARNESS, tmp_path)
    assert subagent_brief("claude", session, BRIEF_SUB) == "PLACEHOLDER-TEXT-19"
    assert subagent_brief("claude", session, "nosuchagent") is None


def test_a_subagent_brief_joins_text_blocks_and_refuses_a_first_row_that_is_not_a_user_row(tmp_path: Path) -> None:
    session = _copy(HARNESS, tmp_path)
    file = session.parent / "session" / "subagents" / f"agent-{BRIEF_SUB}.jsonl"
    rows = [json.loads(line) for line in file.read_text().splitlines()]
    rows[0]["message"]["content"] = [
        {"type": "text", "text": "ONE"},
        {"type": "image", "source": {}},
        {"type": "text", "text": "TWO"},
    ]
    file.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    assert subagent_brief("claude", session, BRIEF_SUB) == "ONE\n\nTWO"
    rows[0]["type"] = "assistant"
    file.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    with pytest.raises(PayloadRefused):
        subagent_brief("claude", session, BRIEF_SUB)


def test_a_subagent_deferred_tools_row_with_text_content_is_sized_without_a_count(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy("2.1.308", tmp_path), TranscriptCursor())
    assert not _of(records, "refusal")
    hits = [
        r
        for r in _of(records, "harness")
        if r.subagent_id == SUB_2_1_308 and getattr(r.item, "kind", None) == "deferred_tools"
    ]
    assert len(hits) == 1
    assert getattr(hits[0].item, "count", 0) is None
    assert getattr(hits[0].item, "chars", 0) == len("PLACEHOLDER_ATTACHMENT_TEXT")
