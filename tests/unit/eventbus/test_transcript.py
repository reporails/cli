"""Transcript reading: usage per assistant response, turn ends, subagent runs and instruction loads."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from reporails_cli.core.eventbus.adapters.claude_transcript import ClaudeTranscriptAdapter
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.eventbus.transcript import (
    CALL_INPUT_CHARS,
    CALL_RESULT_CHARS,
    call_detail,
    prompt_text,
    read_transcript,
    subagent_brief,
)
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object
from reporails_cli.core.platform.dto.events import EventRecord, ReplyText, TranscriptCursor

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
    assert [(r.usage.message_id, r.usage.input_tokens) for r in appended if r.usage] == [("msg_NEW", 9)]


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
        ("hook_note", "UserPromptSubmit", None, _text_size(3)),
        ("session_context", "session context", None, _text_size(4, 5)),
        ("system_prompt", "system prompt", 3, _text_size(6, 7, 8)),
        ("deferred_tools", "deferred tools", 2, _text_size(10, 11)),
        ("agent_list", "agents", 3, _text_size(12, 13, 14)),
        ("mcp_instructions", "MCP server instructions", 1, _text_size(15)),
        ("skill_list", "skills", 7, _text_size(16)),
    ]
    assert not _of(records, "refusal")


def test_a_hook_note_of_every_event_is_a_note_carrying_its_event(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(HARNESS, tmp_path), TranscriptCursor())
    notes = [(r.harness.label, r.harness.event) for r in records if r.harness and r.harness.kind == "hook_note"]
    assert notes == [("SessionStart", "SessionStart"), ("UserPromptSubmit", "UserPromptSubmit")]


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


def test_a_session_context_value_that_is_not_a_string_is_refused_naming_the_row_and_field(tmp_path: Path) -> None:
    session = _copy(HARNESS, tmp_path)
    rows = [json.loads(line) for line in session.read_text().splitlines()]
    hit = next(row for row in rows if row["type"] == "attachment" and row["attachment"]["type"] == "session_context")
    hit["attachment"]["context"] = {"a": "xx", "b": 12.5}
    session.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    records, _ = read_transcript("claude", session, TranscriptCursor())
    reasons = [r.refusal or "" for r in _of(records, "refusal")]
    assert len(reasons) == 1 and "session_context" in reasons[0] and "context" in reasons[0]


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


TURNS = "2.1.309-turns"
COMPACTION = "2.1.309-compaction"


def test_a_typed_prompt_is_one_prompt_submit_record_with_its_id_and_size_never_its_text(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(TURNS, tmp_path), TranscriptCursor())
    got = [(r.prompt.id, r.prompt.chars, r.prompt.queued) for r in _of(records, "prompt_submit") if r.prompt]
    size = len("PLACEHOLDER-TEXT-3")
    assert got == [("p-one", size, False), ("p-two", 2 * (size + 1), False), ("q-one", size + 1, True)]
    assert not _of(records, "refusal")
    assert "PLACEHOLDER" not in json.dumps([r.to_json() for r in records])


def test_a_tool_result_a_meta_row_a_peer_a_task_notification_and_a_queued_non_prompt_yield_no_prompt(
    tmp_path: Path,
) -> None:
    records, _ = read_transcript("claude", _copy(TURNS, tmp_path), TranscriptCursor())
    ids = {r.prompt.id for r in _of(records, "prompt_submit") if r.prompt}
    assert ids.isdisjoint({"t-result", "m-meta", "peer", "task", "q-peer", "q-task"})


def test_hook_success_with_text_and_a_stop_block_are_notes_with_their_event_and_size(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(TURNS, tmp_path), TranscriptCursor())
    entries = [r.harness for r in _of(records, "harness") if r.harness]
    assert [(e.kind, e.label, e.event) for e in entries] == [
        ("hook_note", "SessionStart:startup", "SessionStart"),
        ("hook_note", "SessionStart", "SessionStart"),
        ("hook_note", "UserPromptSubmit", "UserPromptSubmit"),
        ("stop_block", "Stop", "Stop"),
        ("hook_note", "PostToolUse:Edit", "PostToolUse"),
    ]
    assert entries[3].chars == len("PLACEHOLDER-TEXT-12")


@pytest.mark.parametrize(
    ("event", "is_note"),
    [
        ("PreToolUse", False),
        ("PostToolUse", False),
        ("Stop", False),
        ("UserPromptSubmit", True),
        ("UserPromptExpansion", True),
        ("SessionStart", True),
        ("PostModelSwitch", True),
    ],
)
def test_a_hook_success_is_context_only_for_the_events_whose_stdout_claude_code_adds(
    tmp_path: Path, event: str, is_note: bool
) -> None:
    session = _copy(TURNS, tmp_path)
    _edit_row(
        session,
        lambda r: as_object(r.get("attachment")).get("hookName") == "PreToolUse:Read",
        lambda r: as_object(r["attachment"]).update(hookEvent=event, hookName="probe"),
    )
    records, _ = read_transcript("claude", session, TranscriptCursor())
    probes = [r.harness for r in _of(records, "harness") if r.harness and r.harness.label == "probe"]
    assert [(p.kind, p.event) for p in probes] == ([("hook_note", event)] if is_note else [])


def test_a_prompt_text_is_read_again_by_its_row_id_and_joins_text_blocks(tmp_path: Path) -> None:
    session = _copy(TURNS, tmp_path)
    assert prompt_text("claude", session, "p-one") == "PLACEHOLDER-TEXT-3"
    assert prompt_text("claude", session, "p-two") == "PLACEHOLDER-TEXT-13PLACEHOLDER-TEXT-14"
    assert prompt_text("claude", session, "q-one") == "PLACEHOLDER-TEXT-15"
    assert prompt_text("claude", session, "nosuchrow") is None
    with pytest.raises(PayloadRefused):
        prompt_text("claude", session, "t-result")


def _edit_row(session: Path, match: Callable[[JsonObject], bool], edit: Callable[[JsonObject], None]) -> None:
    rows = [json.loads(line) for line in session.read_text().splitlines()]
    edit(next(row for row in rows if match(row)))
    session.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_a_queued_prompt_of_another_shape_is_refused_naming_the_row_and_field(tmp_path: Path) -> None:
    session = _copy(TURNS, tmp_path)
    _edit_row(session, lambda r: r.get("uuid") == "q-one", lambda r: as_object(r["attachment"]).update(prompt=12.5))
    records, _ = read_transcript("claude", session, TranscriptCursor())
    reasons = [r.refusal or "" for r in _of(records, "refusal")]
    assert len(reasons) == 1 and "queued_command" in reasons[0] and "prompt" in reasons[0]


def test_a_typed_row_whose_content_is_not_text_is_refused_naming_the_row(tmp_path: Path) -> None:
    session = _copy(TURNS, tmp_path)
    _edit_row(session, lambda r: r.get("uuid") == "p-one", lambda r: as_object(r["message"]).update(content=12.5))
    records, _ = read_transcript("claude", session, TranscriptCursor())
    reasons = [r.refusal or "" for r in _of(records, "refusal")]
    assert len(reasons) == 1 and "user row" in reasons[0] and "content" in reasons[0]


def test_a_stop_block_whose_error_is_not_an_object_holding_a_string_is_refused(tmp_path: Path) -> None:
    session = _copy(TURNS, tmp_path)
    _edit_row(
        session,
        lambda r: as_object(r.get("attachment")).get("type") == "hook_blocking_error",
        lambda r: as_object(r["attachment"]).update(blockingError="text"),
    )
    records, _ = read_transcript("claude", session, TranscriptCursor())
    reasons = [r.refusal or "" for r in _of(records, "refusal")]
    assert len(reasons) == 1 and "blockingError" in reasons[0]


def test_a_delta_row_counts_its_added_items_less_its_removed_ones(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(COMPACTION, tmp_path), TranscriptCursor())
    deferred = [r.harness.count for r in _of(records, "harness") if r.harness and r.harness.kind == "deferred_tools"]
    assert deferred == [38, 12, 50, 4, -4]


def test_a_compact_boundary_row_is_a_post_compact_record_with_its_trigger(tmp_path: Path) -> None:
    records, _ = read_transcript("claude", _copy(COMPACTION, tmp_path), TranscriptCursor())
    assert [r.source for r in _of(records, "post_compact")] == ["manual"]


def _tool_result(result: object) -> JsonObject:
    return {
        "type": "user",
        "uuid": "u1",
        "sessionId": "s",
        "timestamp": "2026-10-31T10:00:00.000Z",
        "message": {
            "role": "user",
            "content": [{"type": "tool_result", "tool_use_id": "toolu_1", "content": "Launching skill"}],
        },
        "toolUseResult": result,
    }


@pytest.mark.parametrize(
    ("result", "name"),
    [
        ({"success": True, "commandName": "orient"}, "orient"),
        (
            {"success": True, "commandName": "code-review", "status": "forked", "background": True, "agentId": "a1"},
            "code-review",
        ),
    ],
)
def test_a_skill_run_is_a_record_named_by_its_command(result: JsonObject, name: str) -> None:
    (record,) = _of(ClaudeTranscriptAdapter().resolve_row(_tool_result(result), None), "skill_run")
    assert record.event == "skill_run" and record.skill is not None and record.skill.name == name
    assert record.skill.forked == (result.get("status") == "forked")


@pytest.mark.parametrize(
    "result",
    [{"success": False, "commandName": "orient"}, {"stdout": "ok"}, "plain text result"],
    ids=["failed run", "no command name", "text result"],
)
def test_a_failed_skill_run_and_a_tool_result_without_a_command_yield_nothing(result: object) -> None:
    assert _of(ClaudeTranscriptAdapter().resolve_row(_tool_result(result), None), "skill_run") == []


@pytest.mark.parametrize(
    ("result", "field"),
    [
        ({"success": True, "commandName": 7}, "commandName"),
        ({"success": "yes", "commandName": "orient"}, "success"),
    ],
)
def test_a_malformed_skill_run_is_refused_naming_the_field(result: JsonObject, field: str) -> None:
    with pytest.raises(PayloadRefused, match=field):
        ClaudeTranscriptAdapter().resolve_row(_tool_result(result), None)


def _deferred_row(**fields: list[str]) -> JsonObject:
    return {
        "type": "attachment",
        "sessionId": "s",
        "timestamp": "2026-10-31T10:00:00.000Z",
        "attachment": {"type": "deferred_tools_delta", **fields},
    }


def test_tools_re_added_by_name_count_with_size_zero_and_are_not_refused() -> None:
    names = [f"tool_{n}" for n in range(9)]
    (record,) = ClaudeTranscriptAdapter().resolve_row(
        _deferred_row(addedNames=names, addedLines=[], readdedNames=names), None
    )
    entry = record.harness
    assert entry is not None and entry.count == 9 and entry.chars == 0
    assert entry.added == () and entry.readded == tuple(names)


def test_a_delta_row_with_unequal_non_empty_name_and_line_lists_is_refused() -> None:
    with pytest.raises(PayloadRefused, match="names for"):
        ClaudeTranscriptAdapter().resolve_row(_deferred_row(addedNames=["a", "b", "c"], addedLines=["x", "y"]), None)


def test_a_skill_run_status_that_is_not_a_string_is_refused() -> None:
    result = {"success": True, "commandName": "orient", "status": 3}
    with pytest.raises(PayloadRefused, match="status"):
        ClaudeTranscriptAdapter().resolve_row(_tool_result(result), None)


def test_a_listing_delta_with_names_and_no_items_is_refused() -> None:
    row = {
        "type": "attachment",
        "sessionId": "s",
        "timestamp": "2026-10-31T10:00:00.000Z",
        "attachment": {"type": "agent_listing_delta", "addedTypes": ["writer"], "addedLines": []},
    }
    with pytest.raises(PayloadRefused, match="readdedNames"):
        ClaudeTranscriptAdapter().resolve_row(row, None)


def test_deferred_tools_with_no_items_are_refused_unless_every_name_is_re_added() -> None:
    names = ["a", "b", "c"]
    with pytest.raises(PayloadRefused, match="readdedNames"):
        ClaudeTranscriptAdapter().resolve_row(
            _deferred_row(addedNames=names, addedLines=[], readdedNames=["a", "b"]), None
        )


def _assistant_row(**message: object) -> JsonObject:
    usage = {"input_tokens": 1, "cache_creation_input_tokens": 2, "cache_read_input_tokens": 3}
    return {
        "type": "assistant",
        "sessionId": "s",
        "timestamp": "2026-10-31T10:00:00.000Z",
        "message": {"id": "msg_1", "usage": usage, **message},
    }


def test_a_reply_carries_the_model_its_row_names_and_the_model_survives_the_stored_record() -> None:
    (record,) = ClaudeTranscriptAdapter().resolve_row(_assistant_row(model="claude-opus-5"), None)
    assert record.usage is not None and record.usage.model == "claude-opus-5"
    assert EventRecord.from_json(record.to_json()).usage == record.usage
    (bare,) = ClaudeTranscriptAdapter().resolve_row(_assistant_row(), None)
    assert bare.usage is not None and bare.usage.model is None
    assert EventRecord.from_json(bare.to_json()).usage == bare.usage


def test_a_reply_whose_model_is_not_a_string_is_refused() -> None:
    with pytest.raises(PayloadRefused, match="model"):
        ClaudeTranscriptAdapter().resolve_row(_assistant_row(model=5), None)


def _listing_row(**fields: object) -> JsonObject:
    attachment = {"type": "skill_listing", "content": "abc", "skillCount": 2, **fields}
    return {"type": "attachment", "sessionId": "s", "timestamp": "2026-10-31T10:00:00.000Z", "attachment": attachment}


def test_a_skill_listing_row_names_its_skills_only_when_the_row_carries_them() -> None:
    (named,) = ClaudeTranscriptAdapter().resolve_row(_listing_row(names=["a", "b"]), None)
    (bare,) = ClaudeTranscriptAdapter().resolve_row(_listing_row(), None)
    assert named.harness is not None and named.harness.names == ("a", "b")
    assert bare.harness is not None and bare.harness.names is None
    with pytest.raises(PayloadRefused, match="names"):
        ClaudeTranscriptAdapter().resolve_row(_listing_row(names="a"), None)


HANDOFFS = "2.1.309-handoffs"
SUB_A, SUB_B, SUB_C, SUB_D, SUB_E = (
    "aaaa0000000000001",
    "abbb0000000000002",
    "accc0000000000003",
    "addd0000000000004",
    "aeee0000000000005",
)


def _handoff_records(tmp_path: Path) -> list[EventRecord]:
    records, _ = read_transcript("claude", _copy(HANDOFFS, tmp_path), TranscriptCursor())
    return records


def test_the_handoffs_session_reads_into_the_expected_records_with_no_refusal(tmp_path: Path) -> None:
    records = _handoff_records(tmp_path)
    counts: dict[str, int] = {}
    for record in records:
        counts[record.event] = counts.get(record.event, 0) + 1
    assert counts["tool_call"] == 21 and counts["tool_result"] == 18 and counts["subagent_run"] == 6
    assert counts["instruction_load"] == 8 and counts["post_compact"] == 1 and counts["skill_run"] == 1
    assert "refusal" not in counts
    categories: dict[str, int] = {}
    for record in _of(records, "tool_call"):
        assert record.tool is not None and record.tool.category is not None
        categories[record.tool.category] = categories.get(record.tool.category, 0) + 1
    assert categories == {"agent": 6, "mcp": 4, "run": 5, "read": 1, "edit": 1, "other": 3, "handback": 1}


def test_a_nested_subagent_carries_its_parent_and_depth_and_no_launching_call(tmp_path: Path) -> None:
    launches = {r.subagent_id: r.launch for r in _of(_handoff_records(tmp_path), "subagent_run")}
    nested, deeper, foreground, stopped = launches[SUB_B], launches[SUB_C], launches[SUB_D], launches[SUB_E]
    assert nested is not None and deeper is not None and foreground is not None and stopped is not None
    assert (nested.parent_id, nested.tool_use_id, nested.depth, nested.background) == (SUB_A, None, 2, True)
    assert (deeper.parent_id, deeper.tool_use_id, deeper.depth) == (SUB_B, None, 3)
    assert (foreground.tool_use_id, foreground.background, foreground.stopped) == ("toolu_agentD", False, False)
    assert stopped.stopped is True and stopped.description == "PLACEHOLDER-DESC-E"
    assert nested.brief_chars == len(subagent_brief("claude", _copy_session(tmp_path), SUB_B) or "")


def _copy_session(tmp_path: Path) -> Path:
    return _copy(HANDOFFS, tmp_path) if not (tmp_path / HANDOFFS).exists() else tmp_path / HANDOFFS / "session.jsonl"


def test_a_handback_call_carries_its_message_size_and_is_the_only_call_with_chars(tmp_path: Path) -> None:
    calls = [r.tool for r in _of(_handoff_records(tmp_path), "tool_call") if r.tool is not None]
    (handback,) = [tool for tool in calls if tool.category == "handback"]
    assert handback.chars == 480 and handback.name == "SubagentHandback"
    assert all(tool.chars is None for tool in calls if tool.category != "handback")


def test_the_three_failing_runs_of_one_command_share_a_fingerprint_with_the_success_after_them(
    tmp_path: Path,
) -> None:
    records = _handoff_records(tmp_path)
    runs = [r.tool for r in _of(records, "tool_call") if r.tool and r.tool.category == "run" and not r.subagent_id]
    errors = {r.tool.use_id: r.tool.error for r in _of(records, "tool_result") if r.tool}
    assert len({tool.fingerprint for tool in runs}) == 1 and runs[0].fingerprint is not None
    assert len(runs[0].fingerprint) == 16
    assert [errors[tool.use_id or ""] for tool in runs] == [True, True, True, False]


def test_mcp_calls_name_their_server_and_read_calls_their_path(tmp_path: Path) -> None:
    calls = [r.tool for r in _of(_handoff_records(tmp_path), "tool_call") if r.tool is not None]
    assert {tool.server for tool in calls if tool.category == "mcp"} == {"plugin_docs_server"}
    assert {tool.path for tool in calls if tool.category in ("read", "edit")} == {
        "/work/proj/CLAUDE.md",
        "/work/proj/src/mod.py",
    }
    assert all(tool.path is None for tool in calls if tool.category not in ("read", "edit"))


def test_a_tool_result_sizes_a_text_list_by_its_text_blocks_only(tmp_path: Path) -> None:
    results = {r.tool.use_id: r.tool for r in _of(_handoff_records(tmp_path), "tool_result") if r.tool}
    assert results["toolu_mcp1"].chars == len("PLACEHOLDER-MCP-RESULT") and results["toolu_mcp1"].error is False
    assert results["toolu_bash1"].error is True and results["toolu_bash4"].error is False


def test_the_command_of_a_main_and_a_subagent_call_is_read_back_by_call_id(tmp_path: Path) -> None:
    session = _copy_session(tmp_path)
    main = call_detail("claude", session, None, "toolu_bash2", "Bash", shell=True)
    assert main is not None and main.text == "PLACEHOLDER-COMMAND --flag" and main.tool == "Bash"
    sub = call_detail("claude", session, SUB_D, "toolu_bashD", "Bash", shell=True)
    assert sub is not None and sub.text == "PLACEHOLDER-SUB-COMMAND"
    assert call_detail("claude", session, None, "toolu_bashD", "Bash", shell=True) is None
    assert call_detail("claude", session, SUB_D, "toolu_nosuch", "Bash", shell=True) is None
    with pytest.raises(PayloadRefused, match="unknown agent"):
        call_detail("nosuch", session, None, "toolu_bash2", "Bash", shell=True)


def test_a_read_call_reads_back_its_input_and_result_with_no_command(tmp_path: Path) -> None:
    detail = call_detail("claude", _copy_session(tmp_path), None, "toolu_read1", "Read", shell=False)
    assert detail is not None and detail.text is None and detail.truncated is False
    assert json.loads(detail.input) == {"file_path": "/work/proj/CLAUDE.md"} and "\n  " in detail.input
    assert detail.result == "PLACEHOLDER-FILE-TEXT" * 10


def test_a_call_with_no_result_reads_back_none_and_a_big_one_is_cut_at_the_bound(tmp_path: Path) -> None:
    session = _copy_session(tmp_path)
    big = "x" * (CALL_RESULT_CHARS + 50)
    rows = [
        _assistant_row(
            content=[{"type": "tool_use", "id": "t_big", "name": "Read", "input": {"p": "y" * CALL_INPUT_CHARS}}]
        ),
        {"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t_big", "content": big}]}},
        _assistant_row(content=[{"type": "tool_use", "id": "t_open", "name": "Read", "input": {}}]),
    ]
    session.write_text("".join(json.dumps(row) + "\n" for row in rows))
    cut = call_detail("claude", session, None, "t_big", "Read", shell=False)
    assert cut is not None and cut.truncated and len(cut.input) == CALL_INPUT_CHARS
    assert cut.result == big[:CALL_RESULT_CHARS]
    open_call = call_detail("claude", session, None, "t_open", "Read", shell=False)
    assert open_call is not None and open_call.result is None and open_call.truncated is False


def test_a_shell_call_with_no_command_has_no_text_to_read_back(tmp_path: Path) -> None:
    session = _copy_session(tmp_path)
    with pytest.raises(PayloadRefused, match="no string command"):
        call_detail("claude", session, None, "toolu_edit1", "Edit", shell=True)


def _call_row(name: str, tool_input: object, use_id: str = "toolu_1") -> JsonObject:
    row = _assistant_row(content=[{"type": "tool_use", "id": use_id, "name": name, "input": tool_input}])
    return row


def test_the_assistant_row_of_a_call_yields_its_usage_and_the_call() -> None:
    records = ClaudeTranscriptAdapter().resolve_row(_call_row("Bash", {"command": "ls"}), "sub")
    assert [r.event for r in records] == ["assistant_usage", "tool_call"]
    assert records[1].subagent_id == "sub" and records[1].tool is not None and records[1].tool.use_id == "toolu_1"


@pytest.mark.parametrize(
    ("name", "tool_input", "reason"),
    [
        ("Bash", [], "input is not an object"),
        ("Bash", {"command": 7}, "no string command"),
        ("SubagentHandback", {"message": None}, "no string message"),
        ("Bash", {"cmd": "ls"}, "no string command"),
    ],
)
def test_a_tool_call_of_an_unknown_shape_is_refused(name: str, tool_input: object, reason: str) -> None:
    with pytest.raises(PayloadRefused, match=reason):
        ClaudeTranscriptAdapter().resolve_row(_call_row(name, tool_input), None)


@pytest.mark.parametrize(
    "block", [{"type": "tool_use", "name": "Read", "input": {}}, {"type": "tool_use", "id": "t", "input": {}}]
)
def test_a_tool_use_block_without_a_string_id_and_name_is_refused(block: JsonObject) -> None:
    with pytest.raises(PayloadRefused, match="string id and name"):
        ClaudeTranscriptAdapter().resolve_row(_assistant_row(content=[block]), None)


def _result_row(block: JsonObject) -> JsonObject:
    return {
        "type": "user",
        "sessionId": "s",
        "timestamp": "2026-10-31T10:00:00.000Z",
        "message": {"role": "user", "content": [{"type": "tool_result", **block}]},
    }


@pytest.mark.parametrize(
    ("block", "reason"),
    [
        ({"content": "x"}, "tool_use_id"),
        ({"tool_use_id": "t", "content": "x", "is_error": "yes"}, "is_error"),
        ({"tool_use_id": "t", "content": 5}, "neither text nor a list"),
        ({"tool_use_id": "t"}, "neither text nor a list"),
    ],
)
def test_a_tool_result_of_an_unknown_shape_is_refused(block: JsonObject, reason: str) -> None:
    with pytest.raises(PayloadRefused, match=reason):
        ClaudeTranscriptAdapter().resolve_row(_result_row(block), None)


def test_a_tool_result_without_is_error_reads_as_no_error() -> None:
    (record,) = ClaudeTranscriptAdapter().resolve_row(_result_row({"tool_use_id": "t", "content": "abc"}), None)
    assert record.tool is not None and (record.tool.chars, record.tool.error) == (3, False)


@pytest.mark.parametrize(
    ("name", "category", "server"),
    [
        ("Grep", "read", None),
        ("MultiEdit", "edit", None),
        ("PowerShell", "run", None),
        ("Task", "agent", None),
        ("mcp__claude_ai_Notion__notion-search", "mcp", "claude_ai_Notion"),
        ("mcp__reporails-dev__validate", "mcp", "reporails-dev"),
        ("EnterWorktree", "other", None),
    ],
)
def test_a_tool_name_falls_in_its_category_and_an_mcp_name_names_its_server(
    name: str, category: str, server: str | None
) -> None:
    tool_input: JsonObject = {"command": "x"} if category == "run" else {}
    (_, record) = ClaudeTranscriptAdapter().resolve_row(_call_row(name, tool_input), None)
    assert record.tool is not None and (record.tool.category, record.tool.server) == (category, server)


def test_a_notebook_path_or_a_plain_path_names_the_target_when_no_file_path_does() -> None:
    adapter = ClaudeTranscriptAdapter()
    (_, notebook) = adapter.resolve_row(_call_row("NotebookEdit", {"notebook_path": "/n.ipynb"}), None)
    (_, grep) = adapter.resolve_row(_call_row("Grep", {"path": "/src", "pattern": "x"}), None)
    assert notebook.tool is not None and notebook.tool.path == "/n.ipynb"
    assert grep.tool is not None and grep.tool.path == "/src"


def test_a_request_blob_row_is_not_read() -> None:
    row = {
        "type": "api-request-blob",
        "sessionId": "s",
        "hash": "h",
        "message": {
            "role": "assistant",
            "content": [{"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": "ls"}}],
        },
    }
    assert ClaudeTranscriptAdapter().resolve_row(row, None) == []


def test_resolve_call_refuses_a_row_without_the_call() -> None:
    adapter = ClaudeTranscriptAdapter()
    assert adapter.resolve_call(_call_row("Bash", {"command": "ls -la"}), "toolu_1") == "ls -la"
    with pytest.raises(PayloadRefused, match="no tool call toolu_2"):
        adapter.resolve_call(_call_row("Bash", {"command": "ls"}), "toolu_2")


def _meta(**fields: object) -> JsonObject:
    return {"agentType": "general-purpose", **fields}  # type: ignore[dict-item]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("description", 3),
        ("parentAgentId", 3),
        ("toolUseId", 3),
        ("requestShape", 3),
        ("spawnDepth", "2"),
        ("spawnDepth", True),
        ("stoppedByUser", "yes"),
    ],
)
def test_a_meta_field_of_the_wrong_type_is_refused_naming_it(field: str, value: object) -> None:
    first = {"type": "user", "sessionId": "s", "timestamp": "2026-10-31T10:00:00.000Z", "message": {"content": "hi"}}
    with pytest.raises(PayloadRefused, match=field):
        ClaudeTranscriptAdapter().resolve_subagent("a1", _meta(**{field: value}), first)


def test_a_meta_file_without_the_optional_fields_reads_as_a_foreground_launch_of_nothing_known() -> None:
    first = {"type": "user", "sessionId": "s", "timestamp": "2026-10-31T10:00:00.000Z", "message": {"content": "hello"}}
    record = ClaudeTranscriptAdapter().resolve_subagent("a1", _meta(), first)
    launch = record.launch
    assert launch is not None and launch.brief_chars == 5
    assert (launch.description, launch.parent_id, launch.tool_use_id, launch.depth) == (None, None, None, None)
    assert (launch.stopped, launch.background) == (False, False)


def _text_row(*blocks: JsonObject) -> JsonObject:
    return _assistant_row(content=list(blocks))


def test_an_assistant_row_with_text_yields_the_size_of_its_text_and_never_the_text() -> None:
    row = _text_row(
        {"type": "text", "text": "hello"}, {"type": "thinking", "thinking": "zzz"}, {"type": "text", "text": "!!"}
    )
    records = ClaudeTranscriptAdapter().resolve_row(row, "sub")
    assert [r.event for r in records] == ["assistant_usage", "assistant_text"]
    assert records[1].subagent_id == "sub" and records[1].reply is not None and records[1].reply.chars == 7
    assert "hello" not in json.dumps(records[1].to_json())


def test_an_assistant_row_with_only_a_call_or_no_content_yields_no_text_record() -> None:
    adapter = ClaudeTranscriptAdapter()
    call_row = _call_row("Bash", {"command": "ls"})
    assert [r.event for r in adapter.resolve_row(call_row, None)] == ["assistant_usage", "tool_call"]
    assert [r.event for r in adapter.resolve_row(_assistant_row(), None)] == ["assistant_usage"]


def test_a_text_block_without_text_is_refused() -> None:
    with pytest.raises(PayloadRefused, match="text block has no text"):
        ClaudeTranscriptAdapter().resolve_row(_text_row({"type": "text", "text": 7}), None)


def test_the_handoffs_subagent_that_ends_on_a_reply_ends_on_its_text_record_and_the_one_that_ends_on_a_call_does_not(
    tmp_path: Path,
) -> None:
    records = _handoff_records(tmp_path)
    last = {
        sub: [r for r in records if r.subagent_id == sub and r.event in ("assistant_text", "tool_call")][-1]
        for sub in (SUB_C, "afff0000000000006")
    }
    assert last[SUB_C].event == "assistant_text" and last[SUB_C].reply == ReplyText(len("PLACEHOLDER-TEXT-30"), False)
    assert last["afff0000000000006"].event == "tool_call"


def _reply_row(text: str, **message: object) -> JsonObject:
    return _assistant_row(content=[{"type": "text", "text": text}], **message)


def test_a_reply_written_by_claude_code_itself_is_marked_synthetic_and_a_model_reply_is_not() -> None:
    adapter = ClaudeTranscriptAdapter()
    synthetic = [r for r in adapter.resolve_row(_reply_row("API Error: 529", model="<synthetic>"), "sub") if r.reply]
    real = [r for r in adapter.resolve_row(_reply_row("Done.", model="claude-opus-5"), "sub") if r.reply]
    assert [r.reply for r in synthetic] == [ReplyText(len("API Error: 529"), True)]
    assert [r.reply for r in real] == [ReplyText(len("Done."), False)]


def _first_row(content: object) -> JsonObject:
    return {"type": "user", "sessionId": "s", "timestamp": "2026-10-31T10:00:00.000Z", "message": {"content": content}}


@pytest.mark.parametrize("content", [[], "", [{"type": "image", "source": {}}]])
def test_a_subagent_whose_first_row_holds_no_text_keeps_its_run_record_with_an_unknown_brief(content: object) -> None:
    adapter = ClaudeTranscriptAdapter()
    meta: JsonObject = {"agentType": "Explore", "description": "look", "toolUseId": "tu1"}
    run = adapter.resolve_subagent("a1", meta, _first_row(content))
    assert run.subagent_type == "Explore"
    assert run.launch is not None and run.launch.brief_chars is None and run.launch.tool_use_id == "tu1"
    with pytest.raises(PayloadRefused):
        adapter.resolve_brief(_first_row(content))


def test_a_first_row_that_is_not_a_user_row_still_refuses_the_run_record() -> None:
    row = {**_first_row("hi"), "type": "assistant"}
    with pytest.raises(PayloadRefused):
        ClaudeTranscriptAdapter().resolve_subagent("a1", {"agentType": "Explore"}, row)


def test_the_adapter_says_which_assistant_row_holds_a_call() -> None:
    adapter = ClaudeTranscriptAdapter()
    block = {"type": "tool_use", "id": "toolu_1", "name": "Bash", "input": {"command": "ls"}}
    row = _assistant_row(content=[{"type": "text", "text": "x"}, block])
    assert adapter.holds_call(row, "toolu_1") and not adapter.holds_call(row, "toolu_2")
    assert not adapter.holds_call({**row, "type": "user"}, "toolu_1")
    assert not adapter.holds_call(_assistant_row(content="plain"), "toolu_1")


def test_a_reply_carries_output_and_the_cache_write_split_through_the_stored_record() -> None:
    usage = {
        "input_tokens": 1,
        "cache_creation_input_tokens": 30,
        "cache_read_input_tokens": 3,
        "output_tokens": 7,
        "cache_creation": {"ephemeral_5m_input_tokens": 10, "ephemeral_1h_input_tokens": 20},
    }
    row = _assistant_row()
    as_object(row["message"])["usage"] = usage
    (record,) = ClaudeTranscriptAdapter().resolve_row(row, None)
    assert record.usage is not None
    assert (record.usage.output_tokens, record.usage.cache_write_5m_tokens, record.usage.cache_write_1h_tokens) == (
        7,
        10,
        20,
    )
    assert EventRecord.from_json(record.to_json()).usage == record.usage


def test_a_reply_without_the_new_counts_reads_them_as_none_and_an_old_stored_record_still_loads() -> None:
    (record,) = ClaudeTranscriptAdapter().resolve_row(_assistant_row(), None)
    assert record.usage is not None
    assert (record.usage.output_tokens, record.usage.cache_write_5m_tokens, record.usage.cache_write_1h_tokens) == (
        None,
        None,
        None,
    )
    stored = record.to_json()
    old_usage = {
        key: value
        for key, value in as_object(stored["usage"]).items()
        if not key.endswith(("_5m_tokens", "_1h_tokens", "output_tokens"))
    }
    loaded = EventRecord.from_json({**stored, "usage": old_usage}).usage
    assert loaded is not None and loaded.output_tokens is None and loaded.input_tokens == 1


@pytest.mark.parametrize(
    "bad",
    [
        {"output_tokens": "many"},
        {"output_tokens": 1.5},
        {"cache_creation": {"ephemeral_5m_input_tokens": "x"}},
        {"cache_creation": [1]},
    ],
)
def test_a_present_count_that_is_not_a_whole_number_refuses_the_row(bad: JsonObject) -> None:
    row = _assistant_row()
    usage = as_object(as_object(row["message"])["usage"])
    as_object(row["message"])["usage"] = {**usage, **bad}
    with pytest.raises(PayloadRefused):
        ClaudeTranscriptAdapter().resolve_row(row, None)


@pytest.mark.parametrize(
    ("text", "acknowledges"),
    [
        ("Async agent launched successfully.\nagentId: a1 (internal ID)", True),
        ("The findings are in the report.", False),
    ],
)
def test_a_tool_result_that_only_acknowledges_a_background_launch_says_so(text: str, acknowledges: bool) -> None:
    row = _tool_result({})
    as_object(row["message"])["content"] = [{"type": "tool_result", "tool_use_id": "toolu_1", "content": text}]
    (record,) = _of(ClaudeTranscriptAdapter().resolve_row(row, None), "tool_result")
    assert record.tool is not None and record.tool.launch_ack is acknowledges


def test_a_call_is_read_back_in_one_pass_over_the_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    session = _copy_session(tmp_path)
    opened: list[Path] = []
    original = Path.open

    def counting(self: Path, *args: object, **kwargs: object) -> object:
        opened.append(self)
        return original(self, *args, **kwargs)  # type: ignore[call-overload]

    monkeypatch.setattr(Path, "open", counting)
    detail = call_detail("claude", session, None, "toolu_read1", "Read", shell=False)
    assert detail is not None and detail.result == "PLACEHOLDER-FILE-TEXT" * 10
    assert opened.count(session) == 1
