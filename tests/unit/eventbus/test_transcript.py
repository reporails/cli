"""Transcript reading: usage per assistant response, turn ends, subagent runs and instruction loads."""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from reporails_cli.core.eventbus.adapters.claude_transcript import ClaudeTranscriptAdapter
from reporails_cli.core.eventbus.port import PayloadRefused
from reporails_cli.core.eventbus.transcript import prompt_text, read_transcript, subagent_brief
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object
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
        "message": {"role": "user", "content": [{"type": "tool_result", "content": "Launching skill"}]},
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
    (record,) = ClaudeTranscriptAdapter().resolve_row(_tool_result(result), None)
    assert record.event == "skill_run" and record.skill is not None and record.skill.name == name
    assert record.skill.forked == (result.get("status") == "forked")


@pytest.mark.parametrize(
    "result",
    [{"success": False, "commandName": "orient"}, {"stdout": "ok"}, "plain text result"],
    ids=["failed run", "no command name", "text result"],
)
def test_a_failed_skill_run_and_a_tool_result_without_a_command_yield_nothing(result: object) -> None:
    assert ClaudeTranscriptAdapter().resolve_row(_tool_result(result), None) == []


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
