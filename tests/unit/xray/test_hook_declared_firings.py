"""Which declared hooks a recorded firing marks as fired: every handler of the event whose matcher selects the tool."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.eventbus.transcript import read_transcript
from reporails_cli.core.platform.dto.events import EventRecord, HookFiring, TranscriptCursor
from reporails_cli.core.platform.dto.xray_build import Frame
from reporails_cli.core.platform.dto.xray_sources import EarlierFiring, EarlierFirings, HookDetail
from reporails_cli.core.xray.graph.hook_sources import hook_sources, with_earlier_firings

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

TIME = "2026-11-24T15:00:00.000Z"


def _declare(root: Path, hooks: dict[str, list[dict[str, object]]]) -> Frame:
    settings = root / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"hooks": hooks}))
    return Frame(0.0, root, {}, {}, {}, False, settings_files=(settings,))


def _group(matcher: str | None, *commands: str) -> dict[str, object]:
    group: dict[str, object] = {"hooks": [{"type": "command", "command": command} for command in commands]}
    if matcher is not None:
        group["matcher"] = matcher
    return group


def _firing(label: str, event: str, command: str | None) -> HookFiring:
    return HookFiring(label, event, None, command, None, None, "ran", 0)


def _record(firing: HookFiring) -> EventRecord:
    return EventRecord("claude", "hook_firing", "s", TIME, item=firing)


def _unfired(records: list[EventRecord], frame: Frame) -> list[str]:
    entries = hook_sources(records, [], frame)
    return [e.name for e in entries if isinstance(e.detail, HookDetail) and not e.detail.firing_count]


def test_a_user_prompt_output_naming_no_command_marks_every_prompt_handler_fired(tmp_path: Path) -> None:
    frame = _declare(tmp_path, {"UserPromptSubmit": [_group(None, "./one.sh"), _group(None, "./two.sh")]})
    assert len(_unfired([], frame)) == 2
    assert _unfired([_record(_firing("UserPromptSubmit", "UserPromptSubmit", None))], frame) == []


def test_a_stop_hook_summary_marks_the_declaration_of_each_command_it_lists(tmp_path: Path) -> None:
    row = {
        "type": "system",
        "subtype": "stop_hook_summary",
        "hookCount": 2,
        "hookInfos": [{"command": "./one.sh"}, {"command": "sh ./two.sh", "durationMs": 376}],
        "timestamp": TIME,
        "sessionId": "s",
    }
    session = tmp_path / "s.jsonl"
    session.write_text(json.dumps(row) + "\n")
    records, _ = read_transcript("claude", session, TranscriptCursor())
    assert [r.hook.command for r in records if r.hook] == ["./one.sh", "sh ./two.sh"]
    frame = _declare(tmp_path / "p", {"Stop": [_group(None, "./one.sh", "sh ./two.sh", "./three.sh")]})
    assert [label.endswith("three.sh") for label in _unfired(records, frame)] == [True]


def test_a_tool_firing_marks_the_handlers_whose_matcher_selects_the_tool(tmp_path: Path) -> None:
    frame = _declare(
        tmp_path,
        {"PreToolUse": [_group("Bash", "./bash.sh"), _group("*", "./any.sh"), _group("Edit", "./edit.sh")]},
    )
    unfired = _unfired([_record(_firing("PreToolUse:Bash", "PreToolUse", None))], frame)
    assert [label.endswith("edit.sh") for label in unfired] == [True]


def test_an_earlier_session_firing_naming_no_command_settles_every_handler_it_selects(tmp_path: Path) -> None:
    frame = _declare(tmp_path, {"PreToolUse": [_group("Bash", "./bash.sh"), _group("Edit", "./edit.sh")]})
    entries = hook_sources([], [], frame)
    earlier = EarlierFirings(False, (EarlierFiring("old", TIME, 1.0, _firing("PreToolUse:Bash", "PreToolUse", None)),))
    settled = [
        e.name.endswith("bash.sh")
        for e in with_earlier_firings(entries, earlier)
        if isinstance(e.detail, HookDetail) and e.detail.earlier is not None
    ]
    assert settled == [True]


def test_a_blocking_stop_hook_is_one_firing_when_the_stop_summary_lists_it_again(tmp_path: Path) -> None:
    command = "$CLAUDE_PROJECT_DIR/.claude/hooks/dispatch.sh"
    blocking = {
        "type": "attachment",
        "uuid": "b1",
        "attachment": {
            "type": "hook_blocking_error",
            "hookName": "Stop",
            "hookEvent": "Stop",
            "blockingError": {"blockingError": "revise the message", "command": command},
        },
        "timestamp": TIME,
        "sessionId": "s",
    }
    summary = {
        "type": "system",
        "subtype": "stop_hook_summary",
        "hookCount": 2,
        "hookInfos": [{"command": command}, {"command": "./other.sh", "durationMs": 12}],
        "timestamp": TIME,
        "sessionId": "s",
    }
    session = tmp_path / "s.jsonl"
    session.write_text(json.dumps(blocking) + "\n" + json.dumps(summary) + "\n")
    records, _ = read_transcript("claude", session, TranscriptCursor())
    firings = [(r.hook.command, r.hook.decision) for r in records if r.hook]
    assert firings == [(command, "blocked"), ("./other.sh", "ran")]
    session.write_text(json.dumps(blocking) + "\n")
    first, cursor = read_transcript("claude", session, TranscriptCursor())
    with session.open("a") as handle:
        handle.write(json.dumps(summary) + "\n")
    later, _ = read_transcript("claude", session, cursor)
    assert [r.hook.command for r in [*first, *later] if r.hook] == [command, "./other.sh"]
