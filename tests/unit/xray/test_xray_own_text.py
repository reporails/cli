"""The text each item of the coding agent's own context opens with is the text its size counts, read from a session
file the way the page's text route reads it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.dto.xray import XrayCheck
from reporails_cli.core.platform.dto.xray_own import XrayOwnItem
from reporails_cli.core.platform.utils.utils import compact_json
from reporails_cli.core.xray.session import XraySession
from reporails_cli.interfaces.cli.xray_fields import context_fields

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

SESSION = "11111111-2222-3333-4444-555555555555"
TOOL = {
    "name": "Read",
    "description": "Reads a file",
    "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}}},
}


def _row(kind: str, second: int, **fields: object) -> dict[str, object]:
    stamp = f"2026-10-31T10:{second // 60:02d}:{second % 60:02d}.000Z"
    return {"type": kind, "timestamp": stamp, "sessionId": SESSION, "version": "2.1.309", "cwd": "/p", **fields}


def _attachment(second: int, **fields: object) -> dict[str, object]:
    return _row("attachment", second, attachment=fields)


def _reminder(text: str) -> str:
    return f"<system-reminder>\n{text}\n</system-reminder>"


def _blob(name: str, role: str, content: object) -> dict[str, object]:
    return {"type": "api-request-blob", "hash": name, "message": {"role": role, "content": content}}


def _session(
    tmp_path: Path, before: list[dict[str, object]], blobs: list[dict[str, object]], *, request: bool = True
) -> XraySession:
    """A main agent whose one reply answers a request made of `blobs`, after the `before` rows."""
    shape = {
        "type": "api-request-shape",
        "shapeHash": "shape",
        "shape": {"system": [{"type": "text", "text": "S" * 400}], "tools": [TOOL]},
    }
    asked = _row("api-request", 100, id="req", shapeHash="shape", keep=0, tail=[b["hash"] for b in blobs])
    usage = {"input_tokens": 2, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 900, "output_tokens": 5}
    message = {"id": "msg", "role": "assistant", "model": "claude-sonnet-5-5", "content": [], "usage": usage}
    reply = _row("assistant", 101, message=message, requestRef="req")
    rows = [*before, shape, *blobs, *([asked] if request else []), reply]
    path = tmp_path / f"{SESSION}.jsonl"
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    session = XraySession(tmp_path, path)
    session.refresh()
    session.view(RunContext(), {}, XrayCheck("running", None), "newest")
    return session


def _item(session: XraySession, key: str) -> XrayOwnItem:
    own = session.view(RunContext(), {}, XrayCheck("running", None), "newest").nodes[0].detail.in_context.own  # type: ignore[union-attr]
    return next(item for item in own.rows if item.key == key)


def _chars(session: XraySession, key: str) -> int:
    return sum(len(text) for text in session.context_text("", key) or [])  # type: ignore[arg-type]


def test_other_messages_leave_out_the_notes_a_source_and_a_hook_count_in_their_own_rows(tmp_path: Path) -> None:
    rules = "Always run the tests before you commit " + "r" * 200
    hook = "[gate] 2 substrate files armed " + "h" * 150
    before = [
        _attachment(1, type="instructions", files=[{"path": "/p/CLAUDE.md", "type": "Project", "content": rules}]),
        _attachment(
            2, type="hook_additional_context", hookName="PreToolUse:Bash", hookEvent="PreToolUse", content=[hook]
        ),
    ]
    rest = _reminder("The user has not heard from you in a while.")
    blobs = [
        _blob("n1", "user", _reminder(f"Contents of /p/CLAUDE.md:\n{rules}")),
        _blob("n2", "user", _reminder(f"PreToolUse:Bash hook additional context: {hook}")),
        _blob("n3", "user", rest),
    ]
    assert _session(tmp_path, before, blobs).context_text("", "harness_other") == [rest]


def test_a_listing_shows_the_entries_its_size_counts_and_no_entry_twice(tmp_path: Path) -> None:
    before = [
        _attachment(1, type="agent_listing_delta", addedTypes=["a", "b"], addedLines=["- a: A", "- b: B"]),
        _attachment(2, type="agent_listing_delta", addedTypes=["c"], addedLines=["- c: C"], removedTypes=["a"]),
        _attachment(3, type="skill_listing", skillCount=1, content="skills one"),
        _attachment(4, type="deferred_tools_delta", addedNames=["W"], addedLines=["W: fetches"], removedNames=[]),
        _attachment(5, type="session_context", context={"cwd": "/p", "date": "2026-11-24"}),
        _row("system", 6, subtype="compact_boundary", compactMetadata={"trigger": "auto"}),
        _attachment(7, type="agent_listing_delta", addedTypes=["d"], addedLines=["- d: D"]),
        _attachment(8, type="deferred_tools_delta", addedNames=["X"], addedLines=["X: later"], removedNames=[]),
    ]
    session = _session(tmp_path, before, [_blob("n", "user", _reminder("x"))])
    assert session.context_text("", "agent_listing") == ["- b: B", "- c: C"]
    assert session.context_text("", "deferred_tools") == ["W: fetches"]
    assert session.context_text("", "skill_listing") == ["skills one"]
    assert session.context_text("", "session_context") == ["/p", "2026-11-24"]
    for key in ("agent_listing", "deferred_tools", "session_context"):
        assert _item(session, key).measure is not None
        assert _chars(session, key) == _item(session, key).measure.chars, key  # type: ignore[union-attr]


def test_signed_thinking_reports_how_much_of_it_is_readable(tmp_path: Path) -> None:
    thought = [
        {"type": "thinking", "thinking": "abc", "signature": "x" * 90},
        {"type": "thinking", "thinking": "", "signature": "y" * 30},
    ]
    session = _session(tmp_path, [], [_blob("t", "assistant", thought)])
    fields = context_fields(session, "", "thinking")
    assert fields is not None
    assert (fields["readable"], fields["counted"], fields["unread"]) == (3, 120, "signed thinking")
    (tmp_path / "b").mkdir()
    empty = context_fields(_session(tmp_path / "b", [], [_blob("t", "assistant", thought[1:])]), "", "thinking")
    assert empty is not None and empty["unreadable"] is True and (empty["readable"], empty["counted"]) == (0, 30)


def test_tool_definitions_report_how_much_of_their_characters_are_readable(tmp_path: Path) -> None:
    session = _session(tmp_path, [], [_blob("n", "user", _reminder("x"))])
    fields = context_fields(session, "", "tool_definitions")
    assert fields is not None and fields["text"] == "Read\nReads a file"
    assert (fields["readable"], fields["counted"], fields["unread"]) == (
        len("Read\nReads a file"),
        len(compact_json(TOOL, ensure_ascii=False)),
        "tool input schemas",
    )


def test_one_unreadable_row_does_not_refuse_the_text_of_an_item_the_view_sized(tmp_path: Path) -> None:
    before = [
        {"type": "api-request-blob", "hash": 7, "message": {"role": "user", "content": "x"}},
        _attachment(2, type="session_context", context={"cwd": "/p"}),
    ]
    session = _session(tmp_path, before, [_blob("n", "user", _reminder("x"))])
    assert session.context_text("", "session_context") == ["/p"]


def test_an_item_is_labelled_measured_only_when_its_share_was_measured(tmp_path: Path) -> None:
    before = [_attachment(1, type="skill_listing", skillCount=1, content="s" * 400)]
    session = _session(tmp_path, before, [_blob("n", "user", _reminder("x"))])
    assert _item(session, "system_prompt").basis == "measured"
    assert _item(session, "skill_listing").basis == "estimate"


def test_with_no_recorded_request_the_remainder_is_not_called_the_system_prompt(tmp_path: Path) -> None:
    session = _session(tmp_path, [], [_blob("n", "user", _reminder("x"))], request=False)
    own = session.view(RunContext(), {}, XrayCheck("running", None), "newest").nodes[0].detail.in_context.own  # type: ignore[union-attr]
    labels = [item.label for item in own.rows]
    assert "System prompt" not in labels and "System prompt, tools and other built-in context" in labels
    assert {item.basis for item in own.rows} == {"estimate"}
