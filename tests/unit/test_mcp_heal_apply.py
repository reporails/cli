"""`heal_apply`: every fix that needs no judgment in one call, each written file checked, a departing file put back."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.pipeline.mapping import map_instruction_files
from reporails_cli.interfaces.mcp import server

pytestmark = [pytest.mark.unit, pytest.mark.subsys_heal]

DOC = """# Demo

Always run the **linter** before you commit.

Never edit **generated** files by hand.

Run build.sh before every commit.
"""


def _wire(tmp_path: Path, m: Any, rows: tuple[tuple[int, str, str], ...]) -> dict[str, Any]:
    def pi(line: int) -> int | None:
        return next((a.position_index for a in m.atoms if a.line == line), None)

    findings = [
        {"rule": r, "file": "CLAUDE.md", "line": ln, "pi": pi(ln), "op": op, "expect": {}} for ln, op, r in rows
    ]
    loc = {"order": 1, "element": "CLAUDE.md", "kind": "main", "loading": "always", "files": ["CLAUDE.md"]}
    return {"summary": "", "locations": [{**loc, "importance": "", "findings": findings, "relations": []}]}


def _call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_workflow: bool = True, tier: str = "pro") -> str:
    path = tmp_path / "CLAUDE.md"
    path.write_text(DOC)
    m = map_instruction_files(tmp_path, [path], spawn_daemon=False)
    payload: dict[str, Any] = {"tier": tier, "files": {"CLAUDE.md": {"count": 3, "findings": []}}}
    if with_workflow:
        payload["workflow"] = _wire(tmp_path, m, ((3, "unbold", "bold"), (7, "code", "format")))
    server._validate_states.clear()
    monkeypatch.setattr(server, "model_not_ready_error", lambda: None)
    monkeypatch.setattr(server, "run_pipeline_for_path", lambda p, full=False: (dict(payload), m, None))
    result = asyncio.run(server.server.call_tool("heal_apply", {"path": str(tmp_path)}))
    assert len(result.content) == 1 and result.structured_content is None
    return result.content[0].text  # type: ignore[no-any-return]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_heal_apply_writes_every_fix_and_reports_them(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    text = _call(tmp_path, monkeypatch)
    lines = text.splitlines()
    assert lines[0] == "heal_apply: 2 fixed · 0 left for a decision · 0 put back"
    assert lines[1] == "CLAUDE.md  2 fixed"
    body = (tmp_path / "CLAUDE.md").read_text()
    assert "*linter*" in body and "`build.sh`" in body


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_heal_apply_puts_back_a_file_that_departs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import reporails_cli.core.heal.keyed as keyed

    original_apply = keyed.apply_edits

    def touching_neighbour(lines: Any, edits: Any) -> Any:
        body, where = original_apply(lines, edits)
        body[0] += " extra"
        return body, where

    monkeypatch.setattr(keyed, "apply_edits", touching_neighbour)
    text = _call(tmp_path, monkeypatch)
    assert text.splitlines()[0] == "heal_apply: 0 fixed · 0 left for a decision · 1 put back"
    assert "put back: CLAUDE.md (outside  line 1)" in text
    assert (tmp_path / "CLAUDE.md").read_text() == DOC


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_heal_apply_without_a_workflow_writes_nothing_and_says_pro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
    text = _call(tmp_path, monkeypatch, with_workflow=False, tier="free")
    assert "Applying fixes needs a Pro account." in text
    assert (tmp_path / "CLAUDE.md").read_text() == DOC


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    "payload",
    [
        {"offline": True, "server_error": None},
        {"offline": False, "server_error": {"error": "rate_limited"}},
        {"tier": "pro", "funnel": {"retryable": True}},
    ],
)
def test_heal_apply_with_a_key_and_no_server_reply_does_not_say_pro(
    payload: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    from reporails_cli.interfaces.mcp.heal_apply import heal_apply_message

    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
    text = heal_apply_message(payload)
    assert "Pro account" not in text
    assert text == "heal_apply: The server sent no fixes, so nothing was changed."


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_apply_with_a_key_and_a_clean_reply_without_fixes_says_pro(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.interfaces.mcp.heal_apply import heal_apply_message

    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
    assert "Applying fixes needs a Pro account." in heal_apply_message({"tier": "free"})
    assert "no fixes" in heal_apply_message({"tier": "pro"}, mapped=False)


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_apply_without_a_key_points_at_sign_in(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.heal.apply import HEAL_SIGN_IN
    from reporails_cli.interfaces.mcp.heal_apply import heal_apply_message

    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: False)
    assert HEAL_SIGN_IN in heal_apply_message({"offline": True})


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_put_back_line_names_the_failed_check_when_no_op_is_named() -> None:
    from reporails_cli.formatters.mcp_view import render_heal_apply

    entry = {"file": "A.md", "op": "", "rule": "", "line": 5, "check": "preservation:order"}
    text = render_heal_apply([], [], [entry], Path("."))
    assert "put back: A.md (preservation:order line 5)" in text
    named = {"file": "A.md", "op": "bold", "rule": "CORE:S:0001", "line": 3, "check": "conformance"}
    assert "put back: A.md (bold CORE:S:0001 line 3)" in render_heal_apply([], [], [named], Path("."))


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_apply_for_a_paid_reply_without_fixes_does_not_say_pro(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.interfaces.mcp.heal_apply import heal_apply_message

    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
    assert "Pro account" not in heal_apply_message({"tier": "pro"})


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_apply_for_a_rejected_key_points_at_sign_in(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.heal.apply import HEAL_SIGN_IN
    from reporails_cli.interfaces.mcp.heal_apply import heal_apply_message

    monkeypatch.setattr("reporails_cli.core.platform.adapters.api_client.has_api_key", lambda: True)
    payload = {"offline": True, "funnel": {"error": "invalid_api_key", "tier": "anonymous"}}
    assert HEAL_SIGN_IN in heal_apply_message(payload)
