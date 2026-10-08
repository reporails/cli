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


def _call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_workflow: bool = True) -> str:
    path = tmp_path / "CLAUDE.md"
    path.write_text(DOC)
    m = map_instruction_files(tmp_path, [path], spawn_daemon=False)
    payload: dict[str, Any] = {"tier": "pro", "files": {"CLAUDE.md": {"count": 3, "findings": []}}}
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
    text = _call(tmp_path, monkeypatch, with_workflow=False)
    assert "Applying fixes needs a Pro account." in text
    assert (tmp_path / "CLAUDE.md").read_text() == DOC
