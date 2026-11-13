"""A `validate(path=<file>)` the circuit breaker stops still answers `accepted` for a briefed file."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.interfaces.mcp import remedy_brief, server

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]

_MAP = SimpleNamespace(atoms=(), files=())


@pytest.fixture
def briefed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr("reporails_cli.core.platform.config.bootstrap.REPORAILS_HOME", home / ".reporails")
    root = tmp_path / "proj"
    root.mkdir()
    file = root / "CLAUDE.md"
    file.write_text("# Project\n\nThe build uses a local cache.\n", encoding="utf-8")
    server.validate_states.clear()
    monkeypatch.setattr(server, "unserved_or_model_not_ready_error", lambda: None)
    payload = {"files": {"CLAUDE.md": {"findings": []}}, "stats": {}}
    monkeypatch.setattr(remedy_brief, "run_pipeline_for_path", lambda *_a, **_k: (payload, _MAP, 5.0))
    location = {
        "order": 1, "element": "CLAUDE.md", "kind": "main", "loading": "session_start", "files": ["CLAUDE.md"],
        "importance": "gate_mover", "findings": [], "relations": [],
    }  # fmt: skip
    assert "error" not in remedy_brief.build_remedy_brief(location, root)

    score = {"value": 5.0}

    async def fake_fresh(path: str, tokens: Any, scan_root: Path, state: Any) -> tuple[dict, Any, float]:
        state.full_payload = payload
        state.scan_root = scan_root
        state.last_ruleset_map = _MAP
        state.last_score = score["value"]
        return payload, _MAP, score["value"]

    monkeypatch.setattr(server, "_fresh_validate_payload", fake_fresh)
    return file


def _validate(file: Path) -> dict[str, Any]:
    return asyncio.run(server._run_validate(str(file), False, None, file.parent))


def test_a_tripped_breaker_still_answers_accepted_for_a_briefed_file(briefed: Path) -> None:
    first = _validate(briefed)
    assert first["accepted"] is True
    _validate(briefed)  # the agent's unchanged repeat

    reply = _validate(briefed)  # the loop's re-check

    assert reply["error"] == "circuit_breaker"
    assert reply["accepted"] is True


def test_a_breaker_reply_for_an_unbriefed_path_carries_no_accepted(briefed: Path) -> None:
    other = briefed.parent / "AGENTS.md"
    other.write_text("# Agents\n\nRun the tests.\n", encoding="utf-8")
    for _ in range(3):
        reply = _validate(other)

    assert reply["error"] == "circuit_breaker"
    assert "accepted" not in reply
