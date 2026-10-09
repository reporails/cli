"""Which channel `validate` answers on: a Pro reply is one text block, everything else keeps JSON + structured."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.interfaces.mcp import server

_WORKFLOW = {
    "summary": "Rewrite 1 location.",
    "locations": [
        {
            "order": 1,
            "element": "CLAUDE.md",
            "kind": "main",
            "loading": "always",
            "files": ["CLAUDE.md"],
            "importance": "gate_mover",
            "findings": [{"rule": "CORE:C:0001", "line": 3, "message": "m", "remedy": "r", "impact_tier": "cosmetic"}],
            "relations": [],
        }
    ],
}


def _call(tmp_path: Path, monkeypatch, payload: dict[str, Any], **arguments: Any):
    server._validate_states.clear()
    monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: (dict(payload), None, None))
    return asyncio.run(server.server.call_tool("validate", {"path": str(tmp_path), **arguments}))


def _paid() -> dict[str, Any]:
    return {
        "tier": "pro",
        "level": "L2",
        "quality": 8.0,
        "stats": {"total_findings": 1},
        "files": {"CLAUDE.md": {"count": 1, "findings": [{"rule": "CORE:C:0001", "line": 3}]}},
        "workflow": _WORKFLOW,
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_paid_workflow_reply_is_one_text_block(tmp_path: Path, monkeypatch) -> None:
    result = _call(tmp_path, monkeypatch, _paid())
    assert len(result.content) == 1
    assert result.structured_content is None
    assert result.content[0].text.startswith("validate: tier pro")
    assert "workflow.locations:" in result.content[0].text


@pytest.mark.unit
@pytest.mark.subsys_server
def test_full_true_keeps_json_and_structured(tmp_path: Path, monkeypatch) -> None:
    result = _call(tmp_path, monkeypatch, _paid(), full=True)
    assert isinstance(result.structured_content, dict) and "workflow" in result.structured_content
    assert result.content[0].text.startswith("{")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_free_reply_keeps_both_channels(tmp_path: Path, monkeypatch) -> None:
    payload = {
        "tier": "free",
        "level": "L2",
        "files": {"CLAUDE.md": {"count": 1, "findings": [{"rule": "x", "line": 1}]}},
    }
    result = _call(tmp_path, monkeypatch, payload)
    assert isinstance(result.structured_content, dict)
    assert result.content[0].text.startswith("{")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_error_reply_keeps_both_channels(tmp_path: Path, monkeypatch) -> None:
    server._validate_states.clear()
    result = asyncio.run(server.server.call_tool("validate", {"path": str(tmp_path / "missing")}))
    assert isinstance(result.structured_content, dict) and "error" in result.structured_content


@pytest.mark.unit
@pytest.mark.subsys_server
def test_preservation_reply_is_one_text_block(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "CLAUDE.md"
    target.write_text("# P\n\nRun tests.\n", encoding="utf-8")
    preservation = {"ok": True, "score_before": 7.0, "score_after": 8.0, "kept": {"instructions": 1}}
    monkeypatch.setattr(server, "_with_preservation", lambda payload, *a: {**payload, "preservation": preservation})
    monkeypatch.setattr(server, "_with_feedback", lambda payload, *a: {**payload, "feedback": []})
    result = _call(target, monkeypatch, {"tier": "free", "files": {}, "level": "L2"})
    assert len(result.content) == 1 and result.structured_content is None
    assert "preservation.ok: true" in result.content[0].text


@pytest.mark.unit
@pytest.mark.subsys_server
def test_notice_appears_in_the_first_view_only(tmp_path: Path, monkeypatch) -> None:
    payload = {**_paid(), "notices": [{"id": "pay", "level": "warn", "text": "Payment failed", "url": ""}]}
    monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: (dict(payload), None, None))
    server._validate_states.clear()
    first = asyncio.run(server.server.call_tool("validate", {"path": str(tmp_path)}))
    (tmp_path / "CLAUDE.md").write_text("# changed\n", encoding="utf-8")
    second = asyncio.run(server.server.call_tool("validate", {"path": str(tmp_path)}))
    assert "Payment failed" in first.content[0].text
    assert "Payment failed" not in second.content[0].text
