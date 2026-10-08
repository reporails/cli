"""`validate(path=<file>)` on a briefed file counts the findings the rewrite introduced.

`remedy_brief` records the per-rule counts of the briefed file's findings; the later
`preservation` block carries `introduced`: for each rule, how many findings the file has now
beyond the count it had at the brief, summed (a rule that fell never subtracts).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.interfaces.mcp import remedy_brief, server, snapshots, tools


def _payload(*rules: str) -> dict[str, Any]:
    return {"files": {"CLAUDE.md": {"findings": [{"rule": r, "line": 1, "message": "m"} for r in rules]}}}


def _brief(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, *rules: str) -> Path:
    snapshots.clear_snapshots()
    file = tmp_path / "CLAUDE.md"
    file.write_text("# Project\n\nThe build uses a local cache.\n", encoding="utf-8")
    fake_map = SimpleNamespace(atoms=(), files=())
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: (_payload(*rules), fake_map, 5.0))
    location = {
        "order": 1, "element": "CLAUDE.md", "kind": "main", "loading": "session_start", "files": ["CLAUDE.md"],
        "importance": "gate_mover", "findings": [], "relations": [],
    }  # fmt: skip
    reply = remedy_brief.build_remedy_brief(location, tmp_path)
    assert "error" not in reply
    return file


def _after(file: Path, tmp_path: Path, *rules: str) -> dict[str, Any]:
    fake_map = SimpleNamespace(atoms=(), files=())
    return server._with_preservation(_payload(*rules), file, fake_map, 5.0, tmp_path)["preservation"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_introduced_sums_each_rule_s_growth_since_the_brief(monkeypatch, tmp_path: Path) -> None:
    file = _brief(monkeypatch, tmp_path, "CORE:C:0042", "CORE:C:0042", "CORE:C:0049")

    # 0042: 2 -> 3 (+1); 0049: 1 -> 0 (never subtracts); 0058: 0 -> 2 (+2).
    block = _after(file, tmp_path, "CORE:C:0042", "CORE:C:0042", "CORE:C:0042", "CORE:C:0058", "CORE:C:0058")

    assert block["introduced"] == 3


@pytest.mark.unit
@pytest.mark.subsys_server
def test_introduced_is_zero_when_the_rewrite_adds_nothing(monkeypatch, tmp_path: Path) -> None:
    file = _brief(monkeypatch, tmp_path, "CORE:C:0042", "CORE:C:0049")

    assert _after(file, tmp_path, "CORE:C:0042")["introduced"] == 0
