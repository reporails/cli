"""A project-level `validate` frees a briefed file's baseline only once the file is settled."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.mapper.pipeline import map_ruleset
from reporails_cli.interfaces.mcp import remedy_brief, server, snapshots
from tests.fake_models import no_models

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server, pytest.mark.requires_model]

_HEAD = "# Project\n\n## Rules\n\n- Run `pytest` before every commit.\n"
_TAIL = "- Use `ruff` for linting.\n"
ORIGINAL = _HEAD + "- Never push directly to `main`.\n" + _TAIL
DROPPED = _HEAD + _TAIL
KEPT = ORIGINAL + "\n"
PAYLOAD: dict[str, Any] = {}  # the payload every pipeline run answers with; a test sets its own
LOCATION = {
    "order": 1, "element": "CLAUDE.md", "kind": "main", "loading": "session_start", "files": ["CLAUDE.md"],
    "importance": "gate_mover", "findings": [], "relations": [],
}  # fmt: skip


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr("reporails_cli.core.platform.config.bootstrap.REPORAILS_HOME", home / ".reporails")
    root = tmp_path / "proj"
    root.mkdir()
    file = root / "CLAUDE.md"
    file.write_text(ORIGINAL, encoding="utf-8")
    PAYLOAD.clear()
    PAYLOAD.update({"files": {"CLAUDE.md": {"findings": []}}, "stats": {}})
    server.validate_states.clear()
    for store in (snapshots._snapshots, snapshots._plans, snapshots._rule_counts):
        store.clear()
    snapshots._released.clear()
    snapshots._accepted_text.clear()
    snapshots._recorded.clear()

    def pipeline(path: Any, *_a: Any, **_k: Any) -> tuple[dict, Any, float]:
        ruleset_map = map_ruleset([Path(path)], models=no_models(), root=root, cache_dir=None)
        return dict(PAYLOAD), ruleset_map, 5.0

    async def fresh(
        path: str, tokens: Any, scan_root: Path, state: Any, models: Any, *, run: Any
    ) -> tuple[dict, Any, float]:
        payload, ruleset_map, score = pipeline(file)
        state.full_payload, state.scan_root = payload, scan_root
        state.last_ruleset_map, state.last_score = ruleset_map, score
        return payload, ruleset_map, score

    monkeypatch.setattr(remedy_brief, "run_pipeline_for_path", pipeline)
    monkeypatch.setattr(server, "_fresh_validate_payload", fresh)
    monkeypatch.setattr(server, "unserved_or_model_not_ready_error", lambda _run: None)
    return root, file


def _validate(target: Path, root: Path) -> dict[str, Any]:
    return asyncio.run(server._run_validate(str(target), False, None, root, no_models()))


def _brief(root: Path) -> None:
    assert "error" not in remedy_brief.build_remedy_brief(
        LOCATION, root, preservation_contract="Keep everything.", models=no_models()
    )


def test_a_rewrite_failing_the_check_is_not_accepted_after_a_project_validate(project: tuple[Path, Path]) -> None:
    root, file = project
    _brief(root)
    file.write_text(DROPPED, encoding="utf-8")
    assert _validate(file, root).get("accepted") is not True
    _validate(root, root)
    _brief(root)

    reply = _validate(file, root)

    assert reply.get("accepted") is not True
    snap = snapshots.get_snapshot(file)
    assert snap is not None
    assert snap.text == ORIGINAL


def test_an_accepted_rewrite_becomes_the_baseline_after_a_project_validate(
    project: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, file = project
    monkeypatch.setattr(snapshots, "check_conformance", lambda *_a, **_k: {"ok": True, "deviations": []})
    _brief(root)
    file.write_text(KEPT, encoding="utf-8")
    assert _validate(file, root)["accepted"] is True
    _validate(root, root)
    _brief(root)

    snap = snapshots.get_snapshot(file)
    assert snap is not None
    assert snap.text == KEPT


def _heal_record(root: Path) -> dict[str, Any]:
    path = root / ".ails" / "reports" / "heal-latest.json"
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def test_a_project_validate_records_each_kept_file_with_its_score_and_finding_counts(
    project: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, file = project
    monkeypatch.setattr(snapshots, "check_conformance", lambda *_a, **_k: {"ok": True, "deviations": []})
    found = [{"rule": "CORE:C:0058"}, {"rule": "CORE:C:0058"}, {"rule": "CORE:S:0001"}]
    PAYLOAD["files"] = {"CLAUDE.md": {"findings": found}}
    PAYLOAD["file_scores"] = {"CLAUDE.md": 8.4}
    _brief(root)
    file.write_text(KEPT, encoding="utf-8")
    assert _validate(file, root)["accepted"] is True
    assert _heal_record(root) == {}  # a single-file validate records nothing

    _validate(root, root)

    entry = _heal_record(root)["files"]["CLAUDE.md"]
    assert (entry["score"], entry["rules"]) == (8.4, {"CORE:C:0058": 2, "CORE:S:0001": 1})
    assert entry["healed_at"]


def test_a_file_never_accepted_is_not_recorded(project: tuple[Path, Path]) -> None:
    root, file = project
    _brief(root)
    file.write_text(DROPPED, encoding="utf-8")
    assert _validate(file, root).get("accepted") is not True

    _validate(root, root)

    assert _heal_record(root) == {}


def test_a_hand_edit_between_two_runs_becomes_the_next_baseline(project: tuple[Path, Path]) -> None:
    root, file = project
    user_text = ORIGINAL + _TAIL.replace("ruff", "mypy")
    _brief(root)
    file.write_text(DROPPED, encoding="utf-8")
    assert _validate(file, root).get("accepted") is not True
    file.write_text(ORIGINAL, encoding="utf-8")
    _validate(root, root)
    file.write_text(user_text, encoding="utf-8")
    _validate(root, root)
    _brief(root)

    snap = snapshots.get_snapshot(file)
    assert snap is not None
    assert snap.text == user_text
