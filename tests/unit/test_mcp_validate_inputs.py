"""`validate` serves a stored reply only while nothing the reply depends on has changed."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.interfaces.mcp import server


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AILS_API_KEY", raising=False)
    monkeypatch.setattr("reporails_cli.core.platform.config.bootstrap.REPORAILS_HOME", home / ".reporails")
    root = tmp_path / "proj"
    (root / ".claude").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# Project\n\nRun the tests with pytest.\n", encoding="utf-8")
    (root / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"allow": []}}), encoding="utf-8")
    server._validate_states.clear()
    monkeypatch.setattr(server, "model_not_ready_error", lambda: None)
    return root


@pytest.fixture
def runs(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Every fresh pipeline run, recorded; a cached reply adds nothing."""
    seen: list[int] = []

    async def fake_fresh(path: str, tokens: Any, scan_root: Path, state: Any) -> tuple[dict, Any, float]:
        seen.append(1)
        payload = {"files": {}, "stats": {}}
        state.full_payload = payload
        state.scan_root = scan_root
        return payload, None, 0.0

    monkeypatch.setattr(server, "_fresh_validate_payload", fake_fresh)
    monkeypatch.setattr(server, "_with_preservation", lambda payload, *a, **k: payload)
    return seen


def _call(project: Path, full: bool = False) -> dict[str, Any]:
    return asyncio.run(server._run_validate(str(project), full))


def _rewrite(path: Path, text: str) -> None:
    """Write `text` and keep the size, so only the content (and its mtime) differs."""
    before = path.stat().st_mtime_ns if path.exists() else 0
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    assert path.stat().st_mtime_ns != before or before == 0


@pytest.mark.unit
@pytest.mark.subsys_server
def test_no_change_is_served_from_the_stored_reply_and_counted(project: Path, runs: list[int]) -> None:
    _call(project)
    _call(project)
    assert len(runs) == 1
    state = next(iter(server._validate_states.values()))
    assert state.consecutive_unchanged == 1
    assert _call(project).get("error") == "circuit_breaker"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_full_repeat_without_change_does_not_count(project: Path, runs: list[int]) -> None:
    _call(project)
    _call(project, full=True)
    assert len(runs) == 1
    assert next(iter(server._validate_states.values())).consecutive_unchanged == 0


@pytest.mark.unit
@pytest.mark.subsys_server
def test_agent_config_edit_gets_a_fresh_reply(project: Path, runs: list[int]) -> None:
    _call(project)
    _rewrite(project / ".claude" / "settings.json", json.dumps({"permissions": {"deny": ["Read(./.env)"]}}))
    reply = _call(project)
    assert reply.get("error") is None
    assert len(runs) == 2
    assert next(iter(server._validate_states.values())).consecutive_unchanged == 0


@pytest.mark.unit
@pytest.mark.subsys_server
def test_edit_inside_one_clock_tick_is_not_missed(project: Path, runs: list[int]) -> None:
    import os

    cfg = project / ".claude" / "settings.json"
    _call(project)
    stat = cfg.stat()
    cfg.write_text(json.dumps({"permissions": {"allow": ["x"]}}), encoding="utf-8")
    os.utime(cfg, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    _call(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_project_config_edit_gets_a_fresh_reply(project: Path, runs: list[int]) -> None:
    _call(project)
    _rewrite(project / ".ails" / "config.yml", "exclude_dirs:\n  - docs\n")
    _call(project)
    assert len(runs) == 2
    _rewrite(project / ".ails" / "config.yml", "exclude_dirs:\n  - src\n")
    _call(project)
    assert len(runs) == 3


@pytest.mark.unit
@pytest.mark.subsys_server
def test_user_config_edit_gets_a_fresh_reply(project: Path, runs: list[int]) -> None:
    _call(project)
    _rewrite(Path.home() / ".reporails" / "config.yml", "disabled_rules:\n  - CLAUDE:S:0001\n")
    _call(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_tier_change_gets_a_fresh_reply(project: Path, runs: list[int]) -> None:
    _rewrite(Path.home() / ".reporails" / "config.yml", "tier: free\n")
    _call(project)
    _call(project)
    assert len(runs) == 1
    _rewrite(Path.home() / ".reporails" / "config.yml", "tier: pro\n")
    _call(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_signing_in_gets_a_fresh_reply(project: Path, runs: list[int], monkeypatch: pytest.MonkeyPatch) -> None:
    _call(project)
    monkeypatch.setenv("AILS_API_KEY", "synthetic-key-value")
    _call(project)
    assert len(runs) == 2
    _call(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_stored_credentials_appearing_gets_a_fresh_reply(project: Path, runs: list[int]) -> None:
    _call(project)
    _rewrite(Path.home() / ".reporails" / "credentials.yml", "api_key: synthetic-key-value\n")
    _call(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_new_config_file_gets_a_fresh_reply(project: Path, runs: list[int]) -> None:
    _call(project)
    _rewrite(project / ".mcp.json", json.dumps({"mcpServers": {}}))
    _call(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_deleted_config_file_gets_a_fresh_reply(project: Path, runs: list[int]) -> None:
    _call(project)
    (project / ".claude" / "settings.json").unlink()
    _call(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_key_value_is_not_part_of_the_stored_fingerprint(
    project: Path, runs: list[int], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AILS_API_KEY", "synthetic-key-value")
    _call(project)
    state = next(iter(server._validate_states.values()))
    assert "synthetic-key-value" not in state.last_mtime_hash


SUPPORT = Path(".claude") / "skills" / "demo" / "references" / "notes.md"


@pytest.fixture
def mapped(project: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[list[int], list[str]]:
    """A skill with a supporting file; each fresh run reports on the files in `mapped_paths`."""
    skill = project / ".claude" / "skills" / "demo"
    (skill / "references").mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: demo\ndescription: Demo.\n---\n\nSee references/notes.md.\n")
    (project / SUPPORT).write_text("# Notes\n\nKeep the notes short.\n", encoding="utf-8")
    seen: list[int] = []
    mapped_paths: list[str] = []

    async def fake_fresh(path: str, tokens: Any, scan_root: Path, state: Any) -> tuple[dict, Any, float]:
        seen.append(1)
        # The supporting file is reported on in the reply but is not one of the map's records.
        payload = {"files": {p: {"findings": []} for p in mapped_paths}, "stats": {}}
        state.full_payload = payload
        state.scan_root = scan_root
        state.last_ruleset_map = SimpleNamespace(files=())
        return payload, state.last_ruleset_map, 0.0

    monkeypatch.setattr(server, "_fresh_validate_payload", fake_fresh)
    monkeypatch.setattr(server, "_with_preservation", lambda payload, *a, **k: payload)
    return seen, mapped_paths


def _call_path(path: Path, full: bool = False) -> dict[str, Any]:
    return asyncio.run(server._run_validate(str(path), full))


@pytest.mark.unit
@pytest.mark.subsys_server
def test_edit_to_a_mapped_supporting_file_is_seen_by_a_file_validate(
    project: Path, mapped: tuple[list[int], list[str]]
) -> None:
    runs, mapped_paths = mapped
    mapped_paths.append(str(SUPPORT))
    _call_path(project / SUPPORT)
    _rewrite(project / SUPPORT, "# Notes\n\nA different, longer text for the notes.\n")
    _call_path(project / SUPPORT)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_edit_to_a_mapped_supporting_file_is_seen_by_a_project_validate(
    project: Path, mapped: tuple[list[int], list[str]]
) -> None:
    runs, mapped_paths = mapped
    mapped_paths.append(str(SUPPORT))
    _call_path(project)
    _call_path(project)
    assert len(runs) == 1
    _rewrite(project / SUPPORT, "# Notes\n\nA different, longer text for the notes.\n")
    _call_path(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_deleted_mapped_supporting_file_is_seen(project: Path, mapped: tuple[list[int], list[str]]) -> None:
    runs, mapped_paths = mapped
    mapped_paths.append(str(SUPPORT))
    _call_path(project)
    (project / SUPPORT).unlink()
    _call_path(project)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_file_target_the_scan_does_not_find_is_covered_before_any_run_maps_it(
    project: Path, mapped: tuple[list[int], list[str]]
) -> None:
    runs, _ = mapped
    _call_path(project / SUPPORT)
    _rewrite(project / SUPPORT, "# Notes\n\nA different, longer text for the notes.\n")
    _call_path(project / SUPPORT)
    assert len(runs) == 2


@pytest.mark.unit
@pytest.mark.subsys_server
def test_unchanged_calls_are_served_and_counted_around_a_mapped_file_edit(
    project: Path, mapped: tuple[list[int], list[str]]
) -> None:
    runs, mapped_paths = mapped
    mapped_paths.append(str(SUPPORT))
    state_of = lambda: next(iter(server._validate_states.values()))  # noqa: E731
    assert "error" not in _call_path(project)
    assert "error" not in _call_path(project)
    assert (len(runs), state_of().consecutive_unchanged) == (1, 1)
    assert _call_path(project).get("error") == "circuit_breaker"
    assert len(runs) == 1
    _rewrite(project / SUPPORT, "# Notes\n\nA different, longer text for the notes.\n")
    assert "error" not in _call_path(project)
    assert (len(runs), state_of().consecutive_unchanged) == (2, 0)
    assert "error" not in _call_path(project)
    assert (len(runs), state_of().consecutive_unchanged) == (2, 1)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_run_that_maps_more_files_does_not_read_as_a_change_on_the_next_call(
    project: Path, mapped: tuple[list[int], list[str]]
) -> None:
    runs, mapped_paths = mapped
    mapped_paths.append(str(SUPPORT))
    _call_path(project)
    mapped_paths.append("CLAUDE.md")
    _rewrite(project / SUPPORT, "# Notes\n\nA different, longer text for the notes.\n")
    _call_path(project)
    assert len(runs) == 2
    _call_path(project)
    assert len(runs) == 2
    assert next(iter(server._validate_states.values())).consecutive_unchanged == 1


@pytest.fixture
def pipeline_replies(project: Path, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """The real `_fresh_validate_payload`, fed by a pipeline stub that answers from a queue."""
    replies: list[dict[str, Any]] = []
    monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full: (replies.pop(0), None, 0.0))
    monkeypatch.setattr(server, "_with_preservation", lambda payload, *a, **k: payload)
    return replies


@pytest.mark.unit
@pytest.mark.subsys_server
def test_signed_in_free_reply_is_not_reused_after_an_upgrade(
    project: Path, pipeline_replies: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AILS_API_KEY", "synthetic-key-value")
    free = {"files": {}, "stats": {}, "tier": "free"}
    pro = {"files": {}, "stats": {}, "tier": "pro", "workflow": {"locations": []}}
    pipeline_replies.extend([free, pro])
    assert "workflow" not in _call(project, full=True)
    second = _call(project, full=True)
    assert second.get("error") is None
    assert second.get("tier") == "pro"
    assert "workflow" in second


@pytest.mark.unit
@pytest.mark.subsys_server
def test_signed_in_free_replies_do_not_trip_the_circuit_breaker(
    project: Path, pipeline_replies: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AILS_API_KEY", "synthetic-key-value")
    pipeline_replies.extend({"files": {}, "stats": {}, "tier": "free"} for _ in range(4))
    for _ in range(4):
        assert _call(project).get("error") is None
