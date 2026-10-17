"""`ails expected-loads`: the files Claude Code loads for a session in a folder, and the AGENTS.md it skips."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.pipeline.expected_loads import expected_loads
from reporails_cli.core.platform.config import claude_settings
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


def _write(path: Path, text: str = "# Notes\n\nRun the tests.\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _mode(mode: str) -> None:
    settings = Path.home() / ".claude" / "settings.json"
    data = {"pluginConfigs": {"agents-md@builtin": {"options": {"instructionFiles": mode}}}}
    _write(settings, json.dumps(data))


@pytest.fixture(autouse=True)
def _no_managed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real = claude_settings._settings_patterns

    def patterns() -> dict[str, list[str]]:
        scopes = real()
        scopes["managed"] = [str(tmp_path / "managed" / "managed-settings.json")]
        scopes["managed_dropin"] = [str(tmp_path / "managed" / "d" / "*.json")]
        return scopes

    monkeypatch.setattr(claude_settings, "_settings_patterns", patterns)


def _project(tmp_path: Path) -> Path:
    return tmp_path / "proj"


def _by_name(items: list[dict], root: Path) -> dict[str, dict]:
    return {Path(i["path"]).relative_to(root).as_posix(): i for i in items}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_agents_md_beside_claude_md_is_skipped(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / "AGENTS.md")
    out = expected_loads(root)
    assert _by_name(out["files"], root)["CLAUDE.md"]["file_type"] == "main"
    assert "AGENTS.md" not in _by_name(out["files"], root)
    skipped = _by_name(out["skipped"], root)["AGENTS.md"]
    assert skipped["reason"] == "claude_md_present"
    assert skipped["setting"] == "claude-md-or-agents-md"
    assert skipped["file_type"] == "agents_md"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_lone_agents_md_loads_at_session_start(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "AGENTS.md")
    out = expected_loads(root)
    entry = _by_name(out["files"], root)["AGENTS.md"]
    assert (entry["file_type"], entry["loading"], entry["precedence"]) == ("agents_md", "session_start", "project")
    assert out["skipped"] == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_and_mode_loads_both(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / "AGENTS.md")
    _mode("claude-md-and-agents-md")
    out = expected_loads(root)
    assert {"CLAUDE.md", "AGENTS.md"} <= set(_by_name(out["files"], root))
    assert out["skipped"] == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_claude_md_mode_skips_agents_md_as_setting_off(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "AGENTS.md")
    _mode("claude-md")
    skipped = _by_name(expected_loads(root)["skipped"], root)["AGENTS.md"]
    assert (skipped["reason"], skipped["setting"]) == ("setting_off", "claude-md")


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_agents_dir_is_never_read(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / ".agents" / "AGENTS.md")
    skipped = _by_name(expected_loads(root)["skipped"], root)
    assert skipped[".agents/AGENTS.md"]["reason"] == "never_read"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_nested_agents_md_beside_its_own_claude_md_is_skipped(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "sub" / "AGENTS.md")
    _write(root / "sub" / "CLAUDE.md")
    _write(root / "other" / "AGENTS.md")
    out = expected_loads(root)
    assert _by_name(out["skipped"], root)["sub/AGENTS.md"]["reason"] == "subdir_has_claude_md"
    loaded = _by_name(out["files"], root)["other/AGENTS.md"]
    assert (loaded["file_type"], loaded["loading"]) == ("nested_context", "on_demand")


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_config_surfaces_are_not_listed(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / ".claude" / "settings.json", "{}")
    _write(root / ".claude" / "rules" / "style.md")
    names = set(_by_name(expected_loads(root)["files"], root))
    assert names == {"CLAUDE.md", ".claude/rules/style.md"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_command_prints_one_json_object(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    result = runner.invoke(app, ["expected-loads", str(root), "--agent", "claude"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert list(data) == ["version", "agent", "root", "event_log_dir", "files", "skipped"]
    assert data["version"] == 1
    assert data["agent"] == "claude"
    assert data["event_log_dir"] == str(Path.home() / ".reporails" / "xray")
    assert set(data["files"][0]) == {"path", "file_type", "loading", "precedence"}
