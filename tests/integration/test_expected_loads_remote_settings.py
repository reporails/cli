"""`ails expected-loads` reads the cache of the organization's server-managed settings, run through the real CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PLUGIN_ID = "cc-plugin-agents-md@builtin"
# Claude Code's machine-wide managed folders, which `expected-loads` reads whatever HOME is.
MANAGED_FOLDERS = ("/etc/claude-code", "/Library/Application Support/ClaudeCode", "C:/Program Files/ClaudeCode")


def _mode(value: str) -> dict:
    return {"pluginConfigs": {PLUGIN_ID: {"options": {"instructionFiles": value}}}}


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run(project: Path, home: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "NO_COLOR": "1"}
    return subprocess.run(
        [sys.executable, "-m", "reporails_cli", "expected-loads", str(project), "--agent", "claude"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
        env=env,
    )


def _setup(tmp_path: Path, remote: str | None, user: dict | None = None) -> tuple[Path, Path]:
    for folder in MANAGED_FOLDERS:
        if Path(folder).exists():
            pytest.skip(f"managed Claude Code files at {folder} would be read beside the isolated HOME's")
    home, project = tmp_path / "home", tmp_path / "proj"
    _write(project / "AGENTS.md", "# Notes\n\nRun the tests.\n")
    if remote is not None:
        _write(home / ".claude" / "remote-settings.json", remote)
    if user is not None:
        _write(home / ".claude" / "settings.json", json.dumps(user))
    home.mkdir(exist_ok=True)
    return project, home


def _skipped(proc: subprocess.CompletedProcess[str], project: Path) -> bool:
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout)
    return any(Path(i["path"]) == project / "AGENTS.md" for i in out["skipped"])


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_remote_cache_mode_changes_what_expected_loads_skips(tmp_path: Path) -> None:
    project, home = _setup(tmp_path, json.dumps(_mode("claude-md")))
    assert _skipped(_run(project, home), project)


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_remote_cache_outranks_the_users_own_mode(tmp_path: Path) -> None:
    project, home = _setup(tmp_path, json.dumps(_mode("claude-md")), user=_mode("claude-md-and-agents-md"))
    assert _skipped(_run(project, home), project)


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_empty_remote_cache_changes_nothing(tmp_path: Path) -> None:
    project, home = _setup(tmp_path, "{}")
    assert not _skipped(_run(project, home), project)


@pytest.mark.integration
@pytest.mark.subsys_classify
@pytest.mark.parametrize("text", ["{not json", "[]", ""])
def test_malformed_remote_cache_ends_expected_loads_with_exit_2(tmp_path: Path, text: str) -> None:
    project, home = _setup(tmp_path, text)
    proc = _run(project, home)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "remote-settings.json" in proc.stderr
    assert "Traceback" not in proc.stderr


@pytest.mark.integration
@pytest.mark.subsys_classify
def test_malformed_remote_cache_ends_ails_check_with_exit_2_not_a_traceback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner  # pylint: disable=import-outside-toplevel  # only this test drives the app

    from reporails_cli.interfaces.cli.main import app  # pylint: disable=import-outside-toplevel  # as above

    project, home = _setup(tmp_path, "{not json")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.chdir(project)
    result = CliRunner().invoke(app, ["check", ".", "--agent", "claude"])
    assert result.exit_code == 2, result.output
    assert "remote-settings.json" in result.output
    assert "Traceback" not in result.output
    assert not isinstance(result.exception, Exception) or isinstance(result.exception, SystemExit)
