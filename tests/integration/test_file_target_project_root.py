"""A file target roots on its own project, never on the home directory or an unrelated folder.

A user-level agent folder (`~/.claude`) is checked on its own: nothing outside it is read. Only an
agent's own config folder gives a project boundary when no `.git`, `.ails` or IDE folder exists
above the file, and the outermost one wins.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.discovery.agent_discovery import resolve_project_root_for_file
from reporails_cli.interfaces.cli import check_orchestration as orch
from reporails_cli.interfaces.cli.main import app
from reporails_cli.interfaces.mcp import tools

runner = CliRunner()

_MAIN_TEXT = "# Notes\n\nAlways run the tests before committing.\n"
_BAD_HOOK_SETTINGS = '{"hooks": {"PreToolUse2": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}\n'


@pytest.fixture
def scratch_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home with two unrelated project folders; one holds a directory that raises on read."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    (home / "other-a" / "src").mkdir(parents=True)
    (home / "other-a" / "CLAUDE.md").write_text(_MAIN_TEXT, encoding="utf-8")
    locked = home / "other-b" / "locked"
    locked.mkdir(parents=True)
    (locked / "CLAUDE.md").write_text(_MAIN_TEXT, encoding="utf-8")
    locked.chmod(0)
    yield home
    locked.chmod(0o755)


@pytest.fixture
def reads_outside(scratch_home: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every directory listing under the scratch home that lies outside `~/.claude`."""
    seen: list[str] = []
    allowed = scratch_home / ".claude"

    def note(path: object) -> None:
        try:
            p = Path(os.fspath(path)).absolute()  # type: ignore[arg-type]
        except TypeError:
            return
        if p.is_relative_to(scratch_home) and not (p == allowed or p.is_relative_to(allowed)):
            seen.append(str(p))

    real_scandir, real_listdir, real_walk = os.scandir, os.listdir, os.walk

    def scandir(path: object = ".") -> object:
        note(path)
        return real_scandir(path)  # type: ignore[arg-type]

    def listdir(path: object = ".") -> list[str]:
        note(path)
        return real_listdir(path)  # type: ignore[arg-type]

    def walk(top: object, *args: object, **kwargs: object) -> Iterator[object]:
        note(top)
        return real_walk(top, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(os, "listdir", listdir)
    monkeypatch.setattr(os, "walk", walk)
    return seen


def _write_user_level(home: Path) -> tuple[Path, Path]:
    user_dir = home / ".claude"
    user_dir.mkdir()
    main = user_dir / "CLAUDE.md"
    main.write_text(_MAIN_TEXT, encoding="utf-8")
    config = user_dir / "settings.json"
    config.write_text(_BAD_HOOK_SETTINGS, encoding="utf-8")
    return main, config


def _check(cwd: Path, target: Path) -> dict:
    previous = os.getcwd()
    os.chdir(cwd)
    try:
        result = runner.invoke(app, ["check", str(target), "--agent", "claude", "-f", "json"])
    finally:
        os.chdir(previous)
    assert result.exit_code in (0, 1), result.output
    return json.loads(result.output)


def _findings(payload: dict) -> set[tuple[str, int]]:
    return {(f["rule"], f["line"]) for entry in payload["files"].values() for f in entry.get("findings", [])}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_user_level_agent_folder_is_its_own_project_root(scratch_home: Path) -> None:
    main, config = _write_user_level(scratch_home)
    assert resolve_project_root_for_file(main) == scratch_home / ".claude"
    assert resolve_project_root_for_file(config) == scratch_home / ".claude"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_user_level_file_roots_the_same_when_checked_from_the_home_directory(scratch_home: Path) -> None:
    main, _ = _write_user_level(scratch_home)
    assert orch._scan_root(main, main, scratch_home) == (None, scratch_home / ".claude")
    assert tools._resolve_scan_target(main) == (scratch_home / ".claude", main)


@pytest.mark.integration
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_checking_a_user_level_file_reads_nothing_outside_its_folder(
    scratch_home: Path, reads_outside: list[str], tmp_path: Path
) -> None:
    main, config = _write_user_level(scratch_home)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for target in (main, config):
        payload = _check(elsewhere, target)
        assert reads_outside == []
        assert list(payload["files"]) == [target.name]


@pytest.mark.integration
@pytest.mark.subsys_cli_ux
def test_validating_a_user_level_file_reads_nothing_outside_its_folder(
    scratch_home: Path, reads_outside: list[str]
) -> None:
    main, config = _write_user_level(scratch_home)
    for target in (main, config):
        payload = tools.validate_tool(str(target), full=True)
        assert reads_outside == []
        assert list(payload["files"]) == [target.name]


@pytest.mark.integration
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_a_user_level_file_draws_the_findings_it_draws_as_a_project_file(scratch_home: Path, tmp_path: Path) -> None:
    main, config = _write_user_level(scratch_home)
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    (project / "CLAUDE.md").write_text(_MAIN_TEXT, encoding="utf-8")
    (project / ".claude" / "settings.json").write_text(_BAD_HOOK_SETTINGS, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    for user_file, project_file in ((main, project / "CLAUDE.md"), (config, project / ".claude" / "settings.json")):
        user_findings = _findings(_check(elsewhere, user_file))
        assert user_findings
        assert user_findings == _findings(_check(elsewhere, project_file))


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_hidden_folder_that_is_not_an_agent_folder_is_no_project_boundary(tmp_path: Path) -> None:
    notes = tmp_path / "a" / ".config" / "tool" / "sub"
    notes.mkdir(parents=True)
    (notes / "notes.md").write_text("# Notes\n", encoding="utf-8")
    assert resolve_project_root_for_file(notes / "notes.md") == notes


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_hidden_folder_inside_an_agent_folder_does_not_end_the_walk(tmp_path: Path) -> None:
    hidden = tmp_path / "proj" / ".claude" / "skills" / ".hidden"
    hidden.mkdir(parents=True)
    (hidden / "SKILL.md").write_text("# Skill\n", encoding="utf-8")
    assert resolve_project_root_for_file(hidden / "SKILL.md") == tmp_path / "proj"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_the_outermost_agent_folder_wins(tmp_path: Path) -> None:
    inner = tmp_path / "proj" / ".claude" / "skills" / "x" / ".codex"
    inner.mkdir(parents=True)
    (inner / "note.md").write_text("# Note\n", encoding="utf-8")
    assert resolve_project_root_for_file(inner / "note.md") == tmp_path / "proj"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_stronger_markers_still_decide_the_root(tmp_path: Path) -> None:
    (tmp_path / "git-proj" / ".git").mkdir(parents=True)
    (tmp_path / "git-proj" / "pkg" / ".claude").mkdir(parents=True)
    git_file = tmp_path / "git-proj" / "pkg" / ".claude" / "x.md"
    git_file.write_text("# X\n", encoding="utf-8")
    assert resolve_project_root_for_file(git_file) == tmp_path / "git-proj"

    (tmp_path / "ide-proj" / ".vscode").mkdir(parents=True)
    (tmp_path / "ide-proj" / ".claude").mkdir()
    ide_file = tmp_path / "ide-proj" / ".claude" / "x.md"
    ide_file.write_text("# X\n", encoding="utf-8")
    assert resolve_project_root_for_file(ide_file) == tmp_path / "ide-proj"

    (tmp_path / "ails-proj" / ".ails").mkdir(parents=True)
    (tmp_path / "ails-proj" / ".ails" / "backbone.yml").write_text("modules: []\n", encoding="utf-8")
    (tmp_path / "ails-proj" / "deep" / ".claude").mkdir(parents=True)
    ails_file = tmp_path / "ails-proj" / "deep" / ".claude" / "x.md"
    ails_file.write_text("# X\n", encoding="utf-8")
    assert resolve_project_root_for_file(ails_file) == tmp_path / "ails-proj"


@pytest.mark.integration
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_a_misspelled_hook_event_is_reported_in_a_project_with_no_git_checked_from_anywhere(
    scratch_home: Path, tmp_path: Path
) -> None:
    project = scratch_home / "proj"
    (project / ".claude").mkdir(parents=True)
    settings = project / ".claude" / "settings.json"
    settings.write_text(_BAD_HOOK_SETTINGS, encoding="utf-8")
    (project / "CLAUDE.md").write_text(_MAIN_TEXT, encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    assert resolve_project_root_for_file(settings) == project
    assert orch._scan_root(settings, settings, elsewhere) == (None, project)
    assert tools._resolve_scan_target(settings) == (project, settings)

    cli = _check(elsewhere, settings)
    assert list(cli["files"]) == [".claude/settings.json"]
    assert ("CLAUDE:G:0001", 1) in _findings(cli)
    mcp = tools.validate_tool(str(settings), full=True)
    assert _findings(mcp) == _findings(cli)
