"""A project whose instructions are Cursor rules is found and checked without `--agent`,
a Claude+Cursor project lists every agent's files, and a run pinned to one agent that finds
nothing says the project has another agent's files instead of asking for that agent's file."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

_WEAK = "# Rules\n\nYou should maybe try to run tests sometimes.\n\nNEVER commit secrets.\n"
_MDC = "---\nalwaysApply: true\n---\n\n" + _WEAK


def _cursor_project(tmp_path: Path, *, claude: bool = False) -> Path:
    project = tmp_path / "proj"
    (project / ".cursor" / "rules").mkdir(parents=True)
    (project / ".cursor" / "rules" / "always.mdc").write_text(_MDC, encoding="utf-8")
    if claude:
        (project / "CLAUDE.md").write_text(_WEAK, encoding="utf-8")
    return project


def _check_json(project: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", ".", "-f", "json"])
    assert result.exit_code in (0, 1), result.output
    return json.loads(result.output[result.output.index("{") :])


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_cursor_only_project_is_checked_without_agent_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _check_json(_cursor_project(tmp_path), monkeypatch)
    assert ".cursor/rules/always.mdc" in data["files"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_mixed_project_lists_every_agents_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _check_json(_cursor_project(tmp_path, claude=True), monkeypatch)
    assert {"CLAUDE.md", ".cursor/rules/always.mdc"} <= set(data["files"])


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_pinned_agent_with_no_files_points_at_the_agent_the_project_has(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _cursor_project(tmp_path)
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", ".", "--agent", "claude"])
    assert "No instruction files found for claude" in result.output
    assert "cursor" in result.output
    assert "Create a CLAUDE.md" not in result.output


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_unpinned_check_of_an_empty_folder_keeps_the_usual_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _cursor_project(tmp_path, claude=True)
    (project / "docs").mkdir()
    (project / "docs" / "readme.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_config_path",
        lambda: tmp_path / "home" / "config.yml",
    )
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "docs"])
    assert "No instruction files found." in result.output
    assert "for generic" not in result.output
    assert "--agent" not in result.output
    assert "default_agent" not in result.output


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_pinned_check_of_an_empty_folder_keeps_the_usual_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _cursor_project(tmp_path)
    (project / "docs").mkdir()
    (project / "docs" / "readme.txt").write_text("hello\n", encoding="utf-8")
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_config_path",
        lambda: tmp_path / "home" / "config.yml",
    )
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "docs", "--agent", "claude"])
    assert "No instruction files found." in result.output
    assert "This project has files for" not in result.output


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_agent_set_in_config_with_no_files_points_at_the_agent_the_project_has(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    (home / ".reporails").mkdir(parents=True)
    (home / ".reporails" / "config.yml").write_text("default_agent: claude\n", encoding="utf-8")
    monkeypatch.setattr(
        "reporails_cli.core.platform.config.bootstrap.get_global_config_path",
        lambda: home / ".reporails" / "config.yml",
    )
    project = _cursor_project(tmp_path)
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "."])
    assert "No instruction files found for claude" in result.output
    assert "This project has files for: cursor" in result.output
