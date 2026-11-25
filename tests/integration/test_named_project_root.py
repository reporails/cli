"""A project's root named by path is checked as that project, exactly as `ails check` run inside it.

Its file set, exclusions, agent and config are the project's own: the markdown in it that no agent
loads is not checked as referenced files. A named folder that is not a project's root still has its
markdown checked.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

MAIN_FILE = "# Project\n\nRun `uv run pytest tests/` before every commit.\n\nNEVER edit files under `dist/`.\n"
NOTES = "# Notes\n\nThe release notes live here.\n"
RULE = "# Style\n\nUse four spaces for indentation.\n"


def _git_project(root: Path) -> Path:
    (root / ".git").mkdir(parents=True)
    return root


def _sample(root: Path) -> Path:
    project = _git_project(root)
    (project / "CLAUDE.md").write_text(MAIN_FILE, encoding="utf-8")
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / ".claude" / "rules" / "style.md").write_text(RULE, encoding="utf-8")
    (project / "README.md").write_text(NOTES, encoding="utf-8")
    (project / "docs").mkdir()
    (project / "docs" / "notes.md").write_text(NOTES, encoding="utf-8")
    return project


def _run(monkeypatch: pytest.MonkeyPatch, cwd: Path, *args: str) -> dict:
    monkeypatch.chdir(cwd)
    result = runner.invoke(app, ["check", *args, "-f", "json"])
    return json.loads(result.output[result.output.index("{") :])


def _outcome(data: dict) -> tuple[list[str], object, object]:
    return sorted(data["files"]), data.get("quality"), data.get("level")


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_project_root_named_from_another_git_project_is_checked_as_that_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """From inside one git project, naming another project's root by absolute path gives the files and
    score of `ails check` run inside it; its unloaded markdown is not checked."""
    sample = _sample(tmp_path / "sample")
    elsewhere = _git_project(tmp_path / "elsewhere")

    inside = _run(monkeypatch, sample)
    named = _run(monkeypatch, elsewhere, str(sample))

    assert "README.md" not in inside["files"], sorted(inside["files"])
    assert _outcome(named) == _outcome(inside)
    assert named["not_evaluated"] == inside["not_evaluated"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_project_root_named_from_a_folder_above_it_is_checked_as_that_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """From a plain folder holding the project, `ails check ./sample` gives the files and score of
    `ails check` run inside it."""
    sample = _sample(tmp_path / "sample")

    inside = _run(monkeypatch, sample)
    named = _run(monkeypatch, tmp_path, "./sample")

    assert _outcome(named) == _outcome(inside)


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_folder_that_is_no_project_root_still_has_its_markdown_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A named folder outside the run's project that is not a project's root has its markdown checked."""
    folder = tmp_path / "loose"
    folder.mkdir()
    (folder / "notes.md").write_text(NOTES, encoding="utf-8")
    elsewhere = _sample(tmp_path / "elsewhere")

    named = _run(monkeypatch, elsewhere, str(folder))

    assert any(key.endswith("notes.md") for key in named["files"]), sorted(named["files"])
