"""The folder `ails check` runs in is the project root; a folder inside it is checked within that
project; a folder outside it is checked at itself, as `ails check` run inside it does. Nothing walks up
looking for `.git` or markers.
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


def _sample(root: Path, *, git: bool = True) -> Path:
    project = _git_project(root) if git else root
    project.mkdir(parents=True, exist_ok=True)
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
def test_folder_named_from_a_plain_parent_is_checked_within_the_parent_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """From a plain folder holding `sample`, `ails check ./sample` is inside the cwd: it is checked
    within the parent project, so the markdown under the named folder is checked."""
    _sample(tmp_path / "sample")

    named = _run(monkeypatch, tmp_path, "./sample")

    checked = set(named.get("capability_paths", []))
    for shown in ("sample/CLAUDE.md", "sample/README.md", "sample/docs/notes.md"):
        assert shown in checked, (shown, sorted(checked))


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_outside_folder_is_checked_at_itself_as_run_inside_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A folder outside the cwd with no `.git` is checked at itself, exactly as `ails check` run in it."""
    folder = tmp_path / "loose"
    folder.mkdir()
    (folder / "notes.md").write_text(NOTES, encoding="utf-8")
    elsewhere = _sample(tmp_path / "elsewhere")

    inside = _run(monkeypatch, folder)
    named = _run(monkeypatch, elsewhere, str(folder))

    assert _outcome(named) == _outcome(inside)
    assert named["not_evaluated"] == inside["not_evaluated"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_outside_folder_without_git_holding_sample_content_needs_no_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An outside folder with the sample's content but no `.git` gives the outcome of a run inside it."""
    folder = _sample(tmp_path / "nogit", git=False)
    elsewhere = _git_project(tmp_path / "elsewhere")

    inside = _run(monkeypatch, folder)
    named = _run(monkeypatch, elsewhere, str(folder))

    assert "README.md" not in inside["files"], sorted(inside["files"])
    assert _outcome(named) == _outcome(inside)
    assert named["not_evaluated"] == inside["not_evaluated"]
