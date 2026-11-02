"""`ails xray`'s refusals: each ends before any page starts, with the message and exit code the user reads."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.eventbus.transcript import session_transcript
from reporails_cli.interfaces.cli.main import app

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript" / "2.1.308" / "session.jsonl"


@pytest.fixture(name="project")
def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    root = tmp_path / "proj"
    root.mkdir()
    monkeypatch.chdir(root)
    return root.resolve()


def test_session_and_current_together_are_refused(project: Path) -> None:
    result = CliRunner().invoke(app, ["xray", "--session", "x", "--current", "--no-open"])
    assert result.exit_code == 2 and "--session and --current" in result.output
    assert project.exists()


def test_an_unknown_session_names_the_id_and_the_folder(project: Path) -> None:
    transcript = session_transcript(project, "real")
    transcript.parent.mkdir(parents=True)
    shutil.copy(FIXTURE, transcript)
    result = CliRunner().invoke(app, ["xray", "--session", "nosuch", "--no-open"])
    assert (
        result.exit_code == 2
        and f"Error: no session nosuch for {project}; run it in the folder Claude Code was started in" in result.output
    )


def test_a_folder_without_sessions_says_so(project: Path) -> None:
    result = CliRunner().invoke(app, ["xray", "--no-open"])
    assert (
        result.exit_code == 2
        and f"Error: no Claude Code session found for {project}; run it in the folder Claude Code was started in"
        in result.output
    )
