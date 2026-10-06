"""Local findings on small project shapes: what is reported, and at what severity."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "projects"
PROHIBITION_RULES = {"CORE:C:0019", "CORE:C:0022", "CORE:G:0004"}


def _check(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str, *, git: bool = False) -> dict:
    """Run a local-only check on a copy of the fixture, optionally inside a fresh git repository."""
    project = tmp_path / name
    shutil.copytree(FIXTURES / name, project)
    if git:
        subprocess.run(["git", "init", "-q"], cwd=project, check=True)
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "-f", "json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _findings(data: dict) -> list[tuple[str, int, str]]:
    """(rule, line, severity) of every finding, in the order reported."""
    return [(f["rule"], f["line"], f["severity"]) for v in data["files"].values() for f in v["findings"]]


def _rules(data: dict) -> set[str]:
    return {rule for rule, _line, _severity in _findings(data)}


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_a_packed_line_is_reported_as_one_instruction_per_sentence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    findings = _findings(_check(monkeypatch, tmp_path, "packed"))
    assert ("CORE:C:0058", 7, "warning") in findings
    assert "CORE:C:0030" not in {rule for rule, _line, _severity in findings}


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.parametrize("name", ["split_same", "split"])
@pytest.mark.requires_model
def test_a_split_line_is_not_reported_as_packed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    assert "CORE:C:0058" not in _rules(_check(monkeypatch, tmp_path, name))


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_a_project_outside_version_control_draws_one_warning_and_nothing_else(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    without_git = _findings(_check(monkeypatch, tmp_path / "plain", "split"))
    with_git = _findings(_check(monkeypatch, tmp_path / "repo", "split_git", git=True))
    assert [f for f in without_git if f[0] == "CORE:G:0001"] == [("CORE:G:0001", 0, "warning")]
    assert [f for f in without_git if f[0] != "CORE:G:0001"] == with_git


def _copy(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str) -> Path:
    """A copy of the fixture project, checked without a server."""
    project = tmp_path / name
    shutil.copytree(FIXTURES / name, project)
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    return project


def _git_rows(data: dict) -> list[str]:
    """The files that carry the not-a-git-repository finding."""
    return [name for name, v in data["files"].items() if any(f["rule"] == "CORE:G:0001" for f in v["findings"])]


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_documentation_conventions_show_as_one_counted_line_and_json_keeps_each(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _copy(monkeypatch, tmp_path, "split")
    monkeypatch.chdir(project)
    data = json.loads(runner.invoke(app, ["check", "-f", "json"]).output)
    conventions = [f for v in data["files"].values() for f in v["findings"] if f.get("convention")]
    assert len(conventions) >= 5
    assert all(f["message"].startswith("Missing") for f in conventions)

    brief = " ".join(runner.invoke(app, ["check"]).output.split())
    assert f"{len(conventions)} documentation conventions not present" in brief
    assert not [f for f in conventions if f["rule"] in brief]

    verbose = " ".join(runner.invoke(app, ["check", "-v"]).output.split())
    assert "documentation conventions not present" not in verbose
    assert all(f["rule"] in verbose for f in conventions)


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
@pytest.mark.parametrize("target", [None, ".", "AGENTS.md", "dir"])
def test_not_a_git_repository_is_reported_once_per_project_on_every_kind_of_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str | None
) -> None:
    project = _copy(monkeypatch, tmp_path, "multi_agent")
    monkeypatch.chdir(tmp_path if target == "dir" else project)
    args = ["check", str(project)] if target == "dir" else ["check", *([target] if target else [])]
    result = runner.invoke(app, [*args, "-f", "json"])
    assert result.exit_code == 0, result.output
    assert len(_git_rows(json.loads(result.output))) == 1


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_a_file_without_prohibitions_draws_the_prohibition_finding_once_as_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    findings = _findings(_check(monkeypatch, tmp_path, "noconstraint_git", git=True))
    assert [f for f in findings if f[0] in PROHIBITION_RULES] == [("CORE:C:0019", 1, "warning")]
    assert "error" not in {severity for _rule, _line, severity in findings}


@pytest.mark.e2e
@pytest.mark.subsys_lint
def test_a_project_without_instruction_files_reports_no_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    data = _check(monkeypatch, tmp_path, "empty")
    assert data["files"] == {}
    assert data["stats"]["total_findings"] == 0


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_a_do_not_edit_banner_on_the_first_line_is_reported_as_boilerplate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert ("CORE:C:0030", 1, "warning") in _findings(_check(monkeypatch, tmp_path, "banner"))


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_instructions_that_name_what_not_to_edit_are_not_reported_as_boilerplate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert "CORE:C:0030" not in _rules(_check(monkeypatch, tmp_path, "edit_prohibitions"))


@pytest.mark.e2e
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_heal_rewrites_the_instruction_file_and_leaves_the_settings_file_untouched(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "settings_json"
    shutil.copytree(FIXTURES / "settings_json", project)
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AILS_API_KEY", "test-key")
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "--heal", "--cwd", "-f", "json"])
    assert result.exit_code == 0, result.output
    fixed = json.JSONDecoder().raw_decode(result.output[result.output.index('{\n  "auto_fixed"') :])[0]["auto_fixed"]
    assert {Path(f["file_path"]).name for f in fixed} == {"CLAUDE.md"}
    original = (FIXTURES / "settings_json" / ".claude" / "settings.json").read_bytes()
    healed = (project / ".claude" / "settings.json").read_bytes()
    assert healed == original
    assert json.loads(healed)["hooks"]["SessionStart"]
    assert "Run `build.sh` before every commit." in (project / "CLAUDE.md").read_text(encoding="utf-8")
