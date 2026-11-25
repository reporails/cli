"""The markdown a named target brings in gets the checks of what it is.

A named prompt no agent loads is checked like a file reached only by a markdown link: no rule for
path-scoped rule files applies to it. A named folder leaves out agent working copies and plan files.
A named file that imports another under `generic_scanning` brings the imported file into the run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

MAIN_FILE = "# Project\n\nRun `uv run pytest tests/` before every commit.\n"
PROMPT = "# Review prompt\n\nReview the diff for bugs.\nSee [the notes](notes.md).\n"
STYLE = "# Style\n\nUse four spaces for indentation in `src/`.\n"
PATH_RULES = {"CLAUDE:S:0012", "CORE:S:0038", "CURSOR:S:0001", "CORE:S:0026"}


def _project(root: Path, main: str = MAIN_FILE, config: str = "") -> Path:
    (root / ".git").mkdir(parents=True)
    (root / "CLAUDE.md").write_text(main, encoding="utf-8")
    if config:
        (root / ".ails").mkdir()
        (root / ".ails" / "config.yml").write_text(config, encoding="utf-8")
    return root


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _run(monkeypatch: pytest.MonkeyPatch, cwd: Path, *args: str) -> dict:
    monkeypatch.chdir(cwd)
    result = runner.invoke(app, ["check", *args, "-f", "json", "--offline"])
    data, _ = json.JSONDecoder().raw_decode(result.output[result.output.index("{") :])
    return data


def _rules(data: dict, name: str) -> list[tuple[str, int, str]]:
    entry = data["files"].get(name, {"findings": []})
    return sorted((f["rule"], f["line"], f["severity"]) for f in entry["findings"])


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_named_prompt_gets_no_path_scoped_rule_and_matches_the_linked_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    named = _project(tmp_path / "named")
    _write(named / "prompts" / "review.md", PROMPT)
    linked = _project(
        tmp_path / "linked",
        main=MAIN_FILE + "\nSee [the review prompt](prompts/review.md).\n",
        config="generic_scanning: true\n",
    )
    _write(linked / "prompts" / "review.md", PROMPT)

    named_rules = _rules(_run(monkeypatch, named, "prompts/review.md"), "prompts/review.md")
    linked_rules = _rules(_run(monkeypatch, linked), "prompts/review.md")

    assert named_rules, "the broken link gives the prompt a finding to compare"
    assert not {rule for rule, _, _ in named_rules} & PATH_RULES, named_rules
    assert named_rules == linked_rules


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_named_agent_folder_leaves_out_worktrees_and_plans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path / "proj")
    _write(project / ".claude" / "rules" / "style.md", STYLE)
    _write(project / ".claude" / "worktrees" / "w1" / "README.md", PROMPT)
    _write(project / ".claude" / "worktrees" / "w1" / "docs" / "guide.md", PROMPT)
    _write(project / ".claude" / "plans" / "p.md", PROMPT)

    files = sorted(_run(monkeypatch, project, ".claude")["files"])

    assert not [f for f in files if f.startswith((".claude/worktrees/", ".claude/plans/"))], files


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_named_file_brings_in_the_file_it_imports(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path / "proj", main=MAIN_FILE + "\n@docs/style.md\n", config="generic_scanning: true\n")
    _write(project / "docs" / "style.md", STYLE)

    whole = sorted(_run(monkeypatch, project)["files"])
    named = sorted(_run(monkeypatch, project, "CLAUDE.md")["files"])

    assert "docs/style.md" in whole, whole
    assert "docs/style.md" in named, named
