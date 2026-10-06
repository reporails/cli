"""`ails check` names an agent only from a clue that points at it, and says so when it cannot tell.

A folder holding only `AGENTS.md` (a name several agents read) is checked with the rules every
agent shares and the scorecard says the agent was not determined; the agent's own folder or a
project config naming it settles the agent.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

AGENTS_MD = "# Project\n\nRun `uv run pytest` before committing.\nKeep modules under 300 lines.\n"
NOT_DETERMINED = "Agent: not determined"
POINTER = "--agent <name>"


def _write(project: Path, rel: str, text: str = AGENTS_MD) -> None:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _text(monkeypatch: pytest.MonkeyPatch, project: Path) -> str:
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "."])
    assert result.exit_code == 0, result.output
    return result.output


def _files(monkeypatch: pytest.MonkeyPatch, project: Path) -> dict:
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", ".", "-f", "json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.output).get("files") or {}


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_a_folder_with_only_agents_md_is_checked_without_naming_an_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    _write(project, "AGENTS.md")

    out = _text(monkeypatch, project)

    assert NOT_DETERMINED in out
    assert POINTER in out and "default_agent" in out
    files = _files(monkeypatch, project)
    assert list(files) == ["AGENTS.md"]
    assert all(f["rule"].startswith("CORE:") for f in files["AGENTS.md"]["findings"])


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_editor_settings_beside_agents_md_do_not_name_an_agent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "proj"
    _write(project, "AGENTS.md")
    _write(project, ".vscode/settings.json", '{"editor.fontSize": 14}\n')

    assert NOT_DETERMINED in _text(monkeypatch, project)


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_a_codex_folder_beside_agents_md_names_codex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "proj"
    _write(project, "AGENTS.md")
    _write(project, ".codex/config.toml", 'model = "gpt-5"\n')

    out = _text(monkeypatch, project)

    assert "Agent: Codex" in out
    assert NOT_DETERMINED not in out


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_codex_fallback_names_in_the_project_config_name_codex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "proj"
    _write(project, "AGENTS.md")
    _write(project, "sub/CODEX.md", "# Sub\n\nEdit config.yaml and run pytest before you commit.\n")
    _write(
        project,
        ".ails/config.yml",
        'schema_version: "0.1.0"\nagents:\n  codex:\n    fallback_filenames: ["CODEX.md"]\n',
    )

    out = _text(monkeypatch, project)

    assert "Agent: Codex" in out
    assert NOT_DETERMINED not in out
    files = _files(monkeypatch, project)
    assert {"AGENTS.md", "sub/CODEX.md"} <= set(files)
    assert files["sub/CODEX.md"]["findings"]


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_a_claude_skills_folder_names_claude_and_a_bare_skills_folder_does_not(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    skill = "---\nname: fmt\ndescription: Formats Python files\n---\n\nRun `ruff format` on each changed file.\n"
    claude = tmp_path / "claude"
    _write(claude, ".claude/skills/fmt/SKILL.md", skill)
    bare = tmp_path / "bare"
    _write(bare, "skills/fmt/SKILL.md", skill)
    _write(bare, "AGENTS.md")

    assert "Agent: Claude" in _text(monkeypatch, claude)
    assert NOT_DETERMINED in _text(monkeypatch, bare)


EDITOR_SETTINGS = '{"editor.formatOnSave": false, "chat.tools.terminal.autoApprove": {"ls": true}}\n'
PERMISSION_RULES = {"CORE:G:0003", "CORE:G:0005"}


def _rules(files: dict, rel: str) -> set[str]:
    return {f["rule"] for f in files.get(rel, {}).get("findings", [])}


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_plain_editor_settings_are_not_checked_as_an_agents_permission_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    _write(project, "AGENTS.md")
    _write(project, "CLAUDE.md")
    _write(project, ".cursor/rules/a.mdc", "---\ndescription: style\n---\nUse tabs in Makefiles.\n")
    _write(project, ".vscode/settings.json", EDITOR_SETTINGS)

    files = _files(monkeypatch, project)

    assert ".vscode/settings.json" not in files


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_cursor_permission_file_is_the_project_cli_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = tmp_path / "proj"
    _write(project, ".cursor/rules/a.mdc", "---\ndescription: style\n---\nUse tabs in Makefiles.\n")
    _write(project, ".cursor/cli.json", '{"permissions": {"allow": ["Shell(ls)"]}}\n')

    files = _files(monkeypatch, project)

    assert "CORE:G:0005" in _rules(files, ".cursor/cli.json")


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_copilot_settings_are_checked_without_the_agent_permission_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    _write(project, ".github/copilot-instructions.md")
    _write(project, ".vscode/settings.json", EDITOR_SETTINGS)
    empty = tmp_path / "empty"
    _write(empty, ".github/copilot-instructions.md")
    _write(empty, ".vscode/settings.json", "{}\n")

    files = _files(monkeypatch, project)
    empty_files = _files(monkeypatch, empty)

    assert not _rules(files, ".vscode/settings.json")
    assert _rules(empty_files, ".vscode/settings.json") == {"CORE:S:0021"}
