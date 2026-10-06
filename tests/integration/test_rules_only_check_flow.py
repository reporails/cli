"""A project whose only instructions are one agent's rule files is found and checked,
with or without `--agent`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

_WEAK = "# Rules\n\nYou should maybe try to run tests sometimes.\n\nNEVER commit secrets.\n"

_PROJECTS = {
    "antigravity": ".agents/rules/r.md",
    "claude": ".claude/rules/r.md",
}


def _project(tmp_path: Path, rel: str) -> Path:
    project = tmp_path / "proj"
    (project / rel).parent.mkdir(parents=True)
    (project / rel).write_text(_WEAK, encoding="utf-8")
    return project


def _check_json(project: Path, monkeypatch: pytest.MonkeyPatch, *extra: str) -> dict:
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", ".", "-f", "json", *extra])
    assert result.exit_code in (0, 1), result.output
    return json.loads(result.output[result.output.index("{") :])


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
@pytest.mark.parametrize(("agent", "rel"), sorted(_PROJECTS.items()))
@pytest.mark.parametrize("pinned", [False, True])
def test_rules_only_project_is_checked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent: str, rel: str, pinned: bool
) -> None:
    data = _check_json(_project(tmp_path, rel), monkeypatch, *(["--agent", agent] if pinned else []))
    assert rel in data["files"]


def _resolved_agent(project: Path) -> str:
    from reporails_cli.core.discovery.agents import detect_agents
    from reporails_cli.core.pipeline.mapping import resolve_agent_filters

    detected = detect_agents(project)
    agent, _assumed, _mixed, _filtered = resolve_agent_filters("", detected, project, None)
    return agent


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_agents_rules_file_points_at_antigravity(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path, ".agents/rules/r.md")
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "."])
    assert "No instruction files found" not in result.output
    assert _resolved_agent(project) == "antigravity"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_shared_agents_skills_file_is_not_an_antigravity_clue(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path, ".agents/skills/x/SKILL.md")
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "."])
    assert "Agent: Antigravity" not in result.output
    assert _resolved_agent(project) != "antigravity"
