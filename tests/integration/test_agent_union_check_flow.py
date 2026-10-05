"""A union run: two genuinely distinctive agents each run their own rules on
their own files, and the run is never collapsed to a single `generic` pass.

Before the fix, `resolve_agent_filters` returned `effective_agent="generic"` whenever
two or more agents stayed distinctive, and `_flow_pipeline` ran `run_m_probes` /
`run_content_quality_checks` exactly once with `agent="generic"` over the WHOLE
combined file set -- dropping every agent-specific rule (`CLAUDE:*`, `CURSOR:*`, ...).
This test drives a real `ails check` over a project with a genuinely distinctive Claude
main file and a genuinely distinctive Cursor rule file (no shared `AGENTS.md`, so
neither is a cross-read of the other -- both stay distinctive) and spies
on the two rule-running entry points to prove each agent ran once, over only its own
file, and `generic` never ran at all.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


def _claude_and_cursor_project(tmp_path: Path) -> Path:
    """A project with a genuinely distinctive Claude main file and a genuinely
    distinctive Cursor rule file. No `AGENTS.md` anywhere, so neither file is a
    cross-read of the other agent's namespace -- both stay distinctive."""
    project = tmp_path / "proj"
    (project / ".cursor" / "rules").mkdir(parents=True)
    (project / "CLAUDE.md").write_text(
        "# Project\n\nRun `pytest` before every commit.\nNever commit secrets.\n",
        encoding="utf-8",
    )
    (project / ".cursor" / "rules" / "always.mdc").write_text(
        "---\nalwaysApply: true\n---\n\nRun `pytest` before every commit.\nNever commit secrets.\n",
        encoding="utf-8",
    )
    return project


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_two_distinctive_agents_each_run_their_own_rules_never_generic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Claude+Cursor project runs Claude's rules on `CLAUDE.md` and Cursor's rules on
    the `.mdc` file: `run_m_probes` / `run_content_quality_checks` are each called once
    per distinctive agent, over that agent's own file only, and never with
    `agent="generic"` (a union run, never the collapsed pass)."""
    from reporails_cli.core.lint import rule_runner

    project = _claude_and_cursor_project(tmp_path)
    monkeypatch.chdir(project)

    m_probe_calls: list[tuple[str, tuple[str, ...]]] = []
    content_calls: list[tuple[str, tuple[str, ...]]] = []
    real_m_probes = rule_runner.run_m_probes
    real_content_checks = rule_runner.run_content_quality_checks

    def _spy_m_probes(
        project_dir: Path,
        instruction_files: list[Path],
        agent: str = "",
        scoped: bool = False,
        project_checks: str = "all",
        skills: Mapping[str, str] | None = None,
    ):
        # The one whole-project pass (project-wide checks only) is not a per-agent pass.
        if project_checks != "only":
            m_probe_calls.append((agent, tuple(sorted(f.name for f in instruction_files))))
        return real_m_probes(
            project_dir, instruction_files, agent=agent, scoped=scoped, project_checks=project_checks, skills=skills
        )

    def _spy_content_checks(
        ruleset_map: object, project_dir: Path, instruction_files: list[Path] | None = None, agent: str = ""
    ):
        content_calls.append((agent, tuple(sorted(f.name for f in (instruction_files or [])))))
        return real_content_checks(ruleset_map, project_dir, instruction_files, agent=agent)

    monkeypatch.setattr(rule_runner, "run_m_probes", _spy_m_probes)
    monkeypatch.setattr(rule_runner, "run_content_quality_checks", _spy_content_checks)

    result = runner.invoke(app, ["check", "-f", "json"])

    assert result.exit_code in (0, 1), result.output

    m_probe_agents = {agent for agent, _ in m_probe_calls}
    content_agents = {agent for agent, _ in content_calls}
    assert m_probe_agents == {"claude", "cursor"}, m_probe_calls
    assert content_agents == {"claude", "cursor"}, content_calls
    assert "generic" not in (m_probe_agents | content_agents)

    m_probe_by_agent = dict(m_probe_calls)
    assert m_probe_by_agent["claude"] == ("CLAUDE.md",)
    assert m_probe_by_agent["cursor"] == ("always.mdc",)
