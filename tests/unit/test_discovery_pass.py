"""Both surfaces discover in one pass that reads each directory once."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.pipeline.mapping import discover_scope
from reporails_cli.interfaces.cli import check_flow
from reporails_cli.interfaces.cli.check_flow import CheckInputs, CheckState
from reporails_cli.interfaces.mcp import tools


@pytest.fixture
def walker_scans(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Every directory the file walkers read from disk, in order."""
    seen: list[str] = []
    real = os.scandir

    def spy(path: str = ".") -> object:
        if sys._getframe(1).f_globals["__name__"] == "reporails_cli.core.discovery.walk":
            seen.append(str(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", spy)
    return seen


def _project(root: Path) -> Path:
    (root / ".git").mkdir(parents=True)
    (root / ".claude" / "skills" / "one").mkdir(parents=True)
    (root / ".claude" / "rules").mkdir(parents=True)
    (root / "pkg" / "deep").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# Project\n\n- Use uv.\n", encoding="utf-8")
    (root / "AGENTS.md").write_text("# Agents\n\n- Use uv.\n", encoding="utf-8")
    (root / "pkg" / "AGENTS.md").write_text("# Pkg\n\n- Use uv.\n", encoding="utf-8")
    (root / ".claude" / "rules" / "a.md").write_text("# A\n\n- Use uv.\n", encoding="utf-8")
    (root / ".claude" / "skills" / "one" / "SKILL.md").write_text(
        "---\nname: one\ndescription: Does one thing.\n---\n\n# One\n", encoding="utf-8"
    )
    return root


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_discover_scope_reads_each_directory_once(tmp_path: Path, walker_scans: list[str]) -> None:
    project = _project(tmp_path)
    clear_agent_cache()
    found = discover_scope(project, "", [], [])
    assert {p.name for p in found.files} >= {
        "CLAUDE.md",
        "SKILL.md",
        "a.md",
    }  # Claude reads no AGENTS.md beside a CLAUDE.md
    assert walker_scans
    assert len(walker_scans) == len(set(walker_scans))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_check_scope_discovery_reads_each_directory_once(tmp_path: Path, walker_scans: list[str]) -> None:
    project = _project(tmp_path)
    clear_agent_cache()
    inputs = CheckInputs(
        targets=[],
        format_opt="json",
        agent="",
        exclude_dirs=None,
        exclude_files=None,
        ascii_mode=True,
        strict=False,
        verbose=False,
        heal=False,
        dry_run=False,
        cwd=False,
        project_root=project,
    )
    state = CheckState(inputs=inputs)
    state.targets.target = project
    check_flow._resolve_scope_at_target(state)
    assert {p.name for p in state.scope.instruction_files} >= {"CLAUDE.md", "SKILL.md"}
    assert walker_scans
    assert len(walker_scans) == len(set(walker_scans))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mcp_discovery_reads_each_directory_once(tmp_path: Path, walker_scans: list[str]) -> None:
    project = _project(tmp_path)
    clear_agent_cache()
    discovered = tools._discover_files(project)
    assert isinstance(discovered, tuple)
    assert {p.name for p in discovered[2]} >= {"CLAUDE.md", "SKILL.md"}
    assert walker_scans
    assert len(walker_scans) == len(set(walker_scans))
