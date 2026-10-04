"""Checking one existing path never detects agents by walking the folder the command runs from.

The agent whose vocabulary reads target tokens is found under the target's own project when the token
is an existing path; only a capability word (`hooks`, `skills`) is read against the current folder's project.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.interfaces.cli import check_flow
from reporails_cli.interfaces.cli.check_flow import CheckInputs, CheckState


def _inputs(project_root: Path, targets: list[str], agent: str = "") -> CheckInputs:
    return CheckInputs(
        targets=targets,
        format_opt="json",
        agent=agent,
        exclude_dirs=None,
        exclude_files=None,
        ascii_mode=True,
        strict=False,
        verbose=False,
        heal=False,
        dry_run=False,
        cwd=False,
        project_root=project_root,
    )


@pytest.fixture
def scanned(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Record every directory agent detection is asked to scan."""
    seen: list[Path] = []

    def fake_detect(target: Path, *args: Any, **kwargs: Any) -> list[Any]:
        seen.append(Path(target))
        return [SimpleNamespace(agent_type=SimpleNamespace(id="claude"))]

    monkeypatch.setattr("reporails_cli.core.discovery.agents.detect_agents", fake_detect)
    return seen


def _two_projects(tmp_path: Path) -> tuple[Path, Path, Path]:
    cwd_project = tmp_path / "here"
    (cwd_project / ".git").mkdir(parents=True)
    (cwd_project / "CLAUDE.md").write_text("# Here\n", encoding="utf-8")
    for i in range(3):
        (cwd_project / "unrelated" / f"tree{i}").mkdir(parents=True)
        (cwd_project / "unrelated" / f"tree{i}" / "CLAUDE.md").write_text("# Other\n", encoding="utf-8")
    other = tmp_path / "elsewhere" / "proj"
    (other / ".git").mkdir(parents=True)
    target = other / "CLAUDE.md"
    target.write_text("# Proj\n", encoding="utf-8")
    return cwd_project, other, target


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_in_another_project_never_scans_the_current_folder(tmp_path: Path, scanned: list[Path]) -> None:
    cwd_project, other, target = _two_projects(tmp_path)
    state = CheckState(inputs=_inputs(cwd_project, [str(target)]))
    check_flow._flow_targets(state)
    assert all(not d.is_relative_to(cwd_project) for d in scanned)
    assert scanned and all(d == other for d in scanned)
    assert state.targets.single_file == target.resolve()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_folder_in_another_project_never_scans_the_current_folder(tmp_path: Path, scanned: list[Path]) -> None:
    cwd_project, other, _ = _two_projects(tmp_path)
    state = CheckState(inputs=_inputs(cwd_project, [str(other)]))
    check_flow._flow_targets(state)
    assert all(not d.is_relative_to(cwd_project) for d in scanned)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_capability_word_still_reads_the_current_projects_agent(tmp_path: Path, scanned: list[Path]) -> None:
    cwd_project, _, _ = _two_projects(tmp_path)
    state = CheckState(inputs=_inputs(cwd_project, ["hooks"]))
    check_flow._flow_targets(state)
    assert scanned == [cwd_project]
    assert state.targets.capability_specs == [("hooks", "")]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_inside_the_current_project_reads_that_project(tmp_path: Path, scanned: list[Path]) -> None:
    cwd_project, _, _ = _two_projects(tmp_path)
    state = CheckState(inputs=_inputs(cwd_project, [str(cwd_project / "CLAUDE.md")]))
    check_flow._flow_targets(state)
    assert set(scanned) == {cwd_project}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_explicit_agent_scans_nothing(tmp_path: Path, scanned: list[Path]) -> None:
    cwd_project, _, target = _two_projects(tmp_path)
    state = CheckState(inputs=_inputs(cwd_project, [str(target)], agent="claude"))
    check_flow._flow_targets(state)
    assert scanned == []
