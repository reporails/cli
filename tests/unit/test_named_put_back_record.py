"""A file named on the command line or in `validate(targets=...)` is checked inside a left-out folder."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.pipeline import check_one
from reporails_cli.core.platform.dto.pipeline import Discovered
from reporails_cli.interfaces.cli import check_flow
from reporails_cli.interfaces.cli.check_flow import CheckInputs, CheckState


def _project(tmp_path: Path) -> Path:
    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    for name in ("x", "y"):
        (project / "packages" / name).mkdir(parents=True)
        (project / "packages" / name / "CLAUDE.md").write_text(f"# {name}\n\nAlways run the tests.\n", encoding="utf-8")
    return project


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_cli_files_named_in_a_left_out_folder_are_checked_when_nothing_else_is_found(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _project(tmp_path)
    clear_agent_cache()
    emptied: list[int] = []
    monkeypatch.setattr(check_flow, "_emit_empty_run", lambda state: emptied.append(1))
    inputs = CheckInputs(
        targets=[],
        format_opt="json",
        agent="claude",
        exclude_dirs=["packages"],
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
    state.targets.path_targets = {project / "packages" / "x" / "CLAUDE.md", project / "packages" / "y" / "CLAUDE.md"}
    assert check_flow._flow_scope(state)
    assert not emptied
    assert {f.parent.name for f in state.scope.instruction_files} == {"x", "y"}
    assert state.render.excluded == ((), ())


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_cli_nothing_named_and_nothing_found_is_an_empty_run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path)
    clear_agent_cache()
    emptied: list[int] = []
    monkeypatch.setattr(check_flow, "_emit_empty_run", lambda state: emptied.append(1))
    inputs = CheckInputs(
        targets=[],
        format_opt="json",
        agent="claude",
        exclude_dirs=["packages"],
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
    assert not check_flow._flow_scope(state)
    assert emptied


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_whole_project_run_with_a_named_file_keeps_the_left_out_folder_in_the_record(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / ".ails" / "config.yml").write_text("exclude_dirs: [packages]\n", encoding="utf-8")
    (project / "CLAUDE.md").write_text("# Root\n\nAlways run the tests.\n", encoding="utf-8")
    clear_agent_cache()
    named = frozenset({project / "packages" / "x" / "CLAUDE.md"})
    discovered = check_one.discover_files(project, named=named)
    assert isinstance(discovered, Discovered)
    files = {f.relative_to(project).as_posix() for f in discovered.instruction_files}
    assert "packages/x/CLAUDE.md" in files
    assert "packages/y/CLAUDE.md" not in files
    assert discovered.left_out.record == (("packages",), ())
