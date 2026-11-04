"""The folder `ails check` runs in is the project root.

A target inside that folder, file or folder, stays scoped inside it; a target outside it roots at itself
(a folder) or at its own folder (a file); a symlink loop in a file list never stops the run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.walk import file_under_target
from reporails_cli.interfaces.cli import check_orchestration as orch


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_symlink_loop_is_not_under_a_target_and_does_not_stop_the_run(tmp_path: Path) -> None:
    loop = tmp_path / "loop" / "CLAUDE.md"
    loop.parent.mkdir()
    loop.symlink_to(loop)
    target = tmp_path / "proj"
    target.mkdir()
    assert file_under_target(loop, target) is False


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "rel", ["CLAUDE.md", "packages/api/CLAUDE.md", ".claude/skills/alpha/SKILL.md", ".claude/rules/style.md"]
)
def test_a_file_inside_the_cwd_keeps_the_cwd_as_root(tmp_path: Path, rel: str) -> None:
    """A nested file, even one beside its own `.git` or agent folder, never re-roots the run."""
    project = tmp_path / "proj"
    target = project / rel
    target.parent.mkdir(parents=True)
    (project / "packages" / "api" / ".git").mkdir(parents=True, exist_ok=True)
    target.write_text("# Doc\n", encoding="utf-8")
    assert orch.scan_scope(target, project) == (None, project, target)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_outside_the_cwd_roots_at_its_own_folder_even_in_a_project(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    (project / ".git").mkdir(parents=True)
    (project / "sub").mkdir()
    target = project / "sub" / "CLAUDE.md"
    target.write_text("# Doc\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert orch.scan_scope(target, elsewhere) == (None, project / "sub", target)
    assert orch.scan_scope(target, project / ".claude") == (None, project / "sub", target)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("rel", ["docs", ".claude", ".claude/rules", "packages/api"])
def test_a_folder_inside_the_cwd_is_scoped_inside_it(tmp_path: Path, rel: str) -> None:
    project = tmp_path / "proj"
    (project / rel).mkdir(parents=True)
    (project / "packages" / "api" / ".claude").mkdir(parents=True, exist_ok=True)
    (project / "packages" / "api" / "CLAUDE.md").write_text("# API\n", encoding="utf-8")
    assert orch.scan_scope(project / rel, project) == (project / rel, project, None)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_the_cwd_itself_or_no_target_is_the_whole_project(tmp_path: Path) -> None:
    assert orch.scan_scope(tmp_path, tmp_path) == (None, tmp_path, None)
    assert orch.scan_scope(None, tmp_path) == (None, tmp_path, None)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_folder_outside_the_cwd_roots_at_itself_whatever_it_holds(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    assert orch.scan_scope(project, tmp_path / "elsewhere") == (None, project, None)
    assert orch.scan_scope(project / ".claude", tmp_path / "elsewhere") == (None, project / ".claude", None)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_folder_inside_the_user_agent_folder_narrows_to_itself(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    skills = home / ".claude" / "skills"
    skills.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    project = tmp_path / "proj"
    project.mkdir()
    assert orch.scan_scope(skills, project) == (skills, home / ".claude", None)
    assert orch.scan_scope(None, skills) == (skills, home / ".claude", None)
    assert orch.scan_scope(home / ".claude", project) == (None, home / ".claude", None)
    assert orch.scan_scope(home / ".claude" / "CLAUDE.md", project) == (None, home / ".claude", None)
