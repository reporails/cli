"""A path target outside the current directory's project anchors its own scan.

`ails check path/to/project` run from a parent directory must scan the project, not the parent: a project
whose main file is written `claude.md` is still a project root (the file is found whatever its case), and a
symlink loop in a file list never stops the run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.interfaces.cli import check_orchestration as orch


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.subsys_cli_ux
def test_a_project_whose_main_file_is_lowercase_is_its_own_root(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    (project / "claude.md").write_text("# Project\n", encoding="utf-8")
    assert orch._is_project_root(project)
    assert orch._scan_root(project, None, tmp_path) == (None, project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.subsys_cli_ux
def test_a_symlink_loop_is_not_under_a_target_and_does_not_stop_the_run(tmp_path: Path) -> None:
    loop = tmp_path / "loop" / "CLAUDE.md"
    loop.parent.mkdir()
    loop.symlink_to(loop)
    target = tmp_path / "proj"
    target.mkdir()
    assert orch._file_under_target(loop, target) is False


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_target_checked_from_its_own_project_root_keeps_that_root(tmp_path: Path) -> None:
    """Pinned: a file target with the invoking cwd already at its project root must keep
    resolving to that exact root — the common case this fix must not disturb."""
    project = tmp_path / "proj"
    (project / ".git").mkdir(parents=True)
    claude_md = project / "CLAUDE.md"
    claude_md.write_text("# Project\n", encoding="utf-8")
    assert orch._scan_root(claude_md, claude_md, project) == (None, project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_target_resolves_its_own_project_root_when_the_cwd_is_elsewhere(tmp_path: Path) -> None:
    """A file target outside the invoking terminal's cwd roots on the file's own project,
    not on the unrelated cwd — the same root `resolve_project_root_for_file` (MCP's
    `validate`) would give the same file."""
    project = tmp_path / "proj"
    (project / ".git").mkdir(parents=True)
    claude_md = project / "CLAUDE.md"
    claude_md.write_text("# Project\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert orch._scan_root(claude_md, claude_md, elsewhere) == (None, project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_target_resolves_the_real_root_when_the_cwd_is_a_subfolder_of_the_project(
    tmp_path: Path,
) -> None:
    """`cd .claude && ails check ../CLAUDE.md` must still root at the project, not at the
    `.claude` subfolder the terminal happens to be sitting in."""
    project = tmp_path / "proj"
    (project / ".git").mkdir(parents=True)
    claude_dir = project / ".claude"
    claude_dir.mkdir()
    claude_md = project / "CLAUDE.md"
    claude_md.write_text("# Project\n", encoding="utf-8")
    assert orch._scan_root(claude_md, claude_md, claude_dir) == (None, project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_nested_child_file_with_no_markers_of_its_own_keeps_the_whole_project_as_root(
    tmp_path: Path,
) -> None:
    """Regression guard: a nested file already INSIDE the cwd-resolved project
    (`packages/api/CLAUDE.md`, a skill's `SKILL.md`) must never walk up and re-root on
    itself — `resolve_project_root_for_file` finds no `.git`/`.ails`/IDE marker anywhere
    in a bare fixture tree and falls back to the file's OWN directory, which would
    silently re-scope a child file to its own package/skill folder instead of the whole
    project it belongs to."""
    project = tmp_path / "proj"
    nested = project / "packages" / "api"
    nested.mkdir(parents=True)
    nested_file = nested / "CLAUDE.md"
    nested_file.write_text("# API\n", encoding="utf-8")
    assert orch._scan_root(nested_file, nested_file, project) == (None, project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_skill_file_inside_the_project_keeps_the_whole_project_as_root(tmp_path: Path) -> None:
    """Same regression, the skill-folder shape: `ails check .claude/skills/alpha/SKILL.md`
    from the project root must stay scoped to the project, not re-root at
    `.claude/skills/alpha`."""
    project = tmp_path / "proj"
    skill_dir = project / ".claude" / "skills" / "alpha"
    skill_dir.mkdir(parents=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text("---\nname: alpha\n---\n\n# Alpha\n", encoding="utf-8")
    assert orch._scan_root(skill_file, skill_file, project) == (None, project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_target_under_a_markerless_cwd_roots_on_its_own_project(tmp_path: Path) -> None:
    """`cd <parent> && ails check <parent>/proj/CLAUDE.md`: the parent holds no project
    marker, so the file's own project (its main file beside its config folder) is the
    scan root — the parent's other files never feed the run."""
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    claude_md = project / "CLAUDE.md"
    claude_md.write_text("# Project\n", encoding="utf-8")
    assert orch._scan_root(claude_md, claude_md, tmp_path) == (None, project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_file_target_keeps_a_cwd_that_is_a_project(tmp_path: Path) -> None:
    """A cwd that already carries a project marker keeps a file inside it in its own scope."""
    (tmp_path / ".claude").mkdir()
    nested = tmp_path / "packages" / "api"
    (nested / ".claude").mkdir(parents=True)
    nested_file = nested / "CLAUDE.md"
    nested_file.write_text("# API\n", encoding="utf-8")
    assert orch._scan_root(nested_file, nested_file, tmp_path) == (None, tmp_path)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_agent_config_folder_named_from_a_folder_that_is_no_project_resolves_to_the_project_holding_it(
    tmp_path: Path,
) -> None:
    """`cd <parent> && ails check proj/.claude`: the folder is the agent's own configuration inside
    `proj`, so the scan roots on `proj` (its rules and skills stay in) and is narrowed to the folder."""
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / ".claude" / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")
    assert orch._scan_root(project / ".claude", None, tmp_path) == (project / ".claude", project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_agent_config_folder_named_from_outside_its_project_resolves_to_that_project(tmp_path: Path) -> None:
    project = tmp_path / "work" / "proj"
    (project / ".claude").mkdir(parents=True)
    (project / ".claude" / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert orch._scan_root(project / ".claude", None, elsewhere) == (project / ".claude", project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("inside", [".claude", ".claude/rules"])
@pytest.mark.parametrize("named", [False, True])
def test_a_check_started_inside_an_agent_config_folder_scans_the_project_holding_it(
    tmp_path: Path, inside: str, named: bool
) -> None:
    """`cd proj/.claude && ails check` (or `ails check .`, or from `.claude/rules`) checks `proj`, narrowed
    to the folder it was started in, exactly as `ails check proj/.claude` does."""
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")
    cwd = project / inside
    assert orch._scan_root(cwd if named else None, None, cwd) == (cwd, project)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_check_started_in_an_ordinary_project_subfolder_keeps_the_folder_as_its_scan_root(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    (project / ".claude").mkdir(parents=True)
    (project / "docs").mkdir()
    (project / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")
    assert orch._scan_root(None, None, project / "docs") == (None, project / "docs")
    assert orch._scan_root(project / "docs", None, project / "docs") == (None, project / "docs")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("marker", [".claude/rules/style.md", ".claude/skills/x/SKILL.md", ".cursor/rules/a.mdc"])
def test_a_folder_named_from_its_markerless_parent_is_its_own_root_whatever_it_holds(
    tmp_path: Path, marker: str
) -> None:
    """`ails check proj` run from a folder above `proj` scans `proj`, even when `proj` holds
    agent files but no main instruction file."""
    project = tmp_path / "proj"
    (project / marker).parent.mkdir(parents=True)
    (project / marker).write_text("# Rule\n", encoding="utf-8")
    assert orch._scan_root(project, None, tmp_path) == (None, project)
