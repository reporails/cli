"""A separate repository inside a git project is not part of the project."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.pipeline.mapping import discover_scope

_SKILL = "---\nname: s\ndescription: Does one thing.\n---\n\n# S\n"


def _write(path: Path, text: str = "# Doc\n\n- Use uv.\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _repo_files(folder: Path) -> list[Path]:
    return [
        _write(folder / "CLAUDE.md"),
        _write(folder / ".claude" / "rules" / "x.md"),
        _write(folder / ".claude" / "skills" / "s" / "SKILL.md", _SKILL),
        _write(folder / ".claude" / "agents" / "a.md", "---\nname: a\ndescription: An agent.\n---\n\n# A\n"),
    ]


def _discovered(target: Path) -> set[Path]:
    clear_agent_cache()
    return {p.resolve() for p in discover_scope(target, "", [], []).files}


def _project(root: Path) -> Path:
    (root / ".git").mkdir(parents=True)
    _write(root / "CLAUDE.md")
    _write(root / ".claude" / "rules" / "own.md")
    return root


def _paths(files: list[Path]) -> set[Path]:
    return {p.resolve() for p in files}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_clone_files_are_not_discovered(tmp_path: Path) -> None:
    project = _project(tmp_path)
    (project / "research" / "clone" / ".git").mkdir(parents=True)
    clone_files = _repo_files(project / "research" / "clone")
    found = _discovered(project)
    assert not found & _paths(clone_files)
    assert (project / "CLAUDE.md").resolve() in found
    assert (project / ".claude" / "rules" / "own.md").resolve() in found


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_cloned_skill_in_own_skills_folder_is_discovered(tmp_path: Path) -> None:
    project = _project(tmp_path)
    foo = project / ".claude" / "skills" / "foo"
    (foo / ".git").mkdir(parents=True)
    skill = _write(foo / "SKILL.md", _SKILL)
    assert skill.resolve() in _discovered(project)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_worktree_files_are_not_discovered(tmp_path: Path) -> None:
    project = _project(tmp_path)
    wt = project / ".claude" / "worktrees" / "w"
    _write(wt / ".git", f"gitdir: {project}/.git/worktrees/w\n")
    wt_files = _repo_files(wt)
    found = _discovered(project)
    assert not found & _paths(wt_files)
    assert (project / "CLAUDE.md").resolve() in found


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_submodule_files_are_discovered(tmp_path: Path) -> None:
    project = _project(tmp_path)
    _write(project / "pkg" / ".git", "gitdir: ../.git/modules/pkg\n")
    doc = _write(project / "pkg" / "CLAUDE.md")
    assert doc.resolve() in _discovered(project)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_plain_folder_of_repos_is_not_cut(tmp_path: Path) -> None:
    if any((p / ".git").exists() for p in (tmp_path, *tmp_path.parents)):
        pytest.skip("a temp-folder ancestor is a git repository")
    _write(tmp_path / "CLAUDE.md")
    (tmp_path / "child" / ".git").mkdir(parents=True)
    child_files = _repo_files(tmp_path / "child")
    found = _discovered(tmp_path)
    assert {p.resolve() for p in child_files if p.name in {"CLAUDE.md", "x.md"}} <= found


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_relative_target_in_subfolder_still_cuts_clone(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project = _project(tmp_path)
    research = project / "research"
    _write(research / "CLAUDE.md")
    (research / "clone" / ".git").mkdir(parents=True)
    clone_files = _repo_files(research / "clone")
    monkeypatch.chdir(research)
    assert not _discovered(Path(".")) & _paths(clone_files)
