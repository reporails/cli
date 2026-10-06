"""Glob matching goes through the project walker: it prunes excluded folders, follows symlinked
folders, matches case-insensitively on request and terminates on symlink cycles."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.discovery import walk
from reporails_cli.core.discovery.agent_discovery import ci_glob, glob_file_type_patterns
from reporails_cli.core.lint.mechanical.checks import _glob_cache, _resolve_glob_targets


def _write(path: Path, text: str = "# x\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _spy_listings(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    listed: list[str] = []
    real = walk.list_dir

    def spy(path: str) -> object:
        listed.append(path)
        return real(path)

    monkeypatch.setattr(walk, "list_dir", spy)
    return listed


def _rel(root: Path, paths: object) -> set[str]:
    return {p.relative_to(root).as_posix() for p in paths}  # type: ignore[attr-defined]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_symlinked_rules_folder_is_discovered(tmp_path: Path) -> None:
    shared = tmp_path / "shared-rules"
    _write(shared / "style.md")
    _write(shared / "deep" / "more.md")
    (tmp_path / ".claude" / "rules").mkdir(parents=True)
    os.symlink(shared, tmp_path / ".claude" / "rules" / "linked", target_is_directory=True)
    found = glob_file_type_patterns(tmp_path, [".claude/rules/**/*.md"], {"scope": "path_scoped"}, frozenset())
    assert _rel(tmp_path, found) == {".claude/rules/linked/style.md", ".claude/rules/linked/deep/more.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_symlinked_skill_folder_is_discovered(tmp_path: Path) -> None:
    real = tmp_path / "elsewhere" / "deploy"
    _write(real / "SKILL.md")
    (tmp_path / ".claude" / "skills").mkdir(parents=True)
    os.symlink(real, tmp_path / ".claude" / "skills" / "deploy", target_is_directory=True)
    found = glob_file_type_patterns(tmp_path, [".claude/skills/*/SKILL.md"], {}, frozenset())
    assert _rel(tmp_path, found) == {".claude/skills/deploy/SKILL.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_ci_glob_never_lists_a_nested_excluded_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / "a" / ".claude" / "agents" / "x.md")
    _write(tmp_path / "web" / "core" / "deep" / "y.md")
    _write(tmp_path / "a" / "node_modules" / "pkg" / "z.md")
    listed = _spy_listings(monkeypatch)
    found = ci_glob(tmp_path, "**/*.md", frozenset({"core", "node_modules"}))
    assert _rel(tmp_path, found) == {"a/.claude/agents/x.md"}
    assert listed
    assert not [p for p in listed if Path(p).name in {"core", "node_modules", "deep", "pkg"}]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mechanical_targets_never_list_a_nested_excluded_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(tmp_path / ".ails" / "config.yml", "exclude_dirs:\n  - core\n")
    _write(tmp_path / "a" / "keep.md")
    _write(tmp_path / "web" / "core" / "deep" / "y.md")
    _write(tmp_path / "a" / "node_modules" / "pkg" / "z.md")
    _glob_cache.clear()
    listed = _spy_listings(monkeypatch)
    found = _resolve_glob_targets("**/*.md", tmp_path)
    assert _rel(tmp_path, found) == {"a/keep.md"}
    assert listed
    assert not [p for p in listed if Path(p).name in {"core", "node_modules", "deep", "pkg"}]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mechanical_targets_are_files_only(tmp_path: Path) -> None:
    _write(tmp_path / "docs" / "a.md")
    (tmp_path / "folder.md").mkdir()
    _glob_cache.clear()
    assert _rel(tmp_path, _resolve_glob_targets("**/*.md", tmp_path)) == {"docs/a.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_case_insensitive_prefix_folders_are_resolved(tmp_path: Path) -> None:
    _write(tmp_path / ".Claude" / "Agents" / "x.md")
    found = ci_glob(tmp_path, ".claude/agents/*.md", frozenset())
    assert _rel(tmp_path, found) == {".Claude/Agents/x.md"}
    assert _rel(tmp_path, ci_glob(tmp_path, ".claude/agents/X.MD", frozenset())) == {".Claude/Agents/x.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_case_sensitive_match_is_the_default(tmp_path: Path) -> None:
    _write(tmp_path / ".Claude" / "x.md")
    assert list(walk.walk_glob_matches(tmp_path, ".claude/*.md", frozenset())) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_symlink_cycle_terminates(tmp_path: Path) -> None:
    rules = tmp_path / ".claude" / "rules"
    _write(rules / "a.md")
    os.symlink(tmp_path / ".claude", rules / "loop", target_is_directory=True)
    found = ci_glob(tmp_path, ".claude/rules/**/*.md", frozenset())
    assert ".claude/rules/a.md" in _rel(tmp_path, found)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_stats_no_regular_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _write(tmp_path / "a" / "one.md")
    _write(tmp_path / "two.md")
    stats: list[str] = []
    real = Path.is_file

    def spy(self: Path, *args: object, **kwargs: object) -> bool:
        stats.append(str(self))
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "is_file", spy)
    assert _rel(tmp_path, walk.walk_markdown(tmp_path, frozenset())) == {"a/one.md", "two.md"}
    assert _rel(tmp_path, walk.walk_glob_matches(tmp_path, "**/*.md", frozenset())) == {"a/one.md", "two.md"}
    assert stats == []
