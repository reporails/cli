"""Unit tests for the symlink-following markdown walker."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.discovery.walk import walk_files, walk_markdown


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_markdown_yields_files_inside_symlinked_directory(tmp_path: Path) -> None:
    """A .md file inside a symlinked subdirectory must be yielded.

    Regression for `Path.rglob('*.md')` on Python 3.12 which silently
    skips symlinked subdirectories.
    """
    canonical = tmp_path / "canonical" / "orient"
    canonical.mkdir(parents=True)
    (canonical / "SKILL.md").write_text("# orient\n", encoding="utf-8")

    project = tmp_path / "project"
    skills_dir = project / ".claude" / "skills"
    skills_dir.mkdir(parents=True)
    os.symlink(str(canonical), str(skills_dir / "orient"))

    found = list(walk_markdown(skills_dir))
    rels = {p.relative_to(project).as_posix() for p in found}
    assert ".claude/skills/orient/SKILL.md" in rels


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_markdown_breaks_symlink_cycle(tmp_path: Path) -> None:
    """An a->b->a directory cycle must terminate the walk."""
    root = tmp_path / "root"
    a = root / "a"
    b = root / "b"
    a.mkdir(parents=True)
    b.mkdir()
    (a / "SKILL.md").write_text("# A\n", encoding="utf-8")
    os.symlink(str(b), str(a / "loop"))
    os.symlink(str(a), str(b / "loop"))

    found = list(walk_markdown(root))
    assert len(found) == 1
    assert found[0].name == "SKILL.md"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_markdown_dedupes_two_symlinks_to_same_target(tmp_path: Path) -> None:
    """Two surface symlinks to one canonical dir → file yielded once."""
    canonical = tmp_path / "canonical" / "shared"
    canonical.mkdir(parents=True)
    (canonical / "SKILL.md").write_text("# Shared\n", encoding="utf-8")

    project = tmp_path / "project"
    project.mkdir()
    os.symlink(str(canonical), str(project / "via_a"))
    os.symlink(str(canonical), str(project / "via_b"))

    found = list(walk_markdown(project))
    assert len(found) == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_markdown_ignores_non_markdown(tmp_path: Path) -> None:
    (tmp_path / "keep.md").write_text("# keep\n", encoding="utf-8")
    (tmp_path / "skip.txt").write_text("nope\n", encoding="utf-8")
    found = {p.name for p in walk_markdown(tmp_path)}
    assert found == {"keep.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_files_applies_predicate(tmp_path: Path) -> None:
    (tmp_path / "match.txt").write_text("yes\n", encoding="utf-8")
    (tmp_path / "skip.bin").write_bytes(b"\x00\x01\x02")
    found = {p.name for p in walk_files(tmp_path, lambda p: p.suffix == ".txt")}
    assert found == {"match.txt"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_walk_files_follows_symlinked_subdir(tmp_path: Path) -> None:
    canonical = tmp_path / "canonical"
    canonical.mkdir()
    (canonical / "inner.md").write_text("# inner\n", encoding="utf-8")
    project = tmp_path / "project"
    project.mkdir()
    os.symlink(str(canonical), str(project / "via"))
    found = {p.name for p in walk_files(project)}
    assert "inner.md" in found
