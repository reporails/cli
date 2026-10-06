"""Skill membership decides which files the skill rules judge."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.lint.rule_runner import run_m_probes

LONG = "\n".join(f"line {i}" for i in range(601)) + "\n"
SHORT = "---\nname: a\ndescription: does a thing\n---\n" + "\n".join(f"l{i}" for i in range(16)) + "\n"


def _write(root: Path, rel: str, text: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _run(root: Path, files: list[Path], skills: dict[str, str] | None) -> list:
    return run_m_probes(root, files, agent="claude", skills=skills)


def _ids(findings: list, rel: str) -> set[str]:
    return {f.rule for f in findings if f.file.replace("\\", "/").endswith(rel)}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_group_skill_md_is_not_a_skill(tmp_path: Path) -> None:
    f = _write(tmp_path, ".claude/skills/group/x/SKILL.md", LONG)
    file_types = load_file_types("claude", project_root=tmp_path)
    classified = classify_files(tmp_path, [f], file_types, skills={})
    assert all(cf.file_type != "skills" for cf in classified)
    ids = _ids(_run(tmp_path, [f], {}), "group/x/SKILL.md")
    assert "CORE:S:0031" not in ids
    assert "CORE:S:0040" not in ids


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_supporting_skill_md_is_not_measured_as_entry(tmp_path: Path) -> None:
    entry = _write(tmp_path, ".claude/skills/a/SKILL.md", SHORT)
    inner = _write(tmp_path, ".claude/skills/a/b/SKILL.md", LONG)
    folder = entry.parent.as_posix()
    skills = {entry.as_posix(): folder, inner.as_posix(): folder}
    ids = _ids(_run(tmp_path, [entry, inner], skills), "a/b/SKILL.md")
    assert "CORE:S:0031" not in ids
    assert "CORE:S:0040" not in ids


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_long_entry_still_reported(tmp_path: Path) -> None:
    entry = _write(tmp_path, ".claude/skills/a/SKILL.md", LONG)
    skills = {entry.as_posix(): entry.parent.as_posix()}
    assert "CORE:S:0031" in _ids(_run(tmp_path, [entry], skills), "a/SKILL.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_without_a_map_behavior_is_unchanged(tmp_path: Path) -> None:
    entry = _write(tmp_path, ".claude/skills/a/SKILL.md", SHORT)
    inner = _write(tmp_path, ".claude/skills/a/b/SKILL.md", LONG)
    ids = _ids(_run(tmp_path, [entry, inner], None), "a/b/SKILL.md")
    assert "CORE:S:0031" in ids
    assert "CORE:S:0040" in ids
