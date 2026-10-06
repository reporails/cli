"""Skill membership holds for skills nested below the project root and for user-level skills."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.core.mapper.skills import record_skills


def _registry(*entry_patterns: str) -> dict[str, dict[str, Any]]:
    return {"claude": {"file_types": {"skills": {"entry_patterns": list(entry_patterns)}}}}


def _rec(path: Path, type_: str = "skills") -> SimpleNamespace:
    return SimpleNamespace(
        path=path.as_posix(),
        type=type_,
        skill="",
        loading="on_invocation",
        scope="task_scoped",
        globs=(),
        agent="claude",
    )


def _record(root: Path, rels: list[str], registry: dict[str, dict[str, Any]]) -> dict[str, SimpleNamespace]:
    recs = {rel: _rec(root / rel) for rel in rels}
    record_skills(SimpleNamespace(files=list(recs.values())), ["claude"], root, registry)
    return recs


@pytest.mark.unit
@pytest.mark.subsys_map
def test_nested_skill_folder_is_recorded(tmp_path: Path) -> None:
    recs = _record(
        tmp_path,
        [
            "packages/web/.claude/skills/deploy/SKILL.md",
            "packages/web/.claude/skills/deploy/ref.md",
            ".claude/skills/top/SKILL.md",
            ".claude/skills/top/ref.md",
        ],
        _registry("**/.claude/skills/*/SKILL.md"),
    )
    nested = (tmp_path / "packages/web/.claude/skills/deploy").as_posix()
    assert recs["packages/web/.claude/skills/deploy/SKILL.md"].skill == nested
    assert recs["packages/web/.claude/skills/deploy/ref.md"].skill == nested
    top = (tmp_path / ".claude/skills/top").as_posix()
    assert recs[".claude/skills/top/SKILL.md"].skill == top
    assert recs[".claude/skills/top/ref.md"].skill == top


@pytest.mark.unit
@pytest.mark.subsys_map
def test_nested_category_skills_are_each_their_own_folder(tmp_path: Path) -> None:
    recs = _record(
        tmp_path,
        [
            "pkg/.cursor/skills/cat/a/SKILL.md",
            "pkg/.cursor/skills/cat/a/ref.md",
            "pkg/.cursor/skills/cat/b/SKILL.md",
        ],
        _registry("**/.cursor/skills/*/**/SKILL.md"),
    )
    base = tmp_path / "pkg/.cursor/skills/cat"
    assert recs["pkg/.cursor/skills/cat/a/SKILL.md"].skill == (base / "a").as_posix()
    assert recs["pkg/.cursor/skills/cat/a/ref.md"].skill == (base / "a").as_posix()
    assert recs["pkg/.cursor/skills/cat/b/SKILL.md"].skill == (base / "b").as_posix()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_user_level_skill_is_recorded_from_its_full_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Path.home() reads USERPROFILE on Windows
    root = tmp_path / ".claude"
    recs = _record(root, ["skills/s/SKILL.md", "skills/s/ref.md"], _registry("~/.claude/skills/*/SKILL.md"))
    assert recs["skills/s/SKILL.md"].skill == (root / "skills/s").as_posix()
    assert recs["skills/s/ref.md"].skill == (root / "skills/s").as_posix()


def _resolver(root: Path, skill: Path) -> Any:
    from reporails_cli.core.mapper.inspect import _load_registry
    from reporails_cli.core.pipeline.assemble import _local_finding_type_resolver

    rec = _rec(skill / "SKILL.md")
    rec.skill = skill.as_posix()
    inp = SimpleNamespace(ruleset_map=SimpleNamespace(files=[rec]), scan_root=root)
    return _local_finding_type_resolver(inp, _load_registry())  # type: ignore[arg-type]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_unmapped_file_in_a_skill_folder_is_a_skill_file(tmp_path: Path) -> None:
    skill = tmp_path / ".claude/skills/a"
    skill.mkdir(parents=True)
    typed = _resolver(tmp_path, skill)
    assert typed((skill / "data.json").as_posix()) == "skills"
    assert typed((tmp_path / "docs/data.json").as_posix()) != "skills"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_unmapped_file_under_a_symlinked_subfolder_of_a_skill_is_a_skill_file(tmp_path: Path) -> None:
    skill = tmp_path / ".claude/skills/a"
    (tmp_path / "shared").mkdir()
    skill.mkdir(parents=True)
    (skill / "linked").symlink_to(tmp_path / "shared")
    typed = _resolver(tmp_path, skill)
    assert typed((skill / "linked" / "data.json").as_posix()) == "skills"


def _write(root: Path, rel: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("---\nname: x\ndescription: y\n---\nbody\n", encoding="utf-8")


def _entry_check(root: Path, agent: str) -> Any:
    from reporails_cli.core.classify import classify_files, load_file_types
    from reporails_cli.core.lint.mechanical.checks_advanced import skill_entrypoint_present

    files = sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.parts)
    recs = [_rec(p, "skills" if "skills" in p.parts else "generic") for p in files]
    record_skills(SimpleNamespace(files=recs), [agent], root)
    skills = {r.path: r.skill for r in recs if r.skill}
    classified = classify_files(root, files, load_file_types(agent, project_root=root), skills=skills)
    return skill_entrypoint_present(root, {"entry": "SKILL.md"}, classified)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_skills_root_is_not_guessed_from_a_stray_skill_md(tmp_path: Path) -> None:
    _write(tmp_path, ".cursor/skills/SKILL.md")
    _write(tmp_path, ".cursor/skills/a/SKILL.md")
    _write(tmp_path, ".cursor/rules/base.mdc")
    assert _entry_check(tmp_path, "cursor").passed


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_folder_without_entry_is_flagged_under_a_one_level_root(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/skills/a/SKILL.md")
    _write(tmp_path, ".claude/skills/b/notes.md")
    result = _entry_check(tmp_path, "claude")
    assert not result.passed
    assert ".claude/skills/b" in result.message


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_category_folder_under_an_any_depth_root_is_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, ".cursor/skills/cat/a/SKILL.md")
    _write(tmp_path, ".cursor/skills/top/SKILL.md")
    assert _entry_check(tmp_path, "cursor").passed


@pytest.mark.unit
@pytest.mark.subsys_map
def test_user_level_skill_file_is_typed_skills_from_inside_the_user_folder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reporails_cli.core.mapper.inspect import _load_registry, file_type_of

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Path.home() reads USERPROFILE on Windows
    root = tmp_path / ".claude"
    assert file_type_of(root / "skills/s/SKILL.md", root, _load_registry()) == "skills"
