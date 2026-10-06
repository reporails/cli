"""Codex file types match the locations the Codex docs name."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.discovery.agents import clear_agent_cache, detect_agents

SKILL = "---\nname: foo\ndescription: Does foo.\n---\n\n# Foo\n"


def _write(root: Path, rel: str, text: str = "x: 1\n") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _types(project: Path, rels: list[str]) -> dict[str, str]:
    files = [project / r for r in rels]
    classified = classify_files(project, files, load_file_types("codex"))
    return {cf.path.relative_to(project).as_posix(): cf.file_type for cf in classified}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_project_skill_locations_and_metadata_are_typed(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    rels = [
        ".agents/skills/foo/SKILL.md",
        "packages/api/.agents/skills/foo/SKILL.md",
        ".agents/skills/foo/agents/openai.yaml",
        "packages/api/.agents/skills/foo/agents/openai.yaml",
        "docs/agents/openai.yaml",
    ]
    for rel in rels:
        _write(project, rel, SKILL if rel.endswith(".md") else "interface: {}\n")

    got = _types(project, rels)

    assert got[".agents/skills/foo/SKILL.md"] == "skills"
    assert got["packages/api/.agents/skills/foo/SKILL.md"] == "skills"
    assert got[".agents/skills/foo/agents/openai.yaml"] == "skill_metadata"
    assert got["packages/api/.agents/skills/foo/agents/openai.yaml"] == "skill_metadata"
    assert got.get("docs/agents/openai.yaml") != "skill_metadata"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_user_skill_metadata_is_typed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # Path.home() reads USERPROFILE on Windows
    project = tmp_path / "proj"
    project.mkdir()
    meta = _write(home, ".agents/skills/foo/agents/openai.yaml")
    classified = classify_files(project, [meta], load_file_types("codex"))
    assert [cf.file_type for cf in classified] == ["skill_metadata"]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_detection_still_names_codex(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    (project / ".git").mkdir(parents=True)
    _write(project, "AGENTS.md", "# P\n\n- Use uv.\n")
    _write(project, ".codex/config.toml", 'model = "gpt-5"\n')
    _write(project, "docs/agents/openai.yaml")
    clear_agent_cache()
    assert "codex" in {a.agent_type.id for a in detect_agents(project)}
