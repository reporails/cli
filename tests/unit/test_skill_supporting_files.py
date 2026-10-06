"""A skill's supporting markdown files are discovered, classified as the skill's, and checked."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.discovery.agents import clear_agent_cache, get_all_scannable_files
from reporails_cli.core.lint.regex import run_checks

_SKILL = "---\nname: api\ndescription: Use when calling the API\n---\n\n# API\n\nRead `reference.md` first.\n"


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))  # Path.home() reads USERPROFILE on Windows
    _write(tmp_path, "CLAUDE.md", "# Project\n\nRun `uv run pytest` before commits.\n")
    _write(tmp_path, ".claude/skills/api/SKILL.md", _SKILL)
    _write(tmp_path, ".claude/skills/api/reference.md", "# Reference\n\nUse the v2 endpoint.\n")
    _write(tmp_path, ".claude/skills/api/examples/a.md", "# Example\n\nCall `GET /v2/items`.\n")
    _write(tmp_path, ".claude/skills/api/scripts/run.py", "print('x')\n")
    _write(tmp_path, ".claude/skills/api/data.json", "{}\n")
    return tmp_path


def _scanned(root: Path) -> list[str]:
    clear_agent_cache()
    return sorted(p.relative_to(root).as_posix() for p in get_all_scannable_files(root))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_supporting_markdown_files_are_discovered_and_scripts_are_not(project: Path) -> None:
    assert _scanned(project) == [
        ".claude/skills/api/SKILL.md",
        ".claude/skills/api/examples/a.md",
        ".claude/skills/api/reference.md",
        "CLAUDE.md",
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_supporting_files_are_classified_as_the_skills_type(project: Path) -> None:
    clear_agent_cache()
    files = get_all_scannable_files(project)
    classified = classify_files(project, files, load_file_types("claude", project_root=project))

    assert len(classified) == len(files)
    assert {c.path.name: c.file_type for c in classified if "skills" in c.path.parts} == {
        "SKILL.md": "skills",
        "reference.md": "skills",
        "a.md": "skills",
    }


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_skill_supporting_files_under_other_agents_folders_are_discovered(tmp_path: Path) -> None:
    _write(tmp_path, ".agents/skills/api/SKILL.md", _SKILL)
    _write(tmp_path, ".agents/skills/api/reference.md", "# Reference\n\nUse the v2 endpoint.\n")

    assert _scanned(tmp_path) == [".agents/skills/api/SKILL.md", ".agents/skills/api/reference.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_frontmatter_checks_of_a_skill_skip_its_supporting_files(project: Path) -> None:
    rules = Path(__file__).resolve().parents[2] / "framework" / "rules" / "core"
    ymls = [rules / "skill-description-length" / "checks.yml", rules / "skill-directory-kebab-case" / "checks.yml"]
    skill = project / ".claude" / "skills" / "api"
    files = [skill / "SKILL.md", skill / "reference.md", skill / "examples" / "a.md"]

    findings = run_checks(ymls, project, instruction_files=files)

    # SKILL.md carries both fields; reference.md and a.md carry no frontmatter and must not be asked for it.
    assert findings == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_check_without_path_filters_reports_every_scanned_file(tmp_path: Path) -> None:
    yml = tmp_path / "checks.yml"
    yml.write_text(
        "checks:\n- id: X.S.0001.c\n  type: deterministic\n  pattern-regex: 'zzz'\n  expect: present\n  message: m\n"
    )
    _write(tmp_path, "a.md", "# A\n")
    _write(tmp_path, "b.md", "# B\n")

    findings = run_checks([yml], tmp_path, instruction_files=[tmp_path / "a.md", tmp_path / "b.md"])

    assert sorted(f.file for f in findings) == ["a.md", "b.md"]
