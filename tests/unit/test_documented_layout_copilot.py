"""Copilot file types match the locations GitHub's and VS Code's docs name."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.discovery.agents import detect_agents


@pytest.fixture
def home(monkeypatch, tmp_path) -> Path:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    return home_dir


def _touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# x\n", encoding="utf-8")
    return path


def _type_of(project: Path, path: Path) -> str:
    classified = classify_files(project, [path], load_file_types("copilot"))
    return classified[0].file_type


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        ("home/.claude/skills/foo/SKILL.md", "skills"),
        ("home/.claude/agents/reviewer.md", "agents"),
        ("home/.copilot/copilot-instructions.md", "main"),
        ("home/.copilot/hooks/audit.json", "hooks"),
        ("home/.copilot/instructions/style.instructions.md", "rules"),
        ("home/.copilot/settings.json", "config"),
        ("proj/.github/agents/reviewer.md", "agents"),
        ("proj/.github/copilot/settings.json", "config"),
        ("proj/.github/copilot/settings.local.json", "config"),
    ],
)
def test_documented_location_classifies(home: Path, tmp_path: Path, rel: str, expected: str) -> None:
    (tmp_path / "proj").mkdir(exist_ok=True)
    path = _touch(tmp_path / rel)
    assert _type_of(tmp_path / "proj", path) == expected


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_policy_hooks_dir_is_a_managed_hooks_location() -> None:
    hooks = load_file_types("copilot")
    patterns = [p for ft in hooks if ft.name == "hooks" for p in ft.patterns]
    assert "/etc/github-copilot/policy.d/*.json" in patterns


def _ids(root: Path) -> list[str]:
    return sorted(a.agent_type.id for a in detect_agents(root))


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_copilot_instructions_project_still_detects_copilot(tmp_path: Path) -> None:
    _touch(tmp_path / ".github" / "copilot-instructions.md")
    assert "copilot" in _ids(tmp_path)


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_plain_claude_md_project_does_not_detect_copilot(tmp_path: Path) -> None:
    _touch(tmp_path / "CLAUDE.md")
    assert "copilot" not in _ids(tmp_path)
