"""Cursor file types match the locations Cursor's own docs say it loads."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.discovery.agents import clear_agent_cache, detect_agents


def _write(root: Path, rel: str, text: str = "# Notes\n\nRun `make test`.\n") -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _types(root: Path, rels: list[str]) -> dict[str, str | None]:
    paths = [_write(root, rel) for rel in rels]
    classified = classify_files(root, paths, load_file_types("cursor"))
    return {str(c.path.relative_to(root)): c.file_type for c in classified}


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("rel", "expected"),
    [
        (".cursor/rules/a.mdc", "rules"),
        (".cursor/skills/deploy/SKILL.md", "skills"),
        (".agents/skills/deploy/SKILL.md", "skills"),
        (".claude/skills/deploy/SKILL.md", "skills"),
        (".codex/skills/deploy/SKILL.md", "skills"),
        ("apps/web/.cursor/skills/deploy/SKILL.md", "skills"),
        ("apps/web/.agents/skills/deploy/SKILL.md", "skills"),
        (".cursor/BUGBOT.md", "bugbot"),
        ("apps/web/.cursor/BUGBOT.md", "nested_bugbot"),
    ],
)
def test_documented_location_classifies(tmp_path: Path, rel: str, expected: str) -> None:
    assert _types(tmp_path, [rel]).get(rel) == expected


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_plain_md_in_cursor_rules_is_not_a_rule(tmp_path: Path) -> None:
    assert _types(tmp_path, [".cursor/rules/b.md"]).get(".cursor/rules/b.md") != "rules"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_plain_cursor_folder_still_detects_cursor(tmp_path: Path) -> None:
    _write(tmp_path, ".cursor/rules/a.mdc", "---\nalwaysApply: true\n---\n\n- Use `ruff`.\n")
    clear_agent_cache()
    assert "cursor" in {a.agent_type.id for a in detect_agents(tmp_path)}
