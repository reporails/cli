"""Claude Code file locations the docs name are discovered and typed as Claude files.

Each row is a path from code.claude.com (project, nested, managed or plugin location);
the root-anchored rows keep their type, and a plain `.claude/` project still names `claude`.
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.discovery.agent_discovery import discover_from_config
from reporails_cli.core.discovery.agents import clear_agent_cache, detect_agents

MANIFEST = ".claude-plugin/plugin.json"
BODY = "---\nname: demo\ndescription: Demo file\n---\n\nRun the tests before each commit.\n"

# (relative path, expected file type); `plugins/demo/` rows sit under a plugin root.
PROJECT_ROWS = [
    (".claude/commands/frontend/component.md", "commands"),
    (".claude/commands/deploy.md", "commands"),
    ("pkg/.claude/skills/fmt/SKILL.md", "skills"),
    (".claude/skills/fmt/SKILL.md", "skills"),
    ("pkg/.claude/agents/team/reviewer.md", "agents"),
    (".claude/agents/sub/reviewer.md", "agents"),
    (".claude/output-styles/terse.md", "output_styles"),
    ("pkg/.claude/output-styles/terse.md", "output_styles"),
    ("pkg/CLAUDE.local.md", "child_instruction"),
    ("CLAUDE.local.md", "override"),
    (".claude/rules/a.md", "rules"),
    ("pkg/.claude/rules/b.md", "rules"),
    ("plugins/demo/.mcp.json", "mcp"),
    ("plugins/demo/hooks/hooks.json", "hooks"),
]


def _write(path: Path, text: str = BODY) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _project(root: Path) -> Path:
    _write(root / "CLAUDE.md", "# Project\n\nRun the tests before each commit.\n")
    _write(root / "plugins/demo" / MANIFEST, '{"name": "demo"}\n')
    for rel, _ in PROJECT_ROWS:
        _write(root / rel, "{}\n" if rel.endswith(".json") else BODY)
    return root


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_documented_project_locations_are_discovered(tmp_path: Path) -> None:
    project = _project(tmp_path / "proj")
    discovered = discover_from_config(project, "claude")
    assert discovered is not None
    found = {p.relative_to(project).as_posix() for group in discovered for p in group}
    for rel, _ in PROJECT_ROWS:
        assert rel in found, rel


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(("rel", "expected"), PROJECT_ROWS)
def test_documented_location_classifies_to_its_type(tmp_path: Path, rel: str, expected: str) -> None:
    project = _project(tmp_path / "proj")
    path = project / rel
    classified = classify_files(project, [path], load_file_types("claude"))
    assert [c.file_type for c in classified] == [expected], rel


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/etc/claude-code/.claude/skills/fmt/SKILL.md", "skills"),
        ("/Library/Application Support/ClaudeCode/.claude/skills/fmt/SKILL.md", "skills"),
        ("C:/Program Files/ClaudeCode/.claude/skills/fmt/SKILL.md", "skills"),
        ("/etc/claude-code/.claude/agents/team/reviewer.md", "agents"),
        ("C:/Program Files/ClaudeCode/.claude/agents/team/reviewer.md", "agents"),
        ("/Library/Application Support/ClaudeCode/.claude/output-styles/terse.md", "output_styles"),
        ("C:/Program Files/ClaudeCode/.claude/output-styles/terse.md", "output_styles"),
        ("C:/Program Files/ClaudeCode/managed-settings.d/10-a.json", "config"),
        ("C:/Program Files/ClaudeCode/managed-mcp.json", "mcp"),
    ],
)
def test_managed_locations_are_declared(path: str, expected: str) -> None:
    declared = {ft.name: ft for ft in load_file_types("claude")}
    assert expected in declared
    patterns = declared[expected].patterns
    assert any(fnmatch(path, pat) for pat in patterns), path


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_plain_dot_claude_project_still_names_claude(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    _write(project / ".claude/rules/a.md")
    clear_agent_cache()
    assert "claude" in {a.agent_type.id for a in detect_agents(project)}
