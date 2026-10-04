"""An agent is detected only from a clue that points at that agent and no other."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agent_markers import clue_patterns, scan_marker_at
from reporails_cli.core.discovery.agents import (
    clear_agent_cache,
    detect_agents,
    get_all_scannable_files,
    get_known_agents,
    resolve_agent,
)


def _write(root: Path, rel: str, text: str = "# Notes\n\nRun `make test` before committing.\n") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _detected(root: Path) -> list[str]:
    clear_agent_cache()
    return sorted(a.agent_type.id for a in detect_agents(root))


_SKILL = "---\nname: foo\ndescription: Use when foo is needed\n---\n\n# Foo\n\nDo `foo`.\n"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_folder_with_only_agents_md_is_generic(tmp_path: Path) -> None:
    _write(tmp_path, "AGENTS.md")

    assert _detected(tmp_path) == ["generic"]
    clear_agent_cache()
    assert resolve_agent("", detect_agents(tmp_path), tmp_path) == ("", False, False)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_editor_settings_do_not_make_a_project_copilot(tmp_path: Path) -> None:
    _write(tmp_path, ".cursor/rules/style.mdc", "---\nalwaysApply: true\n---\n\n- Use `ruff`.\n")
    _write(tmp_path, "AGENTS.md")
    _write(tmp_path, ".vscode/settings.json", '{"editor.fontSize": 14}\n')

    assert _detected(tmp_path) == ["cursor", "generic"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_editor_settings_alone_detect_no_agent(tmp_path: Path) -> None:
    _write(tmp_path, ".vscode/settings.json", '{"editor.fontSize": 14}\n')

    assert _detected(tmp_path) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_copilot_folder_is_still_a_copilot_clue(tmp_path: Path) -> None:
    _write(tmp_path, ".github/copilot-instructions.md")

    assert _detected(tmp_path) == ["copilot"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_skills_under_a_claude_folder_are_a_claude_project(tmp_path: Path) -> None:
    _write(tmp_path, ".claude/skills/foo/SKILL.md", _SKILL)

    assert _detected(tmp_path) == ["claude"]
    clear_agent_cache()
    assert resolve_agent("", detect_agents(tmp_path), tmp_path)[0] == "claude"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_bare_skills_folder_names_no_agent(tmp_path: Path) -> None:
    _write(tmp_path, "skills/foo/SKILL.md", _SKILL)

    assert _detected(tmp_path) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_claude_cross_read_does_not_make_a_project_copilot(tmp_path: Path) -> None:
    _write(tmp_path, "CLAUDE.md")
    _write(tmp_path, ".claude/rules/style.md", "---\npaths: src/**\n---\n\n- Use `ruff`.\n")
    _write(tmp_path, ".claude/agents/reviewer.md", "---\nname: reviewer\ndescription: Reviews\n---\n\n# Reviewer\n")

    assert _detected(tmp_path) == ["claude"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_codex_fallback_names_in_the_project_config_name_codex(tmp_path: Path) -> None:
    _write(tmp_path, "AGENTS.md")
    _write(tmp_path, "sub/CODEX.md")
    _write(
        tmp_path,
        ".ails/config.yml",
        'schema_version: "0.1.0"\nagents:\n  codex:\n    fallback_filenames: ["CODEX.md"]\n',
    )

    assert _detected(tmp_path) == ["codex"]
    clear_agent_cache()
    detected = detect_agents(tmp_path)
    assert resolve_agent("", detected, tmp_path)[0] == "codex"
    assert {p.name for p in get_all_scannable_files(tmp_path, agents=detected)} == {"AGENTS.md", "CODEX.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_without_the_config_a_codex_fallback_file_is_not_read(tmp_path: Path) -> None:
    _write(tmp_path, "AGENTS.md")
    _write(tmp_path, "sub/CODEX.md")

    assert _detected(tmp_path) == ["generic"]
    clear_agent_cache()
    assert {p.name for p in get_all_scannable_files(tmp_path)} == {"AGENTS.md"}


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("agent", "clue", "expected"),
    [
        ("claude", "CLAUDE.md", True),
        ("claude", ".claude/skills/**/*.md", True),
        ("claude", "AGENTS.md", False),
        ("claude", ".mcp.json", True),
        ("copilot", ".github/copilot-instructions.md", True),
        ("copilot", ".vscode/settings.json", False),
        ("cursor", ".cursorrules", True),
        ("cursor", ".claude/skills/**/*.md", False),
        ("antigravity", "GEMINI.md", True),
        ("antigravity", "AGENTS.md", False),
        ("codex", "AGENTS.override.md", True),
        ("codex", ".agents/skills/**/*.md", False),
        ("generic", "AGENTS.md", True),
        ("generic", ".agents/skills/**/*.md", True),
    ],
)
def test_a_pattern_is_a_clue_when_its_folder_or_name_is_the_agents_own(agent: str, clue: str, expected: bool) -> None:
    registry = get_known_agents()

    assert (clue in clue_patterns(registry[agent], registry)) is expected


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_registry_declares_one_core_agent_with_the_shared_names() -> None:
    registry = get_known_agents()

    assert [a.id for a in registry.values() if a.core] == ["generic"]
    assert registry["generic"].shared_names == ("AGENTS.md",)
    assert {a.id: a.home_dir for a in registry.values()} == {
        "antigravity": ".gemini",
        "claude": ".claude",
        "codex": ".codex",
        "copilot": ".github",
        "cursor": ".cursor",
        "generic": ".agents",
    }


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_an_unreadable_folder_is_logged_not_read_as_empty(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    registry = get_known_agents()

    with caplog.at_level("WARNING"):
        assert scan_marker_at(tmp_path / "missing", registry["claude"], registry) is False

    assert "Cannot read" in caplog.text


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_codex_config_in_the_home_folder_does_not_name_a_projects_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path / "home"
    _write(home, ".codex/config.toml", 'model = "gpt-5"\n')
    monkeypatch.setenv("HOME", str(home))
    project = tmp_path / "proj"
    _write(project, "AGENTS.md")
    _write(project, ".gitignore", ".codex/\n")

    assert _detected(project) == ["generic"]
