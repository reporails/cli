"""A Claude Code plugin's own skills, agents and commands are Claude files.

A plugin is a directory holding `.claude-plugin/plugin.json`; its components sit at the
plugin root (`skills/<name>/SKILL.md`, `agents/*.md`, `commands/*.md`), not under
`.claude/`. Discovery, classification and the mapper resolve them from the plugin root,
at the project root or below it (a marketplace's `plugins/<name>/`). A top-level
`skills/` folder in a project with no plugin manifest is not a plugin's skills.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.discovery.agent_discovery import discover_from_config
from reporails_cli.core.discovery.agents import (
    DEFAULT_EXCLUDE_DIRS,
    clear_agent_cache,
    detect_agents,
    get_all_instruction_files,
)
from reporails_cli.core.discovery.plugin_roots import (
    expand_plugin_patterns,
    find_plugin_roots,
    plugin_relative_path,
    split_plugin_pattern,
)
from reporails_cli.core.mapper.inspect import _detect_file_loading, _load_registry

MANIFEST = ".claude-plugin/plugin.json"
SKILL = "---\nname: fmt\ndescription: Formats Python files\n---\n\nRun `ruff format` on each changed file.\n"
AGENT = "---\nname: reviewer\ndescription: Reviews diffs\n---\n\nReview the diff for missing tests.\n"
COMMAND = "---\ndescription: Show status\n---\n\nPrint the deploy status.\n"


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _plugin(root: Path) -> None:
    _write(root / MANIFEST, '{"name": "demo", "description": "Demo plugin"}\n')
    _write(root / "skills" / "fmt" / "SKILL.md", SKILL)
    _write(root / "agents" / "reviewer.md", AGENT)
    _write(root / "commands" / "status.md", COMMAND)


def _rel(project: Path, files: list[Path]) -> set[str]:
    return {f.relative_to(project).as_posix() for f in files}


def _scope(project: Path) -> set[str]:
    clear_agent_cache()
    detected = detect_agents(project)
    agents = [a for a in detected if a.agent_type.id != "generic"] or detected
    return _rel(project, get_all_instruction_files(project, agents=agents))


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_split_plugin_pattern() -> None:
    assert split_plugin_pattern("<.claude-plugin/plugin.json>/skills/**/SKILL.md") == (
        ".claude-plugin/plugin.json",
        "skills/**/SKILL.md",
    )
    assert split_plugin_pattern(".claude/skills/**/SKILL.md") is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_plugin_roots_at_the_root_and_below_it(tmp_path: Path) -> None:
    _plugin(tmp_path)
    _plugin(tmp_path / "plugins" / "demo")
    _plugin(tmp_path / "node_modules" / "vendored")
    roots = find_plugin_roots(tmp_path, MANIFEST, DEFAULT_EXCLUDE_DIRS)
    assert roots == [tmp_path, tmp_path / "plugins" / "demo"]
    assert expand_plugin_patterns([f"<{MANIFEST}>/skills/**/SKILL.md", "x.md"], tmp_path, DEFAULT_EXCLUDE_DIRS) == [
        "skills/**/SKILL.md",
        "plugins/demo/skills/**/SKILL.md",
        "x.md",
    ]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_no_manifest_no_plugin_pattern(tmp_path: Path) -> None:
    _write(tmp_path / "skills" / "fmt" / "SKILL.md", SKILL)
    assert expand_plugin_patterns([f"<{MANIFEST}>/skills/**/SKILL.md"], tmp_path, DEFAULT_EXCLUDE_DIRS) == []
    assert plugin_relative_path(tmp_path / "skills" / "fmt" / "SKILL.md", tmp_path, MANIFEST) is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_plugin_at_the_project_root_is_a_claude_project(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    _plugin(project)
    assert _scope(project) == {"skills/fmt/SKILL.md", "agents/reviewer.md", "commands/status.md"}
    discovered = discover_from_config(project, "claude")
    assert discovered is not None
    assert _rel(project, discovered[2]) == {MANIFEST}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_marketplace_plugin_below_the_root_is_found(tmp_path: Path) -> None:
    project = tmp_path / "market"
    _write(project / ".claude-plugin" / "marketplace.json", '{"name": "m", "plugins": []}\n')
    _plugin(project / "plugins" / "demo")
    assert _scope(project) == {
        "plugins/demo/skills/fmt/SKILL.md",
        "plugins/demo/agents/reviewer.md",
        "plugins/demo/commands/status.md",
    }
    discovered = discover_from_config(project, "claude")
    assert discovered is not None
    assert _rel(project, discovered[2]) == {f"plugins/demo/{MANIFEST}"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_plugin_components_classify_as_claude_types(tmp_path: Path) -> None:
    project = tmp_path / "market"
    _plugin(project / "plugins" / "demo")
    files = [
        project / "plugins/demo/skills/fmt/SKILL.md",
        project / "plugins/demo/agents/reviewer.md",
        project / "plugins/demo/commands/status.md",
        project / "plugins/demo" / MANIFEST,
    ]
    classified = {c.path: c.file_type for c in classify_files(project, files, load_file_types("claude"))}
    assert [classified.get(f) for f in files] == ["skills", "agents", "commands", "plugins"]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_the_mapper_types_plugin_components_as_claude_types(tmp_path: Path) -> None:
    project = tmp_path / "market"
    _plugin(project / "plugins" / "demo")
    registry = _load_registry()
    skill = _detect_file_loading(project / "plugins/demo/skills/fmt/SKILL.md", project, registry)
    agent = _detect_file_loading(project / "plugins/demo/agents/reviewer.md", project, registry)
    assert (skill[0], skill[3], skill[4]) == ("on_invocation", "claude", "skills")
    assert (agent[0], agent[3], agent[4]) == ("on_invocation", "claude", "agents")


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_top_level_skills_folder_without_a_manifest_is_not_claudes(tmp_path: Path) -> None:
    """No `.claude-plugin/plugin.json`: `skills/` and `agents/` are ordinary folders."""
    project = tmp_path / "proj"
    _write(project / "CLAUDE.md", "# Project\n\nRun the tests before each commit.\n")
    skill = _write(project / "skills" / "fmt" / "SKILL.md", SKILL)
    agent = _write(project / "agents" / "reviewer.md", AGENT)
    assert _scope(project) == {"CLAUDE.md"}
    assert classify_files(project, [skill, agent], load_file_types("claude")) == []
    registry = _load_registry()
    assert _detect_file_loading(skill, project, registry)[3:] == ("generic", "generic")


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.skipif(os.geteuid() == 0, reason="root reads every directory, so nothing is unreadable")
def test_an_unreadable_folder_is_skipped_and_the_plugin_beside_it_is_found(tmp_path: Path) -> None:
    """A folder the user cannot read (another user's volume, a locked build dir) is not
    searched; discovery neither fails on it nor misses a plugin in a readable sibling."""
    project = tmp_path / "proj"
    _write(project / "CLAUDE.md", "# Project\n\nRun the tests before each commit.\n")
    _plugin(project / "plugins" / "demo")
    locked = project / "locked"
    (locked / "inner").mkdir(parents=True)
    locked.chmod(0)
    try:
        assert find_plugin_roots(project, MANIFEST, DEFAULT_EXCLUDE_DIRS) == [project / "plugins" / "demo"]
        clear_agent_cache()
        assert "claude" in {a.agent_type.id for a in detect_agents(project)}
    finally:
        locked.chmod(0o755)


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_plugin_root_skills_and_agents_count_toward_the_capability_surfaces(tmp_path: Path) -> None:
    """Skills and agents that live only under a plugin root are found by the level's
    surface detection, the same files discovery finds and checks."""
    from reporails_cli.core.discovery.features import _agent_surface_files

    _plugin(tmp_path)
    assert _rel(tmp_path, _agent_surface_files(tmp_path, "claude", "skills")) == {"skills/fmt/SKILL.md"}
    assert _rel(tmp_path, _agent_surface_files(tmp_path, "claude", "agents")) == {"agents/reviewer.md"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_top_level_skills_folder_without_a_plugin_manifest_is_not_a_surface(tmp_path: Path) -> None:
    from reporails_cli.core.discovery.features import _agent_surface_files

    _write(tmp_path / "skills" / "fmt" / "SKILL.md", SKILL)
    assert _agent_surface_files(tmp_path, "claude", "skills") == []


def _excluded_plugin_project(tmp_path: Path) -> Path:
    _write(tmp_path / "CLAUDE.md", "# Project\n\nRun `make test` before committing.\n")
    _write(tmp_path / ".ails" / "config.yml", "exclude_dirs:\n  - third_party\n")
    _plugin(tmp_path / "third_party" / "vendored-plugin")
    return tmp_path


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_plugin_under_an_excluded_folder_adds_no_capability_surface(tmp_path: Path) -> None:
    """Skills and agents of a plugin inside an excluded folder are not the project's:
    the surface list stays empty and the project gains neither skills nor sub-agents."""
    from reporails_cli.core.discovery.features import _agent_surface_files, detect_features_filesystem

    project = _excluded_plugin_project(tmp_path)
    clear_agent_cache()
    assert _agent_surface_files(project, "claude", "skills") == []
    assert _agent_surface_files(project, "claude", "agents") == []
    features = detect_features_filesystem(project)
    assert features.has_skills_dir is False
    assert features.has_subagents is False


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_plugin_outside_any_excluded_folder_still_adds_its_surfaces(tmp_path: Path) -> None:
    from reporails_cli.core.discovery.features import detect_features_filesystem

    _write(tmp_path / "CLAUDE.md", "# Project\n\nRun `make test` before committing.\n")
    _write(tmp_path / ".ails" / "config.yml", "exclude_dirs:\n  - third_party\n")
    _plugin(tmp_path / "plugins" / "own")
    clear_agent_cache()
    features = detect_features_filesystem(tmp_path)
    assert features.has_skills_dir is True
    assert features.has_subagents is True


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_one_feature_detection_searches_each_plugin_marker_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reporails_cli.core.discovery import plugin_roots
    from reporails_cli.core.discovery.features import detect_features_filesystem

    _write(tmp_path / "CLAUDE.md", "# Project\n\nRun `make test` before committing.\n")
    _plugin(tmp_path / "plugins" / "own")
    clear_agent_cache()
    agents = detect_agents(tmp_path)
    searched: list[str] = []
    real = plugin_roots.find_plugin_roots

    def spy(target: Path, marker: str, exclude_dirs: frozenset[str] = frozenset()) -> list[Path]:
        searched.append(marker)
        return real(target, marker, exclude_dirs)

    monkeypatch.setattr(plugin_roots, "find_plugin_roots", spy)
    detect_features_filesystem(tmp_path, agents=agents)
    assert searched, "the plugin marker was never searched"
    assert len(searched) == len(set(searched)), f"a marker was searched more than once: {searched}"
