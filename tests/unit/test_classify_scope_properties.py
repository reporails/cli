"""A file matched through a config scope carries that scope's `vcs`; a file with none gets it from where it sits."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.classify.generic_type import make_generic_classified
from reporails_cli.core.discovery.agent_config import load_config_file_types, scope_holding_pattern
from reporails_cli.core.platform.dto.classify import LinkEdge
from reporails_cli.core.platform.dto.results import ProjectConfig


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_scope_vcs_reaches_classified_files(tmp_path: Path) -> None:
    claude_md = tmp_path / "CLAUDE.md"
    settings = tmp_path / ".claude" / "settings.json"
    local = tmp_path / ".claude" / "settings.local.json"
    settings.parent.mkdir()
    claude_md.write_text("# Project\n\nUse tabs.\n")
    settings.write_text("{}\n")
    local.write_text("{}\n")

    classified = classify_files(tmp_path, [claude_md, settings, local], load_file_types("claude"))

    vcs = {cf.path.name: cf.properties.get("vcs") for cf in classified}
    assert vcs == {"CLAUDE.md": "committed", "settings.json": "committed", "settings.local.json": "gitignored"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_scope_in_a_subfolder_leaves_the_other_properties_alone(tmp_path: Path) -> None:
    rule = tmp_path / "sub" / ".claude" / "rules" / "r.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("# Rule\n\nUse tabs.\n")

    (cf,) = classify_files(tmp_path, [rule], load_file_types("claude"))

    assert cf.file_type == "rules"
    assert cf.properties.get("scope") == "path_scoped"
    assert cf.properties.get("vcs") == "committed"


def _edge(source: Path, target: Path, verb: str) -> LinkEdge:
    return LinkEdge(target=target, source=source, source_type="main", depth=1, verb=verb)


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize("verb", ["imported", "read"])
def test_link_reached_file_in_the_project_is_committed(tmp_path: Path, verb: str) -> None:
    target = tmp_path / "docs" / "a.md"
    cf = make_generic_classified(target, [_edge(tmp_path / "CLAUDE.md", target, verb)], tmp_path)

    assert cf.properties["vcs"] == "committed"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_link_reached_file_in_the_home_folder_is_external(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    project = tmp_path / "project"
    project.mkdir()
    target = tmp_path / "home" / "notes" / "a.md"
    cf = make_generic_classified(target, [_edge(project / "CLAUDE.md", target, "imported")], project)

    assert cf.properties["vcs"] == "external"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_project_added_pattern_file_is_committed(tmp_path: Path) -> None:
    extra = tmp_path / "docs" / "team.md"
    extra.parent.mkdir()
    extra.write_text("# Team\n\nUse tabs.\n")
    config = ProjectConfig(surfaces={"claude.main": {"include": ["docs/team.md"]}})

    classified = classify_files(tmp_path, [extra], load_file_types("claude", config=config))

    assert [(cf.file_type, cf.properties.get("vcs")) for cf in classified] == [("main", "committed")]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_codex_fallback_filename_is_committed(tmp_path: Path) -> None:
    fallback = tmp_path / "TEAM.md"
    fallback.write_text("# Team\n\nUse tabs.\n")
    config = ProjectConfig(agents={"codex": {"fallback_filenames": ["TEAM.md"]}})

    classified = classify_files(tmp_path, [fallback], load_file_types("codex", config=config))

    assert [(cf.file_type, cf.properties.get("vcs")) for cf in classified] == [("main", "committed")]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_scope_holding_a_pattern_tells_the_plugin_scope_from_the_project_scope() -> None:
    spec = load_config_file_types("claude")["plugins"]

    project = scope_holding_pattern(spec, ".claude-plugin/plugin.json")
    below_root = scope_holding_pattern(spec, "<.claude-plugin/plugin.json>/.claude-plugin/plugin.json")

    assert project is not None and "root_marker" not in project
    assert below_root is not None and below_root["root_marker"] == ".claude-plugin/plugin.json"
    assert scope_holding_pattern(spec, "nowhere/*.json") is None
