"""`expected_loads` lists what a session in a folder can invoke from every scope, installed plugins included,
and labels each file and says whether the memory index links each topic file."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.discovery.agent_discovery import claude_project_dir
from reporails_cli.core.discovery.plugin_roots import installed_plugin_roots
from reporails_cli.core.mapper.labels import file_label
from reporails_cli.core.pipeline.expected_loads import expected_loads
from reporails_cli.core.platform.config import claude_settings
from reporails_cli.core.platform.config.bootstrap import claude_plugins_dir
from reporails_cli.core.platform.config.claude_settings import enabled_plugins
from reporails_cli.core.platform.contract.errors import InstalledPluginsUnreadableError
from reporails_cli.core.platform.contract.json_value import as_list, as_object, as_str
from reporails_cli.interfaces.cli.main import app

pytestmark = [pytest.mark.unit, pytest.mark.subsys_classify, pytest.mark.subsys_xray]

SKILL = "---\nname: {name}\ndescription: Does {name}.\n---\n\n# {name}\n\nRun the checks.\n"


@pytest.fixture(autouse=True)
def _no_managed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real = claude_settings._settings_patterns

    def patterns() -> dict[str, list[str]]:
        scopes = real()
        scopes["managed"] = [str(tmp_path / "managed" / "managed-settings.json")]
        scopes["managed_dropin"] = [str(tmp_path / "managed" / "d" / "*.json")]
        return scopes

    monkeypatch.setattr(claude_settings, "_settings_patterns", patterns)


@pytest.fixture(autouse=True)
def _plugins_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(tmp_path / "plugins"))


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    _write(root / "CLAUDE.md", "# Rules\n\nRun the tests.\n")
    return root


def _plugin(tmp_path: Path, plugin_id: str, name: str, *, scope: str = "user", project: Path | None = None) -> Path:
    base = tmp_path / "plugins" / "cache" / name
    _write(base / "skills" / "y" / "SKILL.md", SKILL.format(name="y"))
    _write(base / "skills" / "y" / "ref.md", "# ref\n")
    _write(base / "agents" / "sub" / "helper.md", "---\nname: helper\ndescription: Helps.\n---\n\n# Helper\n")
    _write(base / "commands" / "go.md", "---\ndescription: Go.\n---\n\n# Go\n")
    install: dict[str, str] = {"scope": scope, "installPath": str(base), "version": "1.0.0"}
    if project is not None:
        install["projectPath"] = str(project)
    registry = tmp_path / "plugins" / "installed_plugins.json"
    known = json.loads(registry.read_text()) if registry.is_file() else {"version": 2, "plugins": {}}
    known["plugins"][plugin_id] = [install]
    _write(registry, json.dumps(known))
    return base


def _invocable(root: Path) -> dict[tuple[str, str], dict[str, object]]:
    items = [as_object(i) for i in as_list(expected_loads(root)["invocable"])]
    return {(as_str(i["file_type"]), as_str(i["label"])): dict(i) for i in items}


def _files(root: Path) -> dict[str, dict[str, object]]:
    return {Path(as_str(as_object(f)["path"])).name: dict(as_object(f)) for f in as_list(expected_loads(root)["files"])}


def _memory(root: Path) -> Path:
    return claude_project_dir(root) / "memory"


def test_the_plugins_root_follows_the_environment(tmp_path: Path) -> None:
    assert claude_plugins_dir() == tmp_path / "plugins"


def test_enabled_plugins_merge_key_by_key_with_the_highest_source_winning(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(Path.home() / ".claude" / "settings.json", json.dumps({"enabledPlugins": {"a@m": True, "b@m": True}}))
    _write(root / ".claude" / "settings.json", json.dumps({"enabledPlugins": {"b@m": False, "c@m": True}}))
    _write(root / ".claude" / "settings.local.json", json.dumps({"enabledPlugins": {"c@m": False}}))
    assert enabled_plugins(root) == {"a@m": True, "b@m": False, "c@m": False}


def test_a_malformed_install_record_is_refused_by_name(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(tmp_path / "plugins" / "installed_plugins.json", "{not json")
    with pytest.raises(InstalledPluginsUnreadableError):
        installed_plugin_roots(root)


def test_the_command_ends_with_the_message_and_exit_2_for_a_malformed_install_record(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(tmp_path / "plugins" / "installed_plugins.json", "{not json")
    result = CliRunner().invoke(app, ["expected-loads", str(root)])
    assert result.exit_code == 2
    assert "installed_plugins.json" in result.output and "Traceback" not in result.output
    assert not isinstance(result.exception, InstalledPluginsUnreadableError)


def test_a_plugin_installed_for_another_project_does_not_apply(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _plugin(tmp_path, "mine@m", "mine", scope="project", project=root)
    _plugin(tmp_path, "theirs@m", "theirs", scope="project", project=tmp_path / "elsewhere")
    assert [plugin_id for plugin_id, _ in installed_plugin_roots(root)] == ["mine@m"]


def test_a_user_skill_and_an_enabled_plugin_skill_appear_and_a_disabled_one_does_not(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(Path.home() / ".claude" / "skills" / "x" / "SKILL.md", SKILL.format(name="x"))
    on = _plugin(tmp_path, "on@m", "on")
    off = _plugin(tmp_path, "off@m", "off")
    _write(Path.home() / ".claude" / "settings.json", json.dumps({"enabledPlugins": {"off@m": False}}))
    found = _invocable(root)
    user = found[("skills", "x")]
    assert user["precedence"] == "user" and user["plugin"] is None
    plugin = found[("skills", "on:y")]
    assert plugin["precedence"] == "plugin" and plugin["plugin"] == "on@m"
    assert plugin["path"] == str(on / "skills" / "y" / "SKILL.md")
    assert found[("agents", "on:helper")]["plugin"] == "on@m"
    assert found[("commands", "on:go")]["precedence"] == "plugin"
    paths = [str(i["path"]) for i in found.values()]
    assert not any(p.startswith(str(off)) for p in paths)
    assert not any(p.endswith("ref.md") for p in paths)


def test_a_plugin_root_with_brackets_in_its_path_lists_its_skill(tmp_path: Path) -> None:
    root = _project(tmp_path)
    base = _plugin(tmp_path, "odd@m", "[wip]")
    assert base.name == "[wip]"
    assert _invocable(root)[("skills", "odd:y")]["plugin"] == "odd@m"


def test_a_user_skills_folder_is_walked_without_entering_a_pruned_folder(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(Path.home() / ".claude" / "skills" / "x" / "SKILL.md", SKILL.format(name="x"))
    _write(Path.home() / ".claude" / "skills" / "x" / "ref.md", "# ref\n")
    _write(Path.home() / ".claude" / "skills" / "x" / "node_modules" / "dep" / "vendored.md", "# vendored\n")
    names = {Path(as_str(as_object(f)["path"])).name for f in as_list(expected_loads(root)["files"])}
    assert "ref.md" in names
    assert "vendored.md" not in names


def test_a_project_skill_is_project_scope(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / ".claude" / "skills" / "demo" / "SKILL.md", SKILL.format(name="demo"))
    assert _invocable(root)[("skills", "demo")]["precedence"] == "project"


def test_a_memory_topic_file_is_linked_only_when_the_index_links_it_in_the_window(tmp_path: Path) -> None:
    root = _project(tmp_path)
    memory = _memory(root)
    for name in ("a", "b", "c"):
        _write(memory / f"feedback_{name}.md", "---\ntype: feedback\n---\n\nText.\n")
    index = "# Memory\n\n- [a](feedback_a.md) first\n" + "\n" * 205 + "- [c](feedback_c.md) late\n"
    _write(memory / "MEMORY.md", index)
    files = _files(root)
    assert files["feedback_a.md"]["linked"] is True
    assert files["feedback_b.md"]["linked"] is False
    assert files["feedback_c.md"]["linked"] is False
    assert files["feedback_a.md"]["memory_type"] == "feedback"
    assert files["feedback_a.md"]["precedence"] == "auto"
    assert "linked" not in files["MEMORY.md"] and "linked" not in files["CLAUDE.md"]


def test_a_memory_topic_label_drops_its_type_prefix(tmp_path: Path) -> None:
    path = tmp_path / "feedback_energy_misleading.md"
    assert file_label("memory", path, "w", memory_type="feedback") == "energy_misleading"
    assert file_label("memory", path, "w", memory_type=None) == "feedback_energy_misleading"
    assert file_label("memory", tmp_path / "MEMORY.md", "w", memory_type=None) == "MEMORY.md"


def test_the_memory_type_reads_from_frontmatter_type_or_metadata_type(tmp_path: Path) -> None:
    root = _project(tmp_path)
    memory = _memory(root)
    _write(memory / "feedback_one.md", "---\ntype: feedback\n---\n\nOne.\n")
    _write(memory / "project_two.md", "---\nmetadata:\n  type: project\n---\n\nTwo.\n")
    _write(memory / "plain.md", "# plain\n")
    _write(memory / "MEMORY.md", "# Memory\n")
    files = _files(root)
    assert (files["feedback_one.md"]["label"], files["feedback_one.md"]["memory_type"]) == ("one", "feedback")
    assert (files["project_two.md"]["label"], files["project_two.md"]["memory_type"]) == ("two", "project")
    assert (files["plain.md"]["label"], files["plain.md"]["memory_type"]) == ("plain", None)


def test_labels_follow_the_kind_of_file(tmp_path: Path) -> None:
    assert file_label("skills", tmp_path / "skills" / "demo" / "SKILL.md", "w") == "demo"
    assert file_label("agents", tmp_path / "helper.md", "w") == "helper"
    assert file_label("skills", tmp_path / "skills" / "demo" / "SKILL.md", "w", plugin="p@m") == "p:demo"
    assert file_label("agents", tmp_path / "helper.md", "w", plugin="p@m") == "p:helper"
    assert file_label("main", tmp_path / "CLAUDE.md", "CLAUDE.md") == "CLAUDE.md"
