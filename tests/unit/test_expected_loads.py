"""`ails expected-loads`: the files Claude Code loads for a session in a folder, and the AGENTS.md it skips."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.pipeline.expected_loads import expected_loads
from reporails_cli.core.platform.config import claude_settings
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


def _write(path: Path, text: str = "# Notes\n\nRun the tests.\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _mode(mode: str, plugin_id: str = "agents-md@builtin") -> None:
    settings = Path.home() / ".claude" / "settings.json"
    data = {"pluginConfigs": {plugin_id: {"options": {"instructionFiles": mode}}}}
    _write(settings, json.dumps(data))


@pytest.fixture(autouse=True)
def _no_managed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    real = claude_settings._settings_patterns

    def patterns() -> dict[str, list[str]]:
        scopes = real()
        scopes["managed"] = [str(tmp_path / "managed" / "managed-settings.json")]
        scopes["managed_dropin"] = [str(tmp_path / "managed" / "d" / "*.json")]
        return scopes

    monkeypatch.setattr(claude_settings, "_settings_patterns", patterns)


def _project(tmp_path: Path) -> Path:
    return tmp_path / "proj"


def _by_name(items: list[dict], root: Path) -> dict[str, dict]:
    return {Path(i["path"]).relative_to(root).as_posix(): i for i in items}


def _home_items(items: list[dict]) -> dict[str, dict]:
    """The entries under the user's `~/.claude/`, by path relative to it."""
    home = Path.home() / ".claude"
    return {Path(i["path"]).relative_to(home).as_posix(): i for i in items if Path(i["path"]).is_relative_to(home)}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_agents_md_beside_claude_md_is_skipped(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / "AGENTS.md")
    out = expected_loads(root)
    assert _by_name(out["files"], root)["CLAUDE.md"]["file_type"] == "main"
    assert "AGENTS.md" not in _by_name(out["files"], root)
    skipped = _by_name(out["skipped"], root)["AGENTS.md"]
    assert skipped["reason"] == "claude_md_present"
    assert skipped["setting"] == "claude-md-or-agents-md"
    assert skipped["file_type"] == "agents_md"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_lone_agents_md_loads_at_session_start(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "AGENTS.md")
    out = expected_loads(root)
    entry = _by_name(out["files"], root)["AGENTS.md"]
    assert (entry["file_type"], entry["loading"], entry["precedence"]) == ("agents_md", "session_start", "project")
    assert out["skipped"] == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_and_mode_loads_both(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / "AGENTS.md")
    _mode("claude-md-and-agents-md")
    out = expected_loads(root)
    assert {"CLAUDE.md", "AGENTS.md"} <= set(_by_name(out["files"], root))
    assert out["skipped"] == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_claude_md_mode_skips_agents_md_as_setting_off(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "AGENTS.md")
    _mode("claude-md")
    skipped = _by_name(expected_loads(root)["skipped"], root)["AGENTS.md"]
    assert (skipped["reason"], skipped["setting"]) == ("setting_off", "claude-md")


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_agents_dir_is_never_read(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / ".agents" / "AGENTS.md")
    skipped = _by_name(expected_loads(root)["skipped"], root)
    assert skipped[".agents/AGENTS.md"]["reason"] == "never_read"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_nested_agents_md_beside_its_own_claude_md_is_skipped(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "sub" / "AGENTS.md")
    _write(root / "sub" / "CLAUDE.md")
    _write(root / "other" / "AGENTS.md")
    out = expected_loads(root)
    assert _by_name(out["skipped"], root)["sub/AGENTS.md"]["reason"] == "subdir_has_claude_md"
    loaded = _by_name(out["files"], root)["other/AGENTS.md"]
    assert (loaded["file_type"], loaded["loading"]) == ("nested_context", "on_demand")


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_config_surfaces_are_not_listed(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / ".claude" / "settings.json", "{}")
    _write(root / ".claude" / "rules" / "style.md")
    names = set(_by_name(expected_loads(root)["files"], root))
    assert names == {"CLAUDE.md", ".claude/rules/style.md"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_command_prints_one_json_object(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    result = runner.invoke(app, ["expected-loads", str(root), "--agent", "claude"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert list(data) == ["version", "agent", "root", "event_log_dir", "files", "skipped", "aliases"]
    assert data["version"] == 1
    assert data["agent"] == "claude"
    assert data["event_log_dir"] == str(Path.home() / ".reporails" / "xray")
    assert set(data["files"][0]) == {"path", "file_type", "loading", "precedence"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_agents_md_linked_to_claude_md_is_reported_as_that_file(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / "sub" / "CLAUDE.md")
    _write(root / "sub2" / "CLAUDE.md")
    _write(root / "sub2" / "AGENTS.md")
    _write(root / "sub3" / "CLAUDE.md")
    _write(root / "sub3" / "notes.md")
    try:
        (root / "AGENTS.md").symlink_to("CLAUDE.md")
        (root / "sub" / "AGENTS.md").symlink_to("CLAUDE.md")
        (root / "sub3" / "AGENTS.md").symlink_to("notes.md")
    except OSError:
        pytest.skip("symlinks cannot be created here")
    out = expected_loads(root)
    resolved = root.resolve()
    assert out["aliases"] == [
        {"path": str(resolved / "AGENTS.md"), "same_as": str(resolved / "CLAUDE.md")},
        {"path": str(resolved / "sub" / "AGENTS.md"), "same_as": str(resolved / "sub" / "CLAUDE.md")},
    ]
    skipped = {Path(i["path"]).relative_to(resolved).as_posix(): i["reason"] for i in out["skipped"]}
    assert skipped == {"sub2/AGENTS.md": "claude_md_present", "sub3/AGENTS.md": "claude_md_present"}


def _link(link: Path, target: str) -> None:
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlinks cannot be created here")


def _skipped_reasons(out: dict, root: Path) -> dict[str, str]:
    return {k: v["reason"] for k, v in _by_name(out["skipped"], root).items()}


def _alias_names(out: dict, root: Path) -> dict[str, str]:
    resolved = root.resolve()
    return {
        Path(a["path"]).relative_to(resolved).as_posix(): Path(a["same_as"]).relative_to(resolved).as_posix()
        for a in out["aliases"]
    }


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_claude_md_linking_to_regular_agents_md_makes_agents_md_an_alias(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "AGENTS.md")
    _link(root / "CLAUDE.md", "AGENTS.md")
    out = expected_loads(root)
    assert _alias_names(out, root) == {"AGENTS.md": "CLAUDE.md"}
    assert out["skipped"] == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_agents_md_linking_to_claude_local_md_is_an_alias(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.local.md")
    _link(root / "AGENTS.md", "CLAUDE.local.md")
    out = expected_loads(root)
    assert _alias_names(out, root) == {"AGENTS.md": "CLAUDE.local.md"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_agents_md_linking_into_agents_dir_or_excluded_folder_stays_skipped(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / ".agents" / "CLAUDE.md")
    _write(root / "node_modules" / "pkg" / "CLAUDE.md")
    _link(root / "AGENTS.md", ".agents/CLAUDE.md")
    _link(root / "a" / "AGENTS.md", "../node_modules/pkg/CLAUDE.md")
    out = expected_loads(root)
    assert out["aliases"] == []
    assert _skipped_reasons(out, root) == {"AGENTS.md": "claude_md_present", "a/AGENTS.md": "claude_md_present"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_links_to_one_file_are_each_reported_under_their_own_name(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _link(root / "AGENTS.md", "CLAUDE.md")
    _link(root / ".claude" / "AGENTS.md", "../CLAUDE.md")
    assert _alias_names(expected_loads(root), root) == {
        "AGENTS.md": "CLAUDE.md",
        ".claude/AGENTS.md": "CLAUDE.md",
    }


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_agents_md_excluded_in_config_is_not_reported_as_skipped(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / "AGENTS.md")
    _write(root / "legacy" / "AGENTS.md")
    _write(
        root / ".ails" / "config.yml",
        'schema_version: "0.1.0"\nsurfaces:\n  claude.agents_md:\n    exclude: ["legacy/**"]\n',
    )
    assert set(_skipped_reasons(expected_loads(root), root)) == {"AGENTS.md"}


def _managed_only_project(root: Path) -> None:
    _write(root / "CLAUDE.md")
    _write(root / "CLAUDE.local.md")
    _link(root / "AGENTS.md", "CLAUDE.md")
    _write(root / ".claude" / "rules" / "style.md")
    _write(root / ".claude" / "rules" / "scoped.md", "---\npaths:\n  - src/**\n---\n\nUse type hints.\n")
    _write(root / "sub" / "CLAUDE.md")
    _write(root / "sub" / ".claude" / "rules" / "x.md")
    _write(Path.home() / ".claude" / "CLAUDE.md")
    _write(Path.home() / ".claude" / "rules" / "pref.md")


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize("plugin_id", ["agents-md@builtin", "cc-plugin-agents-md@builtin"])
def test_managed_only_leaves_out_what_claude_leaves_out_at_launch(tmp_path: Path, plugin_id: str) -> None:
    root = _project(tmp_path)
    _managed_only_project(root)
    _mode("managed-only", plugin_id)
    out = expected_loads(root)
    assert out["aliases"] == []
    files = _by_name([i for i in out["files"] if Path(i["path"]).is_relative_to(root)], root)
    assert {k: v["loading"] for k, v in files.items()} == {
        "sub/CLAUDE.md": "on_demand",
        "sub/.claude/rules/x.md": "on_demand",
        ".claude/rules/scoped.md": "on_demand",
    }
    assert not _home_items(out["files"])
    skipped = _by_name([i for i in out["skipped"] if Path(i["path"]).is_relative_to(root)], root)
    assert {k: (v["reason"], v["setting"]) for k, v in skipped.items()} == dict.fromkeys(
        ("CLAUDE.md", "CLAUDE.local.md", ".claude/rules/style.md", "AGENTS.md"), ("setting_off", "managed-only")
    )
    assert (skipped[".claude/rules/style.md"]["file_type"], skipped["AGENTS.md"]["file_type"]) == ("rules", "agents_md")
    home = _home_items(out["skipped"])
    assert {k: (v["reason"], v["file_type"]) for k, v in home.items()} == {
        "CLAUDE.md": ("setting_off", "main"),
        "rules/pref.md": ("setting_off", "rules"),
    }


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_claude_md_mode_keeps_every_instruction_file_loaded(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(root / ".claude" / "rules" / "style.md")
    _mode("claude-md", "cc-plugin-agents-md@builtin")
    out = expected_loads(root)
    names = set(_by_name([i for i in out["files"] if Path(i["path"]).is_relative_to(root)], root))
    assert {"CLAUDE.md", ".claude/rules/style.md"} <= names
    assert out["skipped"] == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_empty_files_are_not_expected_to_load(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md", "")
    _write(root / ".claude" / "rules" / "blank.md", " \n\n")
    _write(root / ".claude" / "rules" / "real.md")
    out = expected_loads(root)
    names = set(_by_name([i for i in out["files"] if Path(i["path"]).is_relative_to(root)], root))
    assert names == {".claude/rules/real.md"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_user_instruction_files_are_listed_with_their_loading(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _write(root / "CLAUDE.md")
    _write(Path.home() / ".claude" / "CLAUDE.md")
    _write(Path.home() / ".claude" / "rules" / "pref.md")
    _write(Path.home() / ".claude" / "rules" / "scoped.md", "---\npaths:\n  - src/**\n---\n\nUse type hints.\n")
    out = expected_loads(root)
    home = _home_items(out["files"])
    assert {k: (v["file_type"], v["loading"], v["precedence"]) for k, v in home.items()} == {
        "CLAUDE.md": ("main", "session_start", "user"),
        "rules/pref.md": ("rules", "session_start", "user"),
        "rules/scoped.md": ("rules", "on_demand", "user"),
    }


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_no_candidates_reads_no_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.discovery import read_gates

    def boom(_root: Path) -> str:
        raise AssertionError("settings read for an empty input")

    monkeypatch.setattr(read_gates, "claude_instruction_files_mode", boom)
    reads = read_gates.claude_agents_md_reads([], tmp_path)
    assert (reads.kept, reads.skipped, reads.aliases) == ([], [], [])


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_command_rejects_a_path_that_is_not_a_folder(tmp_path: Path) -> None:
    _write(tmp_path / "CLAUDE.md")
    for bad in (tmp_path / "typo-dir", tmp_path / "CLAUDE.md"):
        result = runner.invoke(app, ["expected-loads", str(bad)])
        assert result.exit_code == 2
        assert "Path not found or not a folder" in result.output
