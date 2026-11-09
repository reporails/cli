"""Claude Code's managed tier: server-managed settings (the remote cache) before the managed files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.platform.config import claude_settings
from reporails_cli.core.platform.config.claude_settings import (
    MODE_CLAUDE_MD,
    MODE_CLAUDE_MD_AND_AGENTS_MD,
    MODE_CLAUDE_MD_OR_AGENTS_MD,
    claude_instruction_files_mode,
    claude_settings_files,
)
from reporails_cli.core.platform.contract.errors import ClaudeSettingsUnreadableError

PLUGIN_ID = "cc-plugin-agents-md@builtin"

pytestmark = [pytest.mark.unit, pytest.mark.subsys_classify]


def _mode(value: str) -> dict:
    return {"pluginConfigs": {PLUGIN_ID: {"options": {"instructionFiles": value}}}}


@pytest.fixture
def tiers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Path]:
    paths = {"remote": tmp_path / "remote-settings.json", "managed": tmp_path / "managed-settings.json"}
    monkeypatch.setattr(
        claude_settings, "_settings_patterns", lambda: {name: [str(path)] for name, path in paths.items()}
    )
    return paths


def _put(path: Path, data: dict | str) -> None:
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")


def test_remote_cache_with_a_policy_key_ignores_the_managed_file(tiers: dict[str, Path]) -> None:
    _put(tiers["remote"], _mode("claude-md"))
    _put(tiers["managed"], _mode("claude-md-and-agents-md"))
    assert claude_instruction_files_mode() == MODE_CLAUDE_MD


def test_empty_remote_cache_leaves_the_managed_file_in_force(tiers: dict[str, Path]) -> None:
    _put(tiers["remote"], {})
    _put(tiers["managed"], _mode("claude-md-and-agents-md"))
    assert claude_instruction_files_mode() == MODE_CLAUDE_MD_AND_AGENTS_MD


def test_remote_cache_with_only_control_keys_delivers_no_policy(tiers: dict[str, Path]) -> None:
    _put(tiers["remote"], {"managedSourcesBehavior": "merge"})
    _put(tiers["managed"], _mode("claude-md-and-agents-md"))
    assert claude_instruction_files_mode() == MODE_CLAUDE_MD_AND_AGENTS_MD


def test_merge_ranks_the_remote_value_above_the_managed_one(tiers: dict[str, Path]) -> None:
    _put(tiers["remote"], {**_mode("claude-md"), "managedSourcesBehavior": "merge"})
    _put(tiers["managed"], _mode("claude-md-and-agents-md"))
    assert claude_instruction_files_mode() == MODE_CLAUDE_MD
    assert claude_settings._managed_files(claude_settings._settings_patterns()) == [tiers["managed"], tiers["remote"]]


def test_merge_keeps_a_managed_key_the_remote_cache_does_not_set(tiers: dict[str, Path]) -> None:
    _put(tiers["remote"], {"cleanupPeriodDays": 5, "managedSourcesBehavior": "merge"})
    _put(tiers["managed"], _mode("claude-md"))
    assert claude_instruction_files_mode() == MODE_CLAUDE_MD


def test_no_remote_cache_is_the_file_tier(tiers: dict[str, Path]) -> None:
    _put(tiers["managed"], _mode("claude-md"))
    assert claude_instruction_files_mode() == MODE_CLAUDE_MD
    tiers["managed"].unlink()
    assert claude_instruction_files_mode() == MODE_CLAUDE_MD_OR_AGENTS_MD


@pytest.mark.parametrize("text", ["{nope", "[]", '"x"', ""])
def test_malformed_remote_cache_is_refused_naming_the_file(tiers: dict[str, Path], text: str) -> None:
    _put(tiers["remote"], text)
    with pytest.raises(ClaudeSettingsUnreadableError, match=r"remote-settings\.json"):
        claude_instruction_files_mode()


def test_a_subfolder_of_a_git_repository_reads_the_repository_roots_local_settings_but_not_its_shared_ones(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        claude_settings,
        "_settings_patterns",
        lambda: {"project": [".claude/settings.json"], "local": [".claude/settings.local.json"]},
    )
    repo = tmp_path / "repo"
    folder = repo / "packages" / "app"
    (repo / ".git").mkdir(parents=True)
    for place in (repo, folder):
        (place / ".claude").mkdir(parents=True)
        _put(place / ".claude" / "settings.json", {})
        _put(place / ".claude" / "settings.local.json", {})
    assert claude_settings_files(folder) == (
        folder / ".claude" / "settings.json",
        repo / ".claude" / "settings.local.json",
        folder / ".claude" / "settings.local.json",
    )
    assert claude_settings_files(repo) == (repo / ".claude" / "settings.json", repo / ".claude" / "settings.local.json")


def test_a_worktree_folder_whose_git_marker_is_a_file_still_roots_the_local_settings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(claude_settings, "_settings_patterns", lambda: {"local": [".claude/settings.local.json"]})
    worktree = tmp_path / "worktree"
    folder = worktree / "app"
    (folder / ".claude").mkdir(parents=True)
    (worktree / ".claude").mkdir()
    (worktree / ".git").write_text("gitdir: ../main/.git/worktrees/worktree\n", encoding="utf-8")
    _put(worktree / ".claude" / "settings.local.json", {})
    assert claude_settings_files(folder) == (worktree / ".claude" / "settings.local.json",)
