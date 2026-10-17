"""Mutation-killing tests for discovery/features.py.

Seam tests over the filesystem feature detectors: hooks detection, settings-hooks parsing, and directory-content checks.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.discovery.features import (
    _detect_auto_memory,
    _hooks_key_is_set,
    _SurfaceScan,
    detect_features_filesystem,
)
from reporails_cli.core.discovery.walk import is_under


def _agent(files: list[Path]) -> SimpleNamespace:
    return SimpleNamespace(instruction_files=files, rule_files=[])


def _claude_agent() -> SimpleNamespace:
    """A minimal detected-agent stand-in that resolves against the real bundled
    claude config.yml — the mcp/hooks surface checks read `agent_type.id` to load
    that agent's own file-type patterns."""
    return SimpleNamespace(agent_type=SimpleNamespace(id="claude"), instruction_files=[], rule_files=[])


# ──────────────────────────────────────────────────────────────────
# hooks detection  (L158, L159)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_hooks_detected_from_settings_json_alone(tmp_path: Path) -> None:
    claude = tmp_path / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text('{"hooks": {"PreToolUse": []}}')
    feats = detect_features_filesystem(tmp_path, agents=[_claude_agent()])
    # Only settings.json carries hooks (no hooks dir, no settings.local) → True.
    assert feats.hook_files == (tmp_path / ".claude/settings.json",)  # kills L158 and L159 (both or→and)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_bare_mcp_json_with_no_detected_agent_grants_no_hooks(tmp_path: Path) -> None:
    """A bare `.mcp.json` with no detected agent grants no capability — the gate
    reads a detected agent's own config.yml, never a raw top-level filename."""
    (tmp_path / ".mcp.json").write_text("{}")
    feats = detect_features_filesystem(tmp_path, agents=[])
    assert feats.hook_files == ()


# ──────────────────────────────────────────────────────────────────
# _hooks_key_is_set  (L175, L181, L182)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_hooks_key_is_set_missing_file_is_false(tmp_path: Path) -> None:
    assert _hooks_key_is_set(tmp_path / "nope.json", _SurfaceScan(exclude_dirs=frozenset())) is False  # kills L175


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_hooks_key_is_set_malformed_json_is_false(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    p.write_text("{ not valid json")
    assert _hooks_key_is_set(p, _SurfaceScan(exclude_dirs=frozenset())) is False  # kills L181


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_hooks_key_is_set_dict_without_hooks_is_false(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    p.write_text('{"other": 1}')
    assert _hooks_key_is_set(p, _SurfaceScan(exclude_dirs=frozenset())) is False  # kills L182 and→or


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_hooks_key_is_set_dict_with_hooks_is_true(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    p.write_text('{"hooks": {"PreToolUse": []}}')
    assert _hooks_key_is_set(p, _SurfaceScan(exclude_dirs=frozenset())) is True


# ──────────────────────────────────────────────────────────────────
# _detect_auto_memory  (L193)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_detect_auto_memory_absent_dir_is_false(tmp_path: Path) -> None:
    # tmp_path's slug has no ~/.claude/projects/<slug>/memory dir → False.
    assert _detect_auto_memory(tmp_path) is False  # kills L193 False→True


# ──────────────────────────────────────────────────────────────────
# is_under  (L205 except → False)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_is_under_unresolvable_path_is_false(tmp_path: Path) -> None:
    # A null-byte path raises ValueError on resolve → the guard must return False.
    assert is_under(Path("bad\x00path"), tmp_path) is False  # kills L205


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_symlink_loop_in_the_scanned_tree_is_skipped_not_fatal(tmp_path: Path) -> None:
    """A circular symlink named like an instruction file never stops level detection."""
    (tmp_path / "CLAUDE.md").write_text("# Project\n\nAlways run tests.\n", encoding="utf-8")
    loop = tmp_path / "loop"
    loop.mkdir()
    (loop / "CLAUDE.md").symlink_to("x")
    (loop / "x").symlink_to("CLAUDE.md")
    assert is_under(loop / "CLAUDE.md", tmp_path) is False
    features = detect_features_filesystem(tmp_path)
    assert features.has_instruction_file is True
