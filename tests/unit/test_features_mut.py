"""Mutation-killing tests for discovery/features.py.

Seam tests over the filesystem feature detectors: symlink resolution strictness,
hierarchy detection, MCP/hooks detection, settings-hooks parsing, root-instruction
selection, content @import detection, and directory-content checks.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.discovery.features import (
    _detect_auto_memory,
    _detect_content_features,
    _find_root_instruction,
    _has_hierarchy,
    _has_hooks_setting,
    detect_features_filesystem,
    resolve_symlinked_files,
)
from reporails_cli.core.discovery.walk import is_under
from reporails_cli.core.platform.dto.results import DetectedFeatures


def _agent(files: list[Path]) -> SimpleNamespace:
    return SimpleNamespace(instruction_files=files, rule_files=[])


def _claude_agent() -> SimpleNamespace:
    """A minimal detected-agent stand-in that resolves against the real bundled
    claude config.yml — the mcp/hooks surface checks read `agent_type.id` to load
    that agent's own file-type patterns."""
    return SimpleNamespace(agent_type=SimpleNamespace(id="claude"), instruction_files=[], rule_files=[])


# ──────────────────────────────────────────────────────────────────
# resolve_symlinked_files  (L39 strict=True)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_dangling_symlink_outside_is_skipped_not_resolved(tmp_path: Path) -> None:
    """A dangling symlink must be skipped by strict resolution — never emitted as an
    extra scan target. strict=False would resolve the missing path and, being outside
    the scan dir, wrongly append it (kills L39 True→False)."""
    link = tmp_path / "CLAUDE.md"
    os.symlink("/nonexistent/outside/CLAUDE.md", str(link))
    result = resolve_symlinked_files(tmp_path, agents=[_agent([link])])
    assert result == []


# ──────────────────────────────────────────────────────────────────
# _has_hierarchy  (L60, L63, L68, L69, L70, L71)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_hierarchy_none_agents_is_false(tmp_path: Path) -> None:
    assert _has_hierarchy(tmp_path, None) is False  # kills L60


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_hierarchy_true_only_with_root_and_nested(tmp_path: Path) -> None:
    hier = _agent([tmp_path / "CLAUDE.md", tmp_path / "sub" / "CLAUDE.md"])
    assert _has_hierarchy(tmp_path, [hier]) is True  # kills L68 (has_nested), L70 (return True)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_hierarchy_root_only_is_false(tmp_path: Path) -> None:
    root_only = _agent([tmp_path / "CLAUDE.md"])
    # names_at_root set but no nested → must be False (kills L63 init, L69 and→or, L71 return False).
    assert _has_hierarchy(tmp_path, [root_only]) is False


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_hierarchy_nested_only_is_false(tmp_path: Path) -> None:
    nested_only = _agent([tmp_path / "sub" / "CLAUDE.md"])
    assert _has_hierarchy(tmp_path, [nested_only]) is False  # kills L69 and→or (nested arm)


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
    assert feats.has_hooks is True  # kills L158 and L159 (both or→and)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_bare_mcp_json_with_no_detected_agent_grants_no_hooks(tmp_path: Path) -> None:
    """A bare `.mcp.json` with no detected agent grants no capability — the gate
    reads a detected agent's own config.yml, never a raw top-level filename."""
    (tmp_path / ".mcp.json").write_text("{}")
    feats = detect_features_filesystem(tmp_path, agents=[])
    assert feats.has_hooks is False


# ──────────────────────────────────────────────────────────────────
# _has_hooks_setting  (L175, L181, L182)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_hooks_setting_missing_file_is_false(tmp_path: Path) -> None:
    assert _has_hooks_setting(tmp_path / "nope.json") is False  # kills L175


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_hooks_setting_malformed_json_is_false(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    p.write_text("{ not valid json")
    assert _has_hooks_setting(p) is False  # kills L181


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_hooks_setting_dict_without_hooks_is_false(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    p.write_text('{"other": 1}')
    assert _has_hooks_setting(p) is False  # kills L182 and→or


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_has_hooks_setting_dict_with_hooks_is_true(tmp_path: Path) -> None:
    p = tmp_path / "settings.json"
    p.write_text('{"hooks": {"PreToolUse": []}}')
    assert _has_hooks_setting(p) is True


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


# ──────────────────────────────────────────────────────────────────
# _find_root_instruction  (L211 ==→!=)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_find_root_instruction_returns_root_level_file(tmp_path: Path) -> None:
    root = tmp_path / "CLAUDE.md"
    nested = tmp_path / "sub" / "AGENTS.md"
    assert _find_root_instruction(tmp_path, [nested, root]) == root  # kills L211


# ──────────────────────────────────────────────────────────────────
# _detect_content_features @import  (L226 or→and)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_content_import_detected_from_import_marker(tmp_path: Path) -> None:
    root = tmp_path / "CLAUDE.md"
    root.write_text("Top matter.\n@./other.md\nMore text.\n")
    feats = DetectedFeatures()
    _detect_content_features(root, feats)
    assert feats.has_imports is True  # kills L226 or→and


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    "body",
    [
        "Mail me at user@example.com.\n",
        "Write `@./other.md` to import a file.\n",
        "```\n@./other.md\n```\n",
        "~~~~\n@./other.md\n~~~~\n",
        "``code @./other.md``\n",
    ],
)
def test_content_import_ignores_mentions_and_code(tmp_path: Path, body: str) -> None:
    root = tmp_path / "CLAUDE.md"
    root.write_text(body)
    feats = DetectedFeatures()
    _detect_content_features(root, feats)
    assert feats.has_imports is False


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
    assert resolve_symlinked_files(tmp_path) == []
