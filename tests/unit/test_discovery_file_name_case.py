"""Discovery finds a file only when the agent would open it by its documented name."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery import walk
from reporails_cli.core.discovery.agents import clear_agent_cache, detect_agents
from reporails_cli.core.discovery.features import detect_features_filesystem
from reporails_cli.core.lint.rule_runner import _classify_agent_files
from reporails_cli.core.platform.dto.models import Level
from reporails_cli.core.platform.policy.levels import determine_level_from_gates

CASES = [("claude", "CLAUDE.md", "docs"), ("codex", "AGENTS.md", "pkg")]


def _write(root: Path, rel: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("# Notes\n\nRun the tests before committing.\n", encoding="utf-8")


def _marker(root: Path, agent: str) -> None:
    (root / f".{agent}").mkdir()
    (root / f".{agent}" / "config.toml").write_text("# marker\n")


def _level(root: Path) -> Level:
    clear_agent_cache()
    return determine_level_from_gates(detect_features_filesystem(root, agents=detect_agents(root)))


def _files(root: Path, agent: str) -> list[str]:
    clear_agent_cache()
    return sorted(
        p.relative_to(root).as_posix()
        for a in detect_agents(root)
        if a.agent_type.id == agent
        for p in a.instruction_files
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("agent", "name", "folder"), CASES)
def test_wrong_case_copy_is_not_discovered_on_a_case_sensitive_filesystem(
    tmp_path: Path, agent: str, name: str, folder: str
) -> None:
    _marker(tmp_path, agent)
    _write(tmp_path, name)
    alone = _level(tmp_path)
    _write(tmp_path, f"{folder}/{name.lower()}")

    assert f"{folder}/{name.lower()}" not in _files(tmp_path, agent)
    assert _level(tmp_path) == alone == Level.L1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_exact_case_nested_file_is_still_discovered(tmp_path: Path) -> None:
    _marker(tmp_path, "codex")
    _write(tmp_path, "AGENTS.md")
    _write(tmp_path, "pkg/AGENTS.md")

    assert "pkg/AGENTS.md" in _files(tmp_path, "codex")
    assert _level(tmp_path) == Level.L3


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_wrong_case_copy_is_discovered_and_typed_on_a_case_insensitive_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".git").mkdir()
    _write(tmp_path, "CLAUDE.md")
    _write(tmp_path, "docs/CLAUDE.md")
    exact_level = _level(tmp_path)
    exact_types = {
        cf.path.relative_to(tmp_path).as_posix(): cf.file_type
        for cf in _classify_agent_files(tmp_path, [tmp_path / "docs" / "CLAUDE.md"], "claude")[0]
    }
    (tmp_path / "docs" / "CLAUDE.md").rename(tmp_path / "docs" / "claude.md")
    monkeypatch.setattr(walk, "_same_file", lambda documented, listed: True)

    found = _files(tmp_path, "claude")
    typed = {
        cf.path.relative_to(tmp_path).as_posix(): cf.file_type
        for cf in _classify_agent_files(tmp_path, [tmp_path / "docs" / "claude.md"], "claude")[0]
    }

    assert "docs/claude.md" in found
    assert list(typed.values()) == list(exact_types.values()) != []
    assert _level(tmp_path) == exact_level
