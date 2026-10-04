"""A home-rooted or memory-recall file reaches the wire with the registry's facts.

`_detect_file_loading` matched a `~`-rooted registry pattern (`~/.claude/CLAUDE.md`,
`~/.codex/AGENTS.md`) against the file's raw absolute path without expanding `~`, so
every discovered home file fell through to the `session_start`/`global`/`generic`
fallback instead of its real agent and type. It also never applied the memory
surface's index-vs-sibling split, so a memory note that is not `MEMORY.md` wired as
`session_start` instead of `on_demand`. These tests demonstrate both are fixed,
using the real bundled registry (`_load_registry()`), the same fixture the
path-filter SEAM tests in `test_inspect_path_key.py` use.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.inspect import _detect_file_loading, _load_registry


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def home(monkeypatch, tmp_path) -> Path:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    return home_dir


@pytest.mark.unit
@pytest.mark.subsys_map
def test_home_auto_memory_note_wires_its_registry_loading(home: Path, tmp_path: Path) -> None:
    """A sibling auto-memory note outside `root` wires `memory`/`on_demand`, not `generic`."""
    root = tmp_path / "proj"
    root.mkdir()
    note = _write(home / ".claude" / "projects" / "proj-slug" / "memory" / "notes.md", "# Notes\n")

    assert _detect_file_loading(note, root, _load_registry()) == ("on_demand", "global", (), "claude", "memory")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_home_auto_memory_index_wires_session_start(home: Path, tmp_path: Path) -> None:
    """The `MEMORY.md` index note still wires eager `session_start`, not `on_demand`."""
    root = tmp_path / "proj"
    root.mkdir()
    index = _write(home / ".claude" / "projects" / "proj-slug" / "memory" / "MEMORY.md", "# Memory\n")

    assert _detect_file_loading(index, root, _load_registry()) == (
        "session_start",
        "global",
        (),
        "claude",
        "memory",
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_user_scope_claude_md_wires_main(home: Path, tmp_path: Path) -> None:
    """`~/.claude/CLAUDE.md` wires `main`/`session_start`, not the generic fallback."""
    root = tmp_path / "proj"
    root.mkdir()
    user_file = _write(home / ".claude" / "CLAUDE.md", "# User memory\n")

    assert _detect_file_loading(user_file, root, _load_registry()) == (
        "session_start",
        "global",
        (),
        "claude",
        "main",
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_other_agents_home_file_wires_its_own_agent_and_type(home: Path, tmp_path: Path) -> None:
    """A non-Claude agent's home file (`~/.codex/AGENTS.md`) wires `codex`/`main`."""
    root = tmp_path / "proj"
    root.mkdir()
    user_file = _write(home / ".codex" / "AGENTS.md", "# Codex user instructions\n")

    assert _detect_file_loading(user_file, root, _load_registry()) == (
        "session_start",
        "global",
        (),
        "codex",
        "main",
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_project_scoped_subagent_memory_sibling_wires_on_demand(tmp_path: Path) -> None:
    """A project-scoped subagent-memory sibling (not `MEMORY.md`) also wires `on_demand`."""
    path = _write(tmp_path / ".claude" / "agent-memory" / "weather-agent" / "notes.md", "# Notes\n")

    assert _detect_file_loading(path, tmp_path, _load_registry()) == (
        "on_demand",
        "task_scoped",
        (),
        "claude",
        "subagent_memory",
    )
