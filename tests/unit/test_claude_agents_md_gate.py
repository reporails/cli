"""Claude Code reads AGENTS.md only under the condition its own settings decide.

Claude Code loads `AGENTS.md` through its built-in `agents-md` plugin. With the default
`claude-md-or-agents-md` setting it reads the root `AGENTS.md` and `.claude/AGENTS.md`
only when no `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` sits in the working
directory or above it, and a subdirectory's `AGENTS.md` on demand when that subdirectory
has none of those files. `claude-md-and-agents-md` reads both; `claude-md`,
`managed-only` and a turned-off plugin read no `AGENTS.md`. The setting counts in the
user's and managed settings, never in a project's own settings files.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.discovery.read_gates import apply_read_gate, claude_agents_md_files, reads_as_fallback
from reporails_cli.core.platform.config import claude_settings
from reporails_cli.core.platform.config.claude_settings import claude_instruction_files_mode


def _write(path: Path, text: str = "# Notes\n\nRun the tests.\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _settings(path: Path, *, mode: str | None = None, enabled: bool | None = None) -> None:
    data: dict = {}
    if mode is not None:
        data["pluginConfigs"] = {"agents-md@builtin": {"options": {"instructionFiles": mode}}}
    if enabled is not None:
        data["enabledPlugins"] = {"agents-md@builtin": enabled}
    _write(path, json.dumps(data))


@pytest.fixture
def no_managed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Point the managed settings at a scratch directory so the machine's own policy
    never decides a test."""
    managed_dir = tmp_path / "managed"
    real = claude_settings._settings_patterns

    def patterns() -> dict[str, list[str]]:
        scopes = real()
        scopes["managed"] = [str(managed_dir / "managed-settings.json")]
        scopes["managed_dropin"] = [str(managed_dir / "managed-settings.d" / "*.json")]
        return scopes

    monkeypatch.setattr(claude_settings, "_settings_patterns", patterns)
    return managed_dir


def _user_settings() -> Path:
    return Path.home() / ".claude" / "settings.json"


# ── the setting ──────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_default_mode_without_any_setting(no_managed: Path, tmp_path: Path) -> None:
    assert claude_instruction_files_mode(tmp_path) == "claude-md-or-agents-md"


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize("mode", ["claude-md-and-agents-md", "claude-md", "managed-only", "claude-md-or-agents-md"])
def test_user_settings_pick_the_mode(no_managed: Path, tmp_path: Path, mode: str) -> None:
    _settings(_user_settings(), mode=mode)
    assert claude_instruction_files_mode(tmp_path) == mode


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_project_and_local_settings_never_pick_the_mode(no_managed: Path, tmp_path: Path) -> None:
    """Claude Code ignores `pluginConfigs` in a project's own settings files."""
    _settings(tmp_path / ".claude" / "settings.json", mode="claude-md")
    _settings(tmp_path / ".claude" / "settings.local.json", mode="claude-md")
    assert claude_instruction_files_mode(tmp_path) == "claude-md-or-agents-md"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_managed_settings_outrank_the_user(no_managed: Path, tmp_path: Path) -> None:
    _settings(_user_settings(), mode="claude-md-and-agents-md")
    _settings(no_managed / "managed-settings.json", mode="claude-md")
    assert claude_instruction_files_mode(tmp_path) == "claude-md"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_managed_drop_in_overrides_the_managed_file(no_managed: Path, tmp_path: Path) -> None:
    _settings(no_managed / "managed-settings.json", mode="claude-md")
    _settings(no_managed / "managed-settings.d" / "20-agents.json", mode="managed-only")
    assert claude_instruction_files_mode(tmp_path) == "managed-only"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_an_unknown_value_is_the_default(no_managed: Path, tmp_path: Path) -> None:
    _settings(_user_settings(), mode="something-else")
    assert claude_instruction_files_mode(tmp_path) == "claude-md-or-agents-md"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_turned_off_plugin_reads_claude_md_only(no_managed: Path, tmp_path: Path) -> None:
    _settings(_user_settings(), mode="claude-md-and-agents-md", enabled=False)
    assert claude_instruction_files_mode(tmp_path) == "claude-md"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_local_settings_turn_the_plugin_back_on_over_the_user(no_managed: Path, tmp_path: Path) -> None:
    """`enabledPlugins` counts in every scope: local outranks project, project outranks user."""
    _settings(_user_settings(), enabled=False)
    _settings(tmp_path / ".claude" / "settings.local.json", enabled=True)
    assert claude_instruction_files_mode(tmp_path) == "claude-md-or-agents-md"


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_an_unreadable_settings_file_is_skipped(no_managed: Path, tmp_path: Path) -> None:
    _write(_user_settings(), "{not json")
    assert claude_instruction_files_mode(tmp_path) == "claude-md-or-agents-md"


# ── the gate ─────────────────────────────────────────────────────────


def _project(tmp_path: Path) -> tuple[Path, list[Path]]:
    project = tmp_path / "proj"
    files = [
        _write(project / "AGENTS.md"),
        _write(project / ".claude" / "AGENTS.md"),
        _write(project / "pkg" / "AGENTS.md"),
        _write(project / "own" / "AGENTS.md"),
        _write(project / ".agents" / "AGENTS.md"),
    ]
    _write(project / "own" / "CLAUDE.md")
    return project, files


def _rel(project: Path, files: list[Path]) -> set[str]:
    return {f.relative_to(project).as_posix() for f in files}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_default_mode_reads_agents_md_when_no_claude_file(no_managed: Path, tmp_path: Path) -> None:
    """Root and `.claude/` copies load at session start; a subdirectory copy loads unless
    that subdirectory has a CLAUDE.md of its own; nothing under `.agents/` is read."""
    project, files = _project(tmp_path)
    kept = claude_agents_md_files(files, project)
    assert _rel(project, kept) == {"AGENTS.md", ".claude/AGENTS.md", "pkg/AGENTS.md"}


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize("claude_file", ["CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.local.md", "claude.md"])
def test_default_mode_skips_agents_md_beside_a_claude_file(no_managed: Path, tmp_path: Path, claude_file: str) -> None:
    project, files = _project(tmp_path)
    _write(project / claude_file)
    assert claude_agents_md_files(files, project) == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_claude_file_above_the_project_root_counts(no_managed: Path, tmp_path: Path) -> None:
    project, files = _project(tmp_path)
    _write(tmp_path / "CLAUDE.md")
    assert claude_agents_md_files(files, project) == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_the_users_own_claude_md_does_not_count(no_managed: Path) -> None:
    """`~/.claude/CLAUDE.md` loads alongside AGENTS.md, so a project under HOME keeps it."""
    home = Path.home()
    _write(home / ".claude" / "CLAUDE.md")
    project = home / "work" / "proj"
    files = [_write(project / "AGENTS.md")]
    assert _rel(project, claude_agents_md_files(files, project)) == {"AGENTS.md"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_both_mode_reads_every_agents_md(no_managed: Path, tmp_path: Path) -> None:
    project, files = _project(tmp_path)
    _write(project / "CLAUDE.md")
    _settings(_user_settings(), mode="claude-md-and-agents-md")
    kept = claude_agents_md_files(files, project)
    assert _rel(project, kept) == {"AGENTS.md", ".claude/AGENTS.md", "pkg/AGENTS.md", "own/AGENTS.md"}


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize("mode", ["claude-md", "managed-only"])
def test_claude_md_modes_read_no_agents_md(no_managed: Path, tmp_path: Path, mode: str) -> None:
    project, files = _project(tmp_path)
    _settings(_user_settings(), mode=mode)
    assert claude_agents_md_files(files, project) == []


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_the_gate_applies_only_to_claudes_agents_md_types(no_managed: Path, tmp_path: Path) -> None:
    project, files = _project(tmp_path)
    _write(project / "CLAUDE.md")
    assert apply_read_gate("claude", "agents_md", files, project) == []
    assert apply_read_gate("claude", "nested_context", files, project) == []
    assert apply_read_gate("codex", "main", files, project) == files
    assert apply_read_gate("claude", "skills", files, project) == files


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_claude_reads_agents_md_only_as_a_fallback() -> None:
    assert reads_as_fallback("claude", Path("AGENTS.md"))
    assert not reads_as_fallback("codex", Path("AGENTS.md"))
    assert not reads_as_fallback("claude", Path("CLAUDE.md"))
