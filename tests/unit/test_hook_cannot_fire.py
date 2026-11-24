"""Whether a declared hook command can run: the edges of the static probe."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.utils.hook_config import cannot_fire

pytestmark = pytest.mark.unit


def _script(folder: Path, name: str, *, executable: bool) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755 if executable else 0o644)
    return path


def test_a_script_without_the_executable_bit_cannot_fire(tmp_path: Path) -> None:
    _script(tmp_path / ".claude" / "hooks", "guard.sh", executable=False)
    assert cannot_fire('"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard.sh', tmp_path) == "not_executable"


def test_an_executable_script_can_fire(tmp_path: Path) -> None:
    _script(tmp_path / "hooks", "guard.sh", executable=True)
    assert cannot_fire("./hooks/guard.sh", tmp_path) is None


def test_a_script_run_through_an_interpreter_needs_no_executable_bit(tmp_path: Path) -> None:
    _script(tmp_path / "hooks", "guard.sh", executable=False)
    assert cannot_fire("bash ./hooks/guard.sh", tmp_path) is None
    _script(tmp_path / "hooks", "guard.py", executable=False)
    assert cannot_fire("python3 ${CLAUDE_PROJECT_DIR}/hooks/guard.py --flag", tmp_path) is None


@pytest.mark.parametrize("spelling", ["${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR"])
def test_the_project_folder_variable_is_expanded_in_both_spellings(tmp_path: Path, spelling: str) -> None:
    _script(tmp_path / "hooks", "guard.sh", executable=False)
    assert cannot_fire(f"{spelling}/hooks/guard.sh", tmp_path) == "not_executable"


def test_the_plugin_folder_variable_is_expanded_from_the_plugin_root(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    _script(plugin / "hooks", "run.sh", executable=False)
    assert cannot_fire("${CLAUDE_PLUGIN_ROOT}/hooks/run.sh", tmp_path, plugin) == "not_executable"
    assert cannot_fire("${CLAUDE_PLUGIN_ROOT}/hooks/run.sh", tmp_path) is None


def test_a_missing_script_folder_cannot_fire(tmp_path: Path) -> None:
    assert cannot_fire("${CLAUDE_PROJECT_DIR}/gone/guard.sh", tmp_path) == "folder_missing"
    assert cannot_fire("node ./gone/guard.js", tmp_path) == "folder_missing"


@pytest.mark.parametrize("command", ["echo hi", "", "uvx reporails", "FOO=1 echo $HOME", "unterminated 'quote"])
def test_a_command_naming_no_script_path_gives_no_reason(tmp_path: Path, command: str) -> None:
    assert cannot_fire(command, tmp_path) is None


def test_a_script_missing_in_an_existing_folder_cannot_fire(tmp_path: Path) -> None:
    (tmp_path / "hooks").mkdir()
    assert cannot_fire("./hooks/absent.sh", tmp_path) == "script_missing"
    assert cannot_fire("bash ./hooks/absent.sh", tmp_path) == "script_missing"
