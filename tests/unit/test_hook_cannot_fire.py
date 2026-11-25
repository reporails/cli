"""Whether a declared hook command can run: the edges of the static probe."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from reporails_cli.core.platform.utils.hook_config import cannot_fire, hook_script

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]


def _script(folder: Path, name: str, *, executable: bool) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755 if executable else 0o644)
    return path


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no executable bit")
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


@pytest.mark.parametrize(
    "command",
    ["python3 -m mypkg.hook --config ~/.config/x/hook.json", "python3 -m mypkg.hook ./sub/run.json"],
)
def test_a_python_module_run_names_no_script(tmp_path: Path, command: str) -> None:
    assert hook_script(command, tmp_path) is None
    assert cannot_fire(command, tmp_path) is None


@pytest.mark.parametrize(
    "command",
    [
        "node -r tsnode/register ./hooks/run.js",
        "node --require tsnode/register ./hooks/run.js",
        "node --import tsx/esm ./hooks/run.js",
        "python3 --config ~/.config/x/hook.json ./hooks/run.js",
    ],
)
def test_an_option_value_is_never_the_script(tmp_path: Path, command: str) -> None:
    found = hook_script(command, tmp_path)
    assert found is not None and found[0] == tmp_path / "hooks" / "run.js"


@pytest.mark.parametrize("spelling", ["${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR"])
def test_the_project_folder_variable_is_expanded_in_both_spellings(tmp_path: Path, spelling: str) -> None:
    (tmp_path / "hooks").mkdir()
    assert cannot_fire(f"{spelling}/hooks/guard.sh", tmp_path) == "script_missing"
    assert cannot_fire(f"{spelling}/gone/guard.sh", tmp_path) == "folder_missing"


def test_the_plugin_folder_variable_is_expanded_from_the_plugin_root(tmp_path: Path) -> None:
    plugin = tmp_path / "plugin"
    (plugin / "hooks").mkdir(parents=True)
    assert cannot_fire("${CLAUDE_PLUGIN_ROOT}/hooks/run.sh", tmp_path, plugin) == "script_missing"
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


@pytest.mark.parametrize(
    "command",
    [
        "bash -c 'cd sub && ./run.sh'",
        'sh -c "./sub/run.sh"',
        "bash -lc './sub/run.sh'",
        "python3 -c 'import x; x.run(\"./sub/run.py\")'",
        "node -e \"require('./sub/run.js')\"",
    ],
)
def test_a_command_running_an_inline_script_names_no_script(tmp_path: Path, command: str) -> None:
    assert hook_script(command, tmp_path) is None
    assert cannot_fire(command, tmp_path) is None


def test_a_script_after_interpreter_options_is_still_the_script(tmp_path: Path) -> None:
    found = hook_script("bash -x ./sub/run.sh", tmp_path)
    assert found is not None and found[0] == tmp_path / "sub" / "run.sh"


@pytest.mark.parametrize("spelling", ["${CLAUDE_PLUGIN_ROOT}", "$CLAUDE_PLUGIN_ROOT"])
def test_the_plugin_folder_variable_comes_from_the_declaring_plugin_in_both_spellings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, spelling: str
) -> None:
    plugin = tmp_path / "plugin"
    _script(plugin / "hooks", "x.sh", executable=True)
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path / "another-plugin"))
    assert cannot_fire(f'"{spelling}"/hooks/x.sh', tmp_path, plugin) is None
    assert hook_script(f"{spelling}/hooks/x.sh", tmp_path, plugin) == (plugin / "hooks" / "x.sh", False)


def test_a_plugin_variable_with_no_known_value_gives_no_reason_whatever_the_environment_holds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / "elsewhere"))
    assert cannot_fire('"${CLAUDE_PLUGIN_ROOT}"/hooks/x.sh', tmp_path, None) is None
    assert cannot_fire('"${CLAUDE_PLUGIN_DATA}"/run.sh', tmp_path, tmp_path / "plugin") is None
