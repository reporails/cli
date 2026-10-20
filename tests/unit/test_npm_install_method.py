"""npm / npx installs: detection, `ails update` hint and one-shot npx copies."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from reporails_cli.core.install.self_update import InstallMethod, detect_install_method
from reporails_cli.core.platform.config import bootstrap
from reporails_cli.interfaces.cli import commands as commands_module
from reporails_cli.interfaces.cli import install as install_module
from reporails_cli.interfaces.cli.install import _is_temporary_ails

pytestmark = [pytest.mark.unit, pytest.mark.subsys_cli_ux]


def test_npm_launch_selects_npm(monkeypatch):
    monkeypatch.setenv("AILS_LAUNCHER", "npm")
    assert detect_install_method() == InstallMethod.NPM


@pytest.mark.parametrize("launcher", ["", "npx", "pip", "NPM", "yarn"])
def test_other_launcher_values_fall_through(monkeypatch, launcher):
    monkeypatch.setenv("AILS_LAUNCHER", launcher)
    assert detect_install_method() != InstallMethod.NPM


def test_launcher_variable_is_consumed_once(monkeypatch):
    monkeypatch.setenv("AILS_LAUNCHER", "npm")
    assert bootstrap.consume_npm_launch() is True
    assert "AILS_LAUNCHER" not in os.environ
    assert bootstrap.consume_npm_launch() is True


_REAL_WHICH = shutil.which


@pytest.fixture
def two_folder_path(tmp_path, monkeypatch):
    """A PATH of two folders; `uv` resolves to a fake and runs nothing."""
    first, second = tmp_path / "proj" / "node_modules" / ".bin", tmp_path / "real" / "bin"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    monkeypatch.setenv("PATH", os.pathsep.join([str(first), str(second)]))

    def which(cmd, mode=os.F_OK | os.X_OK, path=None):
        return "/fake/uv" if cmd == "uv" and path is None else _REAL_WHICH(cmd, mode=mode, path=path)

    monkeypatch.setattr(install_module.shutil, "which", which)
    monkeypatch.setattr(install_module, "_uv_cache_dir", lambda uv: None)
    return first, second


def _stub(folder: Path) -> Path:
    exe = folder / "ails"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o755)
    return exe


@pytest.mark.skipif(os.name == "nt", reason="stub executables are POSIX scripts")
def test_install_to_path_installs_when_only_a_node_modules_copy(two_folder_path, monkeypatch):
    _stub(two_folder_path[0])
    ran: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        install_module, "run_uv_tool", lambda *a, **k: ran.append(a) or subprocess.CompletedProcess(a, 0, "", "")
    )
    assert install_module._install_to_path() is True
    assert len(ran) == 1


@pytest.mark.skipif(os.name == "nt", reason="stub executables are POSIX scripts")
def test_install_to_path_sees_a_real_copy_behind_a_node_modules_one(two_folder_path, monkeypatch, capsys):
    first, second = two_folder_path
    _stub(first)
    real = _stub(second)
    ran: list[tuple[object, ...]] = []
    monkeypatch.setattr(install_module, "run_uv_tool", lambda *a, **k: ran.append(a))
    assert install_module._install_to_path() is True
    assert str(real) in "".join(capsys.readouterr().out.split())
    assert ran == []


def _no_install(monkeypatch) -> list[tuple[object, ...]]:
    ran: list[tuple[object, ...]] = []
    monkeypatch.setattr(
        install_module, "run_uv_tool", lambda *a, **k: ran.append(a) or subprocess.CompletedProcess(a, 0, "", "")
    )
    return ran


@pytest.mark.skipif(os.name == "nt", reason="stub executables are POSIX scripts")
def test_install_to_path_sees_the_path_copy_despite_one_in_the_current_folder(
    two_folder_path, tmp_path, monkeypatch, capsys
):
    """Windows searches the current folder first; the PATH copy must still be found."""
    real = _stub(two_folder_path[1])
    here = tmp_path / "cwd"
    here.mkdir()
    _stub(here)
    monkeypatch.chdir(here)
    ran = _no_install(monkeypatch)
    assert install_module._install_to_path() is True
    assert str(real) in "".join(capsys.readouterr().out.split())
    assert ran == []


@pytest.mark.skipif(os.name == "nt", reason="stub executables are POSIX scripts")
def test_install_to_path_ignores_an_ails_only_in_the_current_folder(two_folder_path, tmp_path, monkeypatch, capsys):
    here = tmp_path / "cwd"
    here.mkdir()
    _stub(here)
    monkeypatch.chdir(here)
    ran = _no_install(monkeypatch)
    assert install_module._install_to_path() is True
    assert len(ran) == 1
    assert "already on PATH" not in capsys.readouterr().out


@pytest.mark.parametrize(
    ("windows", "pathext", "expected"),
    [
        (True, ".COM;.EXE;.BAT;.CMD", ["ails.COM", "ails.EXE", "ails.BAT", "ails.CMD"]),
        (True, ".EXE;;.CMD", ["ails.EXE", "ails.CMD"]),
        (False, ".EXE", ["ails"]),
    ],
)
def test_ails_names(windows, pathext, expected):
    assert install_module._ails_names(windows, pathext) == expected


@pytest.mark.skipif(os.name == "nt", reason="stub executables are POSIX scripts")
def test_ails_in_folder_needs_an_executable_file(tmp_path):
    assert install_module._ails_in_folder(str(tmp_path)) is None
    plain = tmp_path / "ails"
    plain.write_text("x", encoding="utf-8")
    plain.chmod(0o644)
    assert install_module._ails_in_folder(str(tmp_path)) is None
    plain.chmod(0o755)
    assert install_module._ails_in_folder(str(tmp_path)) == str(plain)


@pytest.mark.skipif(os.name == "nt", reason="stub executables are POSIX scripts")
def test_uv_cache_dir_is_asked_once_per_install(two_folder_path, tmp_path, monkeypatch):
    """Two PATH copies outside node_modules, the first inside uv's cache: one lookup."""
    cache = tmp_path / "cache"
    one, two = cache / "bin", tmp_path / "other" / "bin"
    one.mkdir(parents=True)
    two.mkdir(parents=True)
    _stub(one)
    _stub(two)
    monkeypatch.setenv("PATH", os.pathsep.join([str(one), str(two)]))
    calls: list[str] = []
    monkeypatch.setattr(install_module, "_uv_cache_dir", lambda uv: calls.append(uv) or str(cache))
    _no_install(monkeypatch)
    assert install_module._install_to_path() is True
    assert len(calls) == 1


@pytest.mark.skipif(os.name == "nt", reason="stub executables are POSIX scripts")
@pytest.mark.parametrize("with_node_modules_copy", [True, False])
def test_uv_cache_dir_is_not_asked_without_a_copy_outside_node_modules(
    two_folder_path, monkeypatch, with_node_modules_copy
):
    if with_node_modules_copy:
        _stub(two_folder_path[0])
    calls: list[str] = []
    monkeypatch.setattr(install_module, "_uv_cache_dir", lambda uv: calls.append(uv))
    _no_install(monkeypatch)
    assert install_module._install_to_path() is True
    assert calls == []


def test_update_prints_hint_and_runs_nothing(monkeypatch, capsys):
    monkeypatch.setenv("AILS_LAUNCHER", "npm")
    calls: list[object] = []
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: calls.append(a))
    assert commands_module._update_engine() is True
    out = " ".join(capsys.readouterr().out.split())
    assert "npm install -g @reporails/cli@latest" in out
    assert "unless a copy is installed" in out
    assert calls == []


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/home/u/.npm/_npx/ab/node_modules/.bin/ails", True),
        ("/home/u/proj/node_modules/.bin/ails", True),
        ("/home/u/.cache/pnpm/dlx/ab/node_modules/.bin/ails", True),
        ("/tmp/bunx-1000-@reporails/cli@0.6.5/node_modules/.bin/ails", True),
        ("C:\\Users\\u\\AppData\\Local\\npm-cache\\_npx\\ab\\node_modules\\.bin\\ails.cmd", True),
        ("/usr/local/bin/ails", False),
        ("/home/linuxbrew/.linuxbrew/bin/ails", False),
        ("C:\\Users\\u\\AppData\\Roaming\\npm\\ails.cmd", False),
        ("C:\\Users\\u\\AppData\\Local\\uv\\cache\\archive-v0\\x\\Scripts\\ails.exe", True),
        ("/home/u/.cache/uv/archive-v0/x/bin/ails", True),
        ("C:\\tools\\ails.exe", False),
    ],
)
def test_node_modules_copy_is_temporary(path, expected):
    assert _is_temporary_ails(path, None) is expected


@pytest.mark.skipif(os.name == "nt", reason="stub executables are POSIX scripts")
@pytest.mark.parametrize("pathext", [None, ""])
def test_unset_or_empty_pathext_means_the_default_windows_extensions(tmp_path, monkeypatch, pathext):
    exe = tmp_path / "ails.COM"
    exe.write_text("", encoding="utf-8")
    exe.chmod(0o755)
    if pathext is None:
        monkeypatch.delenv("PATHEXT", raising=False)
    else:
        monkeypatch.setenv("PATHEXT", pathext)
    with monkeypatch.context() as windows:
        windows.setattr(install_module.os, "name", "nt")
        found = install_module._ails_in_folder(str(tmp_path))
    assert found == str(exe)


def test_update_stops_when_uv_cannot_run(monkeypatch):
    monkeypatch.delenv("AILS_LAUNCHER", raising=False)
    monkeypatch.setattr(commands_module, "npm_update_hint", lambda method: None)
    monkeypatch.setattr(commands_module.shutil, "which", lambda cmd: "/fake/uv")
    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(commands_module, "run_uv_tool", lambda *a: calls.append(a))
    assert commands_module._update_engine() is False
    assert len(calls) == 1
