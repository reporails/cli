"""The npm launcher starts `uvx` pinned to its own version and marks the run as an npm launch."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.subsys_cli_ux,
    pytest.mark.skipif(
        os.name == "nt",
        reason=(
            "the launcher spawns uvx without a shell; Windows is covered end to end by the post-publish smoke-npx job"
        ),
    ),
]

NPM_DIR = Path(__file__).resolve().parents[2] / "packages" / "npm"
LAUNCHER = NPM_DIR / "bin" / "reporails.mjs"
STUB = (
    "import json, os, sys\n"
    "with open(os.environ['STUB_OUT'], 'w', encoding='utf-8') as fh:\n"
    "    json.dump({'argv': sys.argv[1:], 'launcher': os.environ.get('AILS_LAUNCHER'),\n"
    "               'path': os.environ.get('PATH')}, fh)\n"
    "sys.exit(int(os.environ.get('STUB_EXIT', '0')))\n"
)


def _run_launcher(tmp_path: Path, exit_code: int) -> tuple[int, dict[str, object]]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed; the npm launcher cannot run")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    stub = bin_dir / "uvx"
    stub.write_text(f"#!{sys.executable}\n{STUB}", encoding="utf-8")
    stub.chmod(0o755)
    noop_uv = bin_dir / "uv"
    noop_uv.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    noop_uv.chmod(0o755)
    out = tmp_path / "out.json"
    env = {
        **os.environ,
        "PATH": os.pathsep.join([str(bin_dir), os.environ.get("PATH", "")]),
        "STUB_OUT": str(out),
        "STUB_EXIT": str(exit_code),
    }
    env.pop("AILS_LAUNCHER", None)
    result = subprocess.run([node, str(LAUNCHER), "version"], env=env, capture_output=True, text=True, timeout=60)
    if not out.exists():
        pytest.fail(f"the uvx stub never ran\nstdout: {result.stdout}\nstderr: {result.stderr}")
    return result.returncode, json.loads(out.read_text(encoding="utf-8"))


def test_launcher_pins_its_version_and_marks_npm(tmp_path: Path) -> None:
    version = json.loads((NPM_DIR / "package.json").read_text(encoding="utf-8"))["version"]
    code, seen = _run_launcher(tmp_path, 0)
    assert seen["argv"] == ["--from", f"reporails-cli=={version}", "ails", "version"]
    assert seen["launcher"] == "npm"
    assert code == 0


def test_launcher_exits_with_the_engine_exit_code(tmp_path: Path) -> None:
    code, _ = _run_launcher(tmp_path, 3)
    assert code == 3


def _run_without_uv_on_path(
    tmp_path: Path, stub_dir: Path, **extra_env: str
) -> tuple[subprocess.CompletedProcess[str], dict[str, object]]:
    """Run the launcher with `which` on PATH but no uv/uvx, and a uvx stub in `stub_dir`."""
    node = shutil.which("node")
    which = shutil.which("which")
    if node is None or which is None:
        pytest.skip("node or which is not installed; the npm launcher cannot run")
    which_dir = Path(which).parent
    if (which_dir / "uv").exists() or (which_dir / "uvx").exists():
        pytest.skip(f"uv or uvx sits beside `which` in {which_dir}; cannot build a PATH without uv")
    stub_dir.mkdir(parents=True, exist_ok=True)
    stub = stub_dir / "uvx"
    stub.write_text(f"#!{sys.executable}\n{STUB}", encoding="utf-8")
    stub.chmod(0o755)
    out = tmp_path / "out.json"
    env = {
        **os.environ,
        "PATH": str(which_dir),
        "HOME": str(tmp_path),
        "STUB_OUT": str(out),
        "STUB_EXIT": "4",
        **extra_env,
    }
    for name in ("UV_INSTALL_DIR", "XDG_BIN_HOME", "XDG_DATA_HOME", "AILS_LAUNCHER"):
        if name not in extra_env:
            env.pop(name, None)
    result = subprocess.run([node, str(LAUNCHER), "version"], env=env, capture_output=True, text=True, timeout=60)
    if not out.exists():
        pytest.fail(f"the uvx stub never ran\nstdout: {result.stdout}\nstderr: {result.stderr}")
    return result, json.loads(out.read_text(encoding="utf-8"))


def test_launcher_runs_uvx_from_the_installer_folder_without_reinstalling(tmp_path: Path) -> None:
    version = json.loads((NPM_DIR / "package.json").read_text(encoding="utf-8"))["version"]
    result, seen = _run_without_uv_on_path(tmp_path, tmp_path / ".local" / "bin")
    assert "installing" not in result.stdout
    assert seen["argv"] == ["--from", f"reporails-cli=={version}", "ails", "version"]
    assert seen["launcher"] == "npm"
    assert result.returncode == 4


def test_launcher_prefers_uv_install_dir(tmp_path: Path) -> None:
    custom = tmp_path / "custom"
    result, seen = _run_without_uv_on_path(tmp_path, custom, UV_INSTALL_DIR=str(custom))
    assert "installing" not in result.stdout
    assert seen["launcher"] == "npm"
    assert result.returncode == 4


def test_launcher_puts_the_uvx_folder_first_on_the_child_path(tmp_path: Path) -> None:
    folder = tmp_path / ".local" / "bin"
    _, seen = _run_without_uv_on_path(tmp_path, folder)
    assert str(seen["path"]).split(os.pathsep)[0] == str(folder)
