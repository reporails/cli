"""Integration tests for CLI self-upgrade.

These tests create real virtual environments and exercise the actual
subprocess plumbing (without hitting PyPI — we install from local wheel).

Run via: uv run poe test_integration  (or CI=1 to enable)
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build the wheel once, share across all tests in this module."""
    dist_dir = tmp_path_factory.mktemp("dist")
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(dist_dir)],
        cwd=str(PROJECT_ROOT),
        check=True, capture_output=True,
    )
    wheels = list(dist_dir.glob("*.whl"))
    assert wheels, "No wheel built"
    return wheels[0]


def _create_venv(base: Path, name: str = "venv") -> Path:
    """Create a fresh venv and return its python path."""
    venv_dir = base / name
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True, capture_output=True,
    )
    python = venv_dir / "bin" / "python"
    assert python.exists(), f"venv python not found at {python}"
    return python


class TestSelfUpdateIntegration:
    """End-to-end: build wheel, install in venv, verify detect + command construction."""

    def test_detect_method_in_pip_venv(self, tmp_path: Path, wheel: Path) -> None:
        """Install via pip in a venv, verify detect_install_method returns PIP."""
        python = _create_venv(tmp_path)

        subprocess.run(
            [str(python), "-m", "pip", "install", str(wheel)],
            check=True, capture_output=True,
        )

        result = subprocess.run(
            [
                str(python), "-c",
                "from reporails_cli.core.self_update import detect_install_method; print(detect_install_method().value)",
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        method = result.stdout.strip()
        assert method == "pip", f"Expected 'pip', got '{method}'"

    def test_build_command_in_venv(self, tmp_path: Path, wheel: Path) -> None:
        """Install in venv and verify _build_upgrade_command produces runnable commands."""
        python = _create_venv(tmp_path)

        subprocess.run(
            [str(python), "-m", "pip", "install", str(wheel)],
            check=True, capture_output=True,
        )

        result = subprocess.run(
            [
                str(python), "-c",
                (
                    "from reporails_cli.core.self_update import _build_upgrade_command, InstallMethod; "
                    "cmd = _build_upgrade_command(InstallMethod.PIP, '99.0.0'); "
                    "assert 'reporails-cli==99.0.0' in cmd, cmd; "
                    "print('OK')"
                ),
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "OK" in result.stdout

    def test_upgrade_cli_dev_install_refused(self, tmp_path: Path) -> None:
        """Editable install should refuse upgrade without running subprocess."""
        python = _create_venv(tmp_path)

        # Install editable into the venv's own copy to avoid polluting project root
        work_dir = tmp_path / "project"
        shutil.copytree(PROJECT_ROOT, work_dir, ignore=shutil.ignore_patterns(
            ".venv", "__pycache__", "*.pyc", ".git", ".pytest_cache", "dist",
        ))

        subprocess.run(
            [str(python), "-m", "pip", "install", "-e", str(work_dir)],
            check=True, capture_output=True,
        )

        result = subprocess.run(
            [
                str(python), "-c",
                (
                    "from reporails_cli.core.self_update import upgrade_cli; "
                    "r = upgrade_cli('99.0.0'); "
                    "assert not r.updated; "
                    "assert r.method.value == 'dev'; "
                    "print('OK')"
                ),
            ],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "OK" in result.stdout

    def test_version_command_shows_install_method(self, tmp_path: Path, wheel: Path) -> None:
        """Verify `ails version` output includes install method."""
        python = _create_venv(tmp_path)

        subprocess.run(
            [str(python), "-m", "pip", "install", str(wheel)],
            check=True, capture_output=True,
        )

        venv_bin = tmp_path / "venv" / "bin" / "ails"
        assert venv_bin.exists(), "ails entry point not installed"

        result = subprocess.run(
            [str(venv_bin), "version"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Install:" in result.stdout
