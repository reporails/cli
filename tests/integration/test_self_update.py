"""Integration tests for install-method detection (used by `ails version`).

These tests create real virtual environments and exercise the actual
install-metadata plumbing (installing from a local wheel, no PyPI).

Run via: uv run poe test_integration  (or CI=1 to enable)
"""

from __future__ import annotations

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
        check=True,
        capture_output=True,
    )
    wheels = list(dist_dir.glob("*.whl"))
    assert wheels, "No wheel built"
    return wheels[0]


def _create_venv(base: Path, name: str = "venv") -> Path:
    """Create a fresh venv and return its python path (cross-platform)."""
    venv_dir = base / name
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
    )
    if sys.platform == "win32":
        python = venv_dir / "Scripts" / "python.exe"
    else:
        python = venv_dir / "bin" / "python"
    assert python.exists(), f"venv python not found at {python}"
    return python


@pytest.mark.slow
class TestSelfUpdateIntegration:
    """End-to-end: build wheel, install in venv, verify install-method detection.

    Marked `slow` (class-level): each test builds a real wheel and/or a fresh venv +
    pip install via subprocess — tens of seconds each (minutes on a cold cache). The
    default `test_integration` gate excludes `-m slow`; `test_integration_all` (CI)
    runs them.
    """

    @pytest.mark.integration
    @pytest.mark.subsys_cli_ux
    def test_detect_method_in_pip_venv(self, tmp_path: Path, wheel: Path) -> None:
        """Install via pip in a venv, verify detect_install_method returns PIP."""
        python = _create_venv(tmp_path)

        subprocess.run(
            [str(python), "-m", "pip", "install", str(wheel)],
            check=True,
            capture_output=True,
        )

        result = subprocess.run(
            [
                str(python),
                "-c",
                "from reporails_cli.core.install.self_update import detect_install_method;"
                " print(detect_install_method().value)",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        method = result.stdout.strip()
        assert method == "pip", f"Expected 'pip', got '{method}'"

    @pytest.mark.integration
    @pytest.mark.subsys_cli_ux
    def test_version_command_shows_install_method(self, tmp_path: Path, wheel: Path) -> None:
        """Verify `ails version` output includes install method."""
        python = _create_venv(tmp_path)

        subprocess.run(
            [str(python), "-m", "pip", "install", str(wheel)],
            check=True,
            capture_output=True,
        )

        if sys.platform == "win32":
            venv_bin = tmp_path / "venv" / "Scripts" / "ails.exe"
        else:
            venv_bin = tmp_path / "venv" / "bin" / "ails"
        assert venv_bin.exists(), "ails entry point not installed"

        result = subprocess.run(
            [str(venv_bin), "version"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, f"stderr: {result.stderr}"
        assert "Install:" in result.stdout
