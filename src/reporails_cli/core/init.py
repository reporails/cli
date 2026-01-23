"""Init command - downloads opengrep and rules."""

from __future__ import annotations

import platform
import shutil
import stat
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from reporails_cli.core.bootstrap import get_opengrep_bin, get_reporails_home

# Hardcoded version - no env var handling
OPENGREP_VERSION = "1.15.1"

OPENGREP_URLS: dict[tuple[str, str], str] = {
    ("linux", "x86_64"): (
        "https://github.com/opengrep/opengrep/releases/download/"
        f"v{OPENGREP_VERSION}/opengrep_manylinux_x86"
    ),
    ("linux", "aarch64"): (
        "https://github.com/opengrep/opengrep/releases/download/"
        f"v{OPENGREP_VERSION}/opengrep_manylinux_aarch64"
    ),
    ("darwin", "x86_64"): (
        "https://github.com/opengrep/opengrep/releases/download/"
        f"v{OPENGREP_VERSION}/opengrep_osx_x86"
    ),
    ("darwin", "arm64"): (
        "https://github.com/opengrep/opengrep/releases/download/"
        f"v{OPENGREP_VERSION}/opengrep_osx_arm64"
    ),
    ("windows", "x86_64"): (
        "https://github.com/opengrep/opengrep/releases/download/"
        f"v{OPENGREP_VERSION}/opengrep-core_windows_x86.zip"
    ),
}

FRAMEWORK_REPO = "https://github.com/reporails/framework.git"


def get_platform() -> tuple[str, str]:
    """Detect current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_name = "darwin"
    elif system == "linux":
        os_name = "linux"
    elif system == "windows":
        os_name = "windows"
    else:
        msg = f"Unsupported operating system: {system}"
        raise RuntimeError(msg)

    if machine in ("x86_64", "amd64"):
        arch = "x86_64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64" if os_name == "darwin" else "aarch64"
    else:
        msg = f"Unsupported architecture: {machine}"
        raise RuntimeError(msg)

    return os_name, arch


def download_opengrep() -> Path:
    """Download opengrep binary to ~/.reporails/bin/opengrep."""
    os_name, arch = get_platform()
    key = (os_name, arch)

    if key not in OPENGREP_URLS:
        msg = f"Unsupported platform: {os_name}/{arch}"
        raise RuntimeError(msg)

    url = OPENGREP_URLS[key]
    bin_path = get_opengrep_bin()

    # Create bin directory
    bin_path.parent.mkdir(parents=True, exist_ok=True)

    # Download
    with httpx.Client(follow_redirects=True, timeout=120.0) as client:
        response = client.get(url)
        response.raise_for_status()

        # Write binary directly (raw binary, not archive for non-windows)
        bin_path.write_bytes(response.content)

        # Make executable on Unix
        if os_name != "windows":
            bin_path.chmod(bin_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return bin_path


def download_rules() -> tuple[Path, int]:
    """
    Download rules from framework repo to ~/.reporails/checks/.

    Clones the framework repo and copies rules/ to ~/.reporails/checks/.

    Returns:
        Tuple of (checks_path, rule_count)
    """
    checks_path = get_reporails_home() / "checks"

    with TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        framework_path = tmp_path / "framework"

        # Clone framework repo
        result = subprocess.run(
            ["git", "clone", "--depth=1", FRAMEWORK_REPO, str(framework_path)],
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            msg = f"Failed to clone framework repo: {result.stderr}"
            raise RuntimeError(msg)

        # Source rules directory
        source_rules = framework_path / "rules"
        if not source_rules.exists():
            msg = "No rules/ directory found in framework repo"
            raise RuntimeError(msg)

        # Clear existing checks
        if checks_path.exists():
            shutil.rmtree(checks_path)

        # Copy rules to checks
        shutil.copytree(source_rules, checks_path)

        # Count rule files
        rule_count = len(list(checks_path.rglob("*.md")))

    return checks_path, rule_count


def run_init() -> dict[str, str | int | Path]:
    """
    Run global initialization.

    1. Download opengrep binary to ~/.reporails/bin/
    2. Download rules from framework to ~/.reporails/checks/

    Returns dict with status info.
    """
    results: dict[str, str | int | Path] = {}

    # 1. Download opengrep
    bin_path = download_opengrep()
    results["opengrep_path"] = bin_path
    results["opengrep_version"] = OPENGREP_VERSION

    # 2. Download rules
    checks_path, rule_count = download_rules()
    results["checks_path"] = checks_path
    results["rule_count"] = rule_count

    return results
