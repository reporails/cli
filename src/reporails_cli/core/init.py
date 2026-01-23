"""Init command - downloads opengrep and syncs rules."""

from __future__ import annotations

import importlib.resources
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


def get_bundled_checks_path() -> Path | None:
    """
    Get path to bundled checks (.yml files) in installed package.

    Returns:
        Path to bundled_checks directory, or None if not found
    """
    try:
        # Use importlib.resources to find bundled checks
        files = importlib.resources.files("reporails_cli")
        bundled = files / "bundled_checks"
        # Convert to Path - this works for installed packages
        with importlib.resources.as_file(bundled) as path:
            if path.exists():
                return path
    except (TypeError, FileNotFoundError):
        pass
    return None


def copy_bundled_yml_files(dest: Path) -> int:
    """
    Copy bundled .yml files from package to destination.

    Args:
        dest: Destination directory

    Returns:
        Number of .yml files copied
    """
    bundled_path = get_bundled_checks_path()
    if bundled_path is None:
        return 0

    dest.mkdir(parents=True, exist_ok=True)
    count = 0

    for yml_file in bundled_path.rglob("*.yml"):
        # Preserve directory structure
        relative = yml_file.relative_to(bundled_path)
        dest_file = dest / relative
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(yml_file, dest_file)
        count += 1

    return count


def download_md_files(dest: Path) -> int:
    """
    Download .md files from framework repo to destination.

    Only copies .md files, preserving directory structure.

    Args:
        dest: Destination directory

    Returns:
        Number of .md files copied
    """
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

        dest.mkdir(parents=True, exist_ok=True)
        count = 0

        # Copy only .md files, preserving structure
        for md_file in source_rules.rglob("*.md"):
            relative = md_file.relative_to(source_rules)
            dest_file = dest / relative
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(md_file, dest_file)
            count += 1

    return count


def download_rules() -> tuple[Path, int]:
    """
    Setup rules at ~/.reporails/checks/.

    Merges two sources:
    1. Bundled .yml files (OpenGrep patterns) from package
    2. Downloaded .md files (rule definitions) from framework repo

    Returns:
        Tuple of (checks_path, total_file_count)
    """
    checks_path = get_reporails_home() / "checks"

    # Clear existing checks
    if checks_path.exists():
        shutil.rmtree(checks_path)

    # 1. Copy bundled .yml files
    yml_count = copy_bundled_yml_files(checks_path)

    # 2. Download .md files from framework
    md_count = download_md_files(checks_path)

    return checks_path, yml_count + md_count


def sync_rules_to_local(local_checks_dir: Path) -> int:
    """
    Sync .md files from framework repo to local checks directory.

    For development: downloads only .md files, preserving existing .yml files.

    Args:
        local_checks_dir: Local checks directory (e.g., ./checks/)

    Returns:
        Number of .md files synced
    """
    return download_md_files(local_checks_dir)


def run_init() -> dict[str, str | int | Path]:
    """
    Run global initialization.

    1. Download opengrep binary to ~/.reporails/bin/
    2. Setup rules at ~/.reporails/checks/ (bundled .yml + downloaded .md)

    Returns dict with status info.
    """
    results: dict[str, str | int | Path] = {}

    # 1. Download opengrep
    bin_path = download_opengrep()
    results["opengrep_path"] = bin_path
    results["opengrep_version"] = OPENGREP_VERSION

    # 2. Setup rules (merge bundled yml + framework md)
    checks_path, rule_count = download_rules()
    results["checks_path"] = checks_path
    results["rule_count"] = rule_count

    return results
