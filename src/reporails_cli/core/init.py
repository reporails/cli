"""Init command - downloads opengrep and syncs rules."""

from __future__ import annotations

import importlib.resources
import platform
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from reporails_cli.core.bootstrap import (
    get_global_config,
    get_installed_version,
    get_opengrep_bin,
    get_reporails_home,
    get_version_file,
)

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

RULES_VERSION = "v0.1.1"
RULES_TARBALL_URL = "https://github.com/reporails/rules/releases/download/{version}/reporails-rules-{version}.tar.gz"
RULES_API_URL = "https://api.github.com/repos/reporails/rules/releases/latest"


@dataclass
class UpdateResult:
    """Result of an update operation."""

    previous_version: str | None
    new_version: str
    updated: bool
    rule_count: int
    message: str


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


def copy_local_framework(source: Path) -> tuple[Path, int]:
    """
    Copy rules from local framework directory to ~/.reporails/rules/.

    Used in dev mode when framework_path is configured in ~/.reporails/config.yml.

    Local framework structure:
        source/
        ├── core/           # Core rules
        ├── agents/         # Agent-specific rules
        │   └── claude/
        │       └── rules/  # Claude-specific rules
        ├── schemas/
        └── docs/

    Args:
        source: Local framework directory path

    Returns:
        Tuple of (rules_path, total_file_count)
    """
    rules_path = get_reporails_home() / "rules"

    # Clear existing rules
    if rules_path.exists():
        shutil.rmtree(rules_path)

    rules_path.mkdir(parents=True, exist_ok=True)
    count = 0

    # Directories to copy from framework root
    dirs_to_copy = ["core", "agents", "schemas", "docs"]

    for dir_name in dirs_to_copy:
        source_dir = source / dir_name
        if source_dir.exists() and source_dir.is_dir():
            dest_dir = rules_path / dir_name
            shutil.copytree(source_dir, dest_dir)
            # Count files copied
            count += sum(1 for _ in dest_dir.rglob("*") if _.is_file())

    return rules_path, count


def download_rules_tarball(dest: Path) -> int:
    """
    Download rules from GitHub release tarball.

    Args:
        dest: Destination directory (~/.reporails/rules/)

    Returns:
        Number of files extracted
    """
    import tarfile

    url = RULES_TARBALL_URL.format(version=RULES_VERSION)

    with httpx.Client(follow_redirects=True, timeout=120.0) as client:
        response = client.get(url)
        response.raise_for_status()

        with TemporaryDirectory() as tmpdir:
            tarball_path = Path(tmpdir) / "rules.tar.gz"
            tarball_path.write_bytes(response.content)

            # Extract
            with tarfile.open(tarball_path, "r:gz") as tar:
                tar.extractall(path=dest)

            # Count files
            count = sum(1 for _ in dest.rglob("*") if _.is_file())

    return count


def download_from_github() -> tuple[Path, int]:
    """
    Setup rules from GitHub at ~/.reporails/rules/.

    Merges two sources:
    1. Bundled .yml files (OpenGrep patterns) from package
    2. Downloaded files from GitHub release tarball

    Returns:
        Tuple of (rules_path, total_file_count)
    """
    rules_path = get_reporails_home() / "rules"

    # Clear existing rules
    if rules_path.exists():
        shutil.rmtree(rules_path)

    rules_path.mkdir(parents=True, exist_ok=True)

    # 1. Copy bundled .yml files
    yml_count = copy_bundled_yml_files(rules_path)

    # 2. Download from GitHub release tarball
    tarball_count = download_rules_tarball(rules_path)

    return rules_path, yml_count + tarball_count


def download_rules() -> tuple[Path, int]:
    """
    Setup rules at ~/.reporails/rules/.

    Checks for local framework_path in config first (dev mode),
    otherwise downloads from GitHub.

    Returns:
        Tuple of (rules_path, total_file_count)
    """
    # Check for local framework override (dev mode)
    config = get_global_config()
    if config.framework_path and config.framework_path.exists():
        return copy_local_framework(config.framework_path)

    # Otherwise download from GitHub
    return download_from_github()


def sync_rules_to_local(local_checks_dir: Path) -> int:
    """
    Sync rules from GitHub release tarball to local checks directory.

    For development: downloads rules from release tarball.

    Args:
        local_checks_dir: Local checks directory (e.g., ./checks/)

    Returns:
        Number of files synced
    """
    return download_rules_tarball(local_checks_dir)


def write_version_file(version: str) -> None:
    """Write version to ~/.reporails/version file."""
    version_file = get_version_file()
    version_file.parent.mkdir(parents=True, exist_ok=True)
    version_file.write_text(version.strip() + "\n", encoding="utf-8")


def get_latest_version() -> str | None:
    """
    Fetch the latest release version from GitHub API.

    Returns:
        Version string (e.g., "v0.1.1") or None if fetch fails
    """
    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.get(RULES_API_URL)
            response.raise_for_status()
            data: dict[str, object] = response.json()
            tag_name = data.get("tag_name")
            return str(tag_name) if tag_name else None
    except (httpx.HTTPError, KeyError):
        return None


def download_rules_version(version: str) -> tuple[Path, int]:
    """
    Download rules for a specific version.

    Args:
        version: Version string (e.g., "v0.1.1")

    Returns:
        Tuple of (rules_path, total_file_count)
    """
    import tarfile

    rules_path = get_reporails_home() / "rules"

    # Clear existing rules
    if rules_path.exists():
        shutil.rmtree(rules_path)

    rules_path.mkdir(parents=True, exist_ok=True)

    # 1. Copy bundled .yml files
    yml_count = copy_bundled_yml_files(rules_path)

    # 2. Download from GitHub release tarball
    url = RULES_TARBALL_URL.format(version=version)

    with httpx.Client(follow_redirects=True, timeout=120.0) as client:
        response = client.get(url)
        response.raise_for_status()

        with TemporaryDirectory() as tmpdir:
            tarball_path = Path(tmpdir) / "rules.tar.gz"
            tarball_path.write_bytes(response.content)

            # Extract
            with tarfile.open(tarball_path, "r:gz") as tar:
                tar.extractall(path=rules_path)

            # Count files
            tarball_count = sum(1 for _ in rules_path.rglob("*") if _.is_file())

    # Write version file
    write_version_file(version)

    return rules_path, yml_count + tarball_count


def update_rules(version: str | None = None, force: bool = False) -> UpdateResult:
    """
    Update rules to specified version or latest.

    Args:
        version: Target version (e.g., "v0.1.1"). If None, uses latest.
        force: Force update even if already at target version.

    Returns:
        UpdateResult with details about the update
    """
    # Check for local framework override (dev mode)
    config = get_global_config()
    if config.framework_path and config.framework_path.exists():
        return UpdateResult(
            previous_version=get_installed_version(),
            new_version="local",
            updated=False,
            rule_count=0,
            message="Using local framework path (dev mode). Disable framework_path in config to update.",
        )

    # Determine target version
    if version:
        target_version = version if version.startswith("v") else f"v{version}"
    else:
        latest = get_latest_version()
        if not latest:
            return UpdateResult(
                previous_version=get_installed_version(),
                new_version="unknown",
                updated=False,
                rule_count=0,
                message="Failed to fetch latest version from GitHub.",
            )
        target_version = latest

    # Check current version
    current_version = get_installed_version()

    # Skip if already at target version (unless forced)
    if current_version == target_version and not force:
        return UpdateResult(
            previous_version=current_version,
            new_version=target_version,
            updated=False,
            rule_count=0,
            message=f"Already at version {target_version}.",
        )

    # Download and install
    try:
        _rules_path, rule_count = download_rules_version(target_version)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return UpdateResult(
                previous_version=current_version,
                new_version=target_version,
                updated=False,
                rule_count=0,
                message=f"Version {target_version} not found.",
            )
        raise

    return UpdateResult(
        previous_version=current_version,
        new_version=target_version,
        updated=True,
        rule_count=rule_count,
        message=f"Updated from {current_version or 'none'} to {target_version}.",
    )


def run_init() -> dict[str, str | int | Path]:
    """
    Run global initialization.

    1. Download opengrep binary to ~/.reporails/bin/
    2. Setup rules at ~/.reporails/rules/ (from local framework or GitHub)

    Returns dict with status info.
    """
    results: dict[str, str | int | Path] = {}

    # 1. Download opengrep
    bin_path = download_opengrep()
    results["opengrep_path"] = bin_path
    results["opengrep_version"] = OPENGREP_VERSION

    # 2. Setup rules (check local framework_path first, then GitHub)
    rules_path, rule_count = download_rules()
    results["rules_path"] = rules_path
    results["rule_count"] = rule_count

    # 3. Write version file
    write_version_file(RULES_VERSION)
    results["rules_version"] = RULES_VERSION

    return results
