"""Download and install opengrep, rules, and recommended packages."""

from __future__ import annotations

import importlib.resources
import platform
import shutil
import stat
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from reporails_cli.core.bootstrap import (
    get_global_config,
    get_opengrep_bin,
    get_recommended_package_path,
    get_reporails_home,
    get_version_file,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENGREP_VERSION = "1.15.1"

_OG_BASE = f"https://github.com/opengrep/opengrep/releases/download/v{OPENGREP_VERSION}"
OPENGREP_URLS: dict[tuple[str, str], str] = {
    ("linux", "x86_64"): f"{_OG_BASE}/opengrep_manylinux_x86",
    ("linux", "aarch64"): f"{_OG_BASE}/opengrep_manylinux_aarch64",
    ("darwin", "x86_64"): f"{_OG_BASE}/opengrep_osx_x86",
    ("darwin", "arm64"): f"{_OG_BASE}/opengrep_osx_arm64",
    ("windows", "x86_64"): f"{_OG_BASE}/opengrep-core_windows_x86.zip",
}

RECOMMENDED_REPO = "reporails/recommended"
RECOMMENDED_VERSION = "0.1.0"
RECOMMENDED_API_URL = "https://api.github.com/repos/reporails/recommended/releases/latest"

RULES_VERSION = "0.3.1"
RULES_TARBALL_URL = "https://github.com/reporails/rules/releases/download/{version}/reporails-rules-{version}.tar.gz"
RULES_API_URL = "https://api.github.com/repos/reporails/rules/releases/latest"

# ---------------------------------------------------------------------------
# OpenGrep
# ---------------------------------------------------------------------------


def get_platform() -> tuple[str, str]:
    """Detect current OS and architecture."""
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
    bin_path.parent.mkdir(parents=True, exist_ok=True)

    with httpx.Client(follow_redirects=True, timeout=120.0) as client:
        response = client.get(url)
        response.raise_for_status()
        bin_path.write_bytes(response.content)

        if os_name != "windows":
            bin_path.chmod(bin_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    return bin_path


# ---------------------------------------------------------------------------
# Bundled checks helpers
# ---------------------------------------------------------------------------


def get_bundled_checks_path() -> Path | None:
    """Return path to bundled .yml files in the installed package."""
    try:
        files = importlib.resources.files("reporails_cli")
        bundled = files / "bundled_checks"
        with importlib.resources.as_file(bundled) as path:
            if path.exists():
                return path
    except (TypeError, FileNotFoundError):
        pass
    return None


def copy_bundled_yml_files(dest: Path) -> int:
    """Copy bundled .yml files from package to *dest*, preserving structure."""
    bundled_path = get_bundled_checks_path()
    if bundled_path is None:
        return 0

    dest.mkdir(parents=True, exist_ok=True)
    count = 0
    for yml_file in bundled_path.rglob("*.yml"):
        relative = yml_file.relative_to(bundled_path)
        dest_file = dest / relative
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(yml_file, dest_file)
        count += 1
    return count


# ---------------------------------------------------------------------------
# Rules download (initial install)
# ---------------------------------------------------------------------------


def copy_local_framework(source: Path) -> tuple[Path, int]:
    """Copy rules from a local framework directory (dev mode)."""
    rules_path = get_reporails_home() / "rules"

    if rules_path.exists():
        shutil.rmtree(rules_path)
    rules_path.mkdir(parents=True, exist_ok=True)

    count = 0
    for dir_name in ("core", "agents", "schemas", "docs"):
        source_dir = source / dir_name
        if source_dir.exists() and source_dir.is_dir():
            dest_dir = rules_path / dir_name
            shutil.copytree(source_dir, dest_dir)
            count += sum(1 for _ in dest_dir.rglob("*") if _.is_file())

    for filename in ("levels.yml", "manifest.yml"):
        source_file = source / filename
        if source_file.exists():
            shutil.copy2(source_file, rules_path / filename)
            count += 1

    return rules_path, count


def download_rules_tarball(dest: Path) -> int:
    """Download rules from GitHub release tarball into *dest*."""
    import tarfile

    url = RULES_TARBALL_URL.format(version=RULES_VERSION)

    with httpx.Client(follow_redirects=True, timeout=120.0) as client:
        response = client.get(url)
        response.raise_for_status()

        with TemporaryDirectory() as tmpdir:
            tarball_path = Path(tmpdir) / "rules.tar.gz"
            tarball_path.write_bytes(response.content)

            with tarfile.open(tarball_path, "r:gz") as tar:
                tar.extractall(path=dest)

            count = sum(1 for _ in dest.rglob("*") if _.is_file())

    return count


def download_from_github() -> tuple[Path, int]:
    """Setup rules from GitHub at ~/.reporails/rules/."""
    rules_path = get_reporails_home() / "rules"

    if rules_path.exists():
        shutil.rmtree(rules_path)
    rules_path.mkdir(parents=True, exist_ok=True)

    yml_count = copy_bundled_yml_files(rules_path)
    tarball_count = download_rules_tarball(rules_path)
    return rules_path, yml_count + tarball_count


def download_rules() -> tuple[Path, int]:
    """Setup rules at ~/.reporails/rules/ (local override or GitHub)."""
    config = get_global_config()
    if config.framework_path and config.framework_path.exists():
        return copy_local_framework(config.framework_path)
    return download_from_github()


# ---------------------------------------------------------------------------
# Recommended package
# ---------------------------------------------------------------------------


def is_recommended_installed() -> bool:
    """Check if recommended package is installed with content."""
    pkg_path = get_recommended_package_path()
    if not pkg_path.exists():
        return False
    return any(pkg_path.iterdir())


def download_recommended(version: str | None = None) -> Path:
    """Download recommended rules package from GitHub archive."""
    import tarfile

    if version is None:
        from reporails_cli.core.updater import get_latest_recommended_version

        version = get_latest_recommended_version() or RECOMMENDED_VERSION

    archive_url = f"https://github.com/{RECOMMENDED_REPO}/archive/refs/tags/{version}.tar.gz"
    pkg_path = get_recommended_package_path()

    if pkg_path.exists():
        shutil.rmtree(pkg_path)
    pkg_path.mkdir(parents=True, exist_ok=True)

    with httpx.Client(follow_redirects=True, timeout=120.0) as client:
        response = client.get(archive_url)
        response.raise_for_status()

        with TemporaryDirectory() as tmpdir:
            tarball_path = Path(tmpdir) / "recommended.tar.gz"
            tarball_path.write_bytes(response.content)

            with tarfile.open(tarball_path, "r:gz") as tar:
                tar.extractall(path=tmpdir)

            extracted_dirs = [
                d
                for d in Path(tmpdir).iterdir()
                if d.is_dir() and d.name != "__MACOSX" and d.name.startswith("recommended-")
            ]
            if extracted_dirs:
                source_dir = extracted_dirs[0]
                for item in source_dir.iterdir():
                    dest = pkg_path / item.name
                    if item.is_dir():
                        shutil.copytree(item, dest)
                    else:
                        shutil.copy2(item, dest)
            else:
                with tarfile.open(tarball_path, "r:gz") as tar:
                    tar.extractall(path=pkg_path)

    version_file = pkg_path / ".version"
    version_file.write_text(version + "\n", encoding="utf-8")
    return pkg_path


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def sync_rules_to_local(local_checks_dir: Path) -> int:
    """Sync rules from GitHub release tarball to a local checks directory."""
    return download_rules_tarball(local_checks_dir)


def write_version_file(version: str) -> None:
    """Write version to ~/.reporails/version file."""
    version_file = get_version_file()
    version_file.parent.mkdir(parents=True, exist_ok=True)
    version_file.write_text(version.strip() + "\n", encoding="utf-8")
