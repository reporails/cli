"""Download and install rules and recommended packages."""

from __future__ import annotations

import importlib.resources
import logging
import shutil
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory

import httpx

from reporails_cli.core.bootstrap import (
    get_global_config,
    get_recommended_package_path,
    get_reporails_home,
    get_version_file,
)

logger = logging.getLogger(__name__)

RECOMMENDED_REPO = "reporails/recommended"
RECOMMENDED_VERSION = "0.2.0"
RECOMMENDED_API_URL = "https://api.github.com/repos/reporails/recommended/releases/latest"

RULES_VERSION = "0.4.0"
RULES_EXPECTED_DIRS = ("core", "schemas")  # Minimum dirs after extraction


def _safe_extractall(tar: tarfile.TarFile, dest: Path) -> None:
    """Extract tarball with path traversal and symlink protection."""
    for member in tar.getmembers():
        # Block path traversal
        if member.name.startswith("/") or ".." in member.name.split("/"):
            msg = f"Unsafe path in archive: {member.name}"
            raise RuntimeError(msg)
        # Block symlinks pointing outside dest
        if member.issym() or member.islnk():
            target = member.linkname
            if target.startswith("/") or ".." in target.split("/"):
                msg = f"Unsafe symlink in archive: {member.name} -> {target}"
                raise RuntimeError(msg)
    tar.extractall(path=dest)


def _validate_rules_structure(rules_path: Path) -> None:
    """Verify extracted rules contain expected directories."""
    for dir_name in RULES_EXPECTED_DIRS:
        if not (rules_path / dir_name).is_dir():
            msg = f"Missing expected directory after extraction: {dir_name}"
            raise RuntimeError(msg)


RULES_TARBALL_URL = "https://github.com/reporails/rules/releases/download/{version}/reporails-rules-{version}.tar.gz"
RULES_API_URL = "https://api.github.com/repos/reporails/rules/releases/latest"


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
    url = RULES_TARBALL_URL.format(version=RULES_VERSION)

    try:
        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            response = client.get(url)
            response.raise_for_status()
    except httpx.HTTPError as e:
        msg = f"Could not download rules. Check your internet connection. ({e})"
        raise RuntimeError(msg) from e

    with TemporaryDirectory() as tmpdir:
        tarball_path = Path(tmpdir) / "rules.tar.gz"
        tarball_path.write_bytes(response.content)

        with tarfile.open(tarball_path, "r:gz") as tar:
            _safe_extractall(tar, dest)

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
    _validate_rules_structure(rules_path)
    return rules_path, yml_count + tarball_count


def download_rules() -> tuple[Path, int]:
    """Setup rules at ~/.reporails/rules/ (local override or GitHub)."""
    config = get_global_config()
    if config.framework_path and config.framework_path.exists():
        return copy_local_framework(config.framework_path)
    return download_from_github()


def is_recommended_installed() -> bool:
    """Check if recommended package is installed with content."""
    pkg_path = get_recommended_package_path()
    if not pkg_path.exists():
        return False
    return any(pkg_path.iterdir())


def download_recommended(version: str | None = None) -> Path:  # pylint: disable=too-many-locals
    """Download recommended rules package from GitHub archive."""
    if version is None:
        from reporails_cli.core.updater import get_latest_recommended_version

        version = get_latest_recommended_version() or RECOMMENDED_VERSION

    archive_url = f"https://github.com/{RECOMMENDED_REPO}/archive/refs/tags/{version}.tar.gz"
    pkg_path = get_recommended_package_path()

    if pkg_path.exists():
        shutil.rmtree(pkg_path)
    pkg_path.mkdir(parents=True, exist_ok=True)

    try:
        with httpx.Client(follow_redirects=True, timeout=120.0) as client:
            response = client.get(archive_url)
            response.raise_for_status()
    except httpx.HTTPError as e:
        msg = f"Could not download recommended rules. Check your internet connection. ({e})"
        raise RuntimeError(msg) from e

    with TemporaryDirectory() as tmpdir:
        tarball_path = Path(tmpdir) / "recommended.tar.gz"
        tarball_path.write_bytes(response.content)

        with tarfile.open(tarball_path, "r:gz") as tar:
            _safe_extractall(tar, Path(tmpdir))

        extracted_dirs = sorted(
            (
                d
                for d in Path(tmpdir).iterdir()
                if d.is_dir() and d.name != "__MACOSX" and d.name.startswith("recommended-")
            ),
            key=lambda d: d.name,
        )
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
                _safe_extractall(tar, pkg_path)

    version_file = pkg_path / ".version"
    version_file.write_text(version + "\n", encoding="utf-8")
    return pkg_path


def sync_rules_to_local(local_checks_dir: Path) -> int:
    """Sync rules from GitHub release tarball to a local checks directory."""
    return download_rules_tarball(local_checks_dir)


def write_version_file(version: str) -> None:
    """Write version to ~/.reporails/version file."""
    version_file = get_version_file()
    version_file.parent.mkdir(parents=True, exist_ok=True)
    version_file.write_text(version.strip() + "\n", encoding="utf-8")
