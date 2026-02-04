"""CLI self-upgrade: detect install method and upgrade the reporails-cli package."""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from importlib.metadata import distribution
from pathlib import Path

PKG_NAME = "reporails-cli"


class InstallMethod(str, Enum):
    UV = "uv"
    PIP = "pip"
    PIPX = "pipx"
    DEV = "dev"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class CliUpdateResult:
    updated: bool
    previous_version: str
    new_version: str | None
    method: InstallMethod
    message: str


def detect_install_method() -> InstallMethod:
    """Detect how reporails-cli was installed using package metadata."""
    try:
        dist = distribution(PKG_NAME)
    except Exception:
        return InstallMethod.UNKNOWN

    # Check for editable/dev install via direct_url.json
    direct_url = dist.read_text("direct_url.json")
    if direct_url is not None:
        import json

        try:
            data = json.loads(direct_url)
            if data.get("dir_info", {}).get("editable", False):
                return InstallMethod.DEV
        except (json.JSONDecodeError, KeyError):
            pass

    # Check for pipx by looking at install location
    dist_files = dist.files
    if dist_files:
        first_file = str(dist_files[0])
        location = str(Path(dist._path).resolve()) if hasattr(dist, "_path") else ""
        if "pipx" in location or "pipx" in first_file:
            return InstallMethod.PIPX

    # Check INSTALLER metadata
    installer = dist.read_text("INSTALLER")
    if installer:
        installer = installer.strip().lower()
        if installer == "uv":
            return InstallMethod.UV
        if installer in ("pip", "pip3"):
            return InstallMethod.PIP

    return InstallMethod.PIP  # safe default


def _build_upgrade_command(method: InstallMethod, target: str | None) -> list[str]:
    """Build the subprocess command for a given install method and target version."""
    version_spec = f"{PKG_NAME}=={target}" if target else PKG_NAME

    if method == InstallMethod.UV:
        return ["uv", "pip", "install", "--refresh-package", PKG_NAME, "--upgrade", version_spec]
    if method == InstallMethod.PIPX:
        if target:
            return ["pipx", "install", "--force", f"{PKG_NAME}=={target}"]
        return ["pipx", "upgrade", PKG_NAME]
    # PIP / fallback
    return [sys.executable, "-m", "pip", "install", "--no-cache-dir", "--upgrade", version_spec]


def _verify_installed_version() -> str | None:
    """Get the currently installed version via a fresh subprocess (avoids stale imports)."""
    try:
        result = subprocess.run(
            [sys.executable, "-c", f"from importlib.metadata import version; print(version('{PKG_NAME}'))"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return None


def upgrade_cli(target_version: str | None = None) -> CliUpdateResult:
    """Upgrade the CLI package to target version (or latest).

    Detects the install method from package metadata and runs the
    appropriate upgrade command. Returns a result with success/failure info.
    """
    from reporails_cli import __version__ as current_version
    from reporails_cli.core.update_check import _fetch_latest_cli_version, _is_newer

    method = detect_install_method()

    if method == InstallMethod.DEV:
        return CliUpdateResult(
            updated=False, previous_version=current_version, new_version=None,
            method=method, message="Development install detected. Run `uv sync` to update.",
        )

    if method == InstallMethod.UNKNOWN:
        return CliUpdateResult(
            updated=False, previous_version=current_version, new_version=None,
            method=method,
            message=f"Could not detect install method. Upgrade manually: pip install --upgrade {PKG_NAME}",
        )

    # Resolve target
    resolved_target = target_version
    if not resolved_target:
        resolved_target = _fetch_latest_cli_version()
        if not resolved_target:
            return CliUpdateResult(
                updated=False, previous_version=current_version, new_version=None,
                method=method, message="Could not fetch latest version from PyPI.",
            )

    if not _is_newer(current_version, resolved_target):
        return CliUpdateResult(
            updated=False, previous_version=current_version, new_version=resolved_target,
            method=method, message=f"Already at {current_version} (latest: {resolved_target}).",
        )

    cmd = _build_upgrade_command(method, resolved_target)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            return CliUpdateResult(
                updated=False, previous_version=current_version, new_version=resolved_target,
                method=method, message=f"Upgrade failed: {result.stderr.strip()[:200]}",
            )
    except subprocess.TimeoutExpired:
        return CliUpdateResult(
            updated=False, previous_version=current_version, new_version=resolved_target,
            method=method, message="Upgrade timed out.",
        )
    except Exception as e:
        return CliUpdateResult(
            updated=False, previous_version=current_version, new_version=resolved_target,
            method=method, message=f"Upgrade failed: {e}",
        )

    # Verify
    new_ver = _verify_installed_version() or resolved_target
    return CliUpdateResult(
        updated=True, previous_version=current_version, new_version=new_ver,
        method=method,
        message=f"Upgraded {current_version} -> {new_ver}. Restart your shell to use the new version.",
    )
