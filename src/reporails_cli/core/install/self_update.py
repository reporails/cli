"""Detect how the reporails-cli package was installed (for `ails version`)."""

from __future__ import annotations

from enum import Enum
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

PKG_NAME = "reporails-cli"


class InstallMethod(str, Enum):
    UV = "uv"
    PIP = "pip"
    PIPX = "pipx"
    DEV = "dev"
    UNKNOWN = "unknown"


def detect_install_method() -> InstallMethod:
    """Detect how reporails-cli was installed using package metadata."""
    try:
        dist = distribution(PKG_NAME)
    except PackageNotFoundError:
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
