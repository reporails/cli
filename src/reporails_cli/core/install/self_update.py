"""Detect how the reporails-cli package was installed (for `ails version`)."""

from __future__ import annotations

import json
from enum import Enum
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from reporails_cli.core.platform.config.bootstrap import consume_npm_launch

PKG_NAME = "reporails-cli"


class InstallMethod(str, Enum):
    """How the package was installed."""

    UV = "uv"
    PIP = "pip"
    PIPX = "pipx"
    NPM = "npm"
    DEV = "dev"
    UNKNOWN = "unknown"


def detect_install_method() -> InstallMethod:
    """Detect how reporails-cli was installed: the npm launcher when it names one, else package metadata."""
    return InstallMethod.NPM if consume_npm_launch() else _method_from_metadata()


def npm_update_hint(method: InstallMethod) -> str | None:
    """The sentence `ails update` prints for an npm install; None for other methods."""
    if method == InstallMethod.NPM:
        return (
            "This ails runs from the npm package. A pinned `npx @reporails/cli@X.Y.Z` runs that version; a bare "
            "`npx @reporails/cli` runs the latest release unless a copy is installed globally or in the project. "
            "Update a global install with `npm install -g @reporails/cli@latest`; for a project dependency, "
            "raise its version in package.json."
        )
    return None


def _method_from_metadata() -> InstallMethod:
    """Detect how reporails-cli was installed using package metadata."""
    try:
        dist = distribution(PKG_NAME)
    except PackageNotFoundError:
        return InstallMethod.UNKNOWN

    # Check for editable/dev install via direct_url.json
    direct_url = dist.read_text("direct_url.json")
    if direct_url is not None:
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
        location = str(Path(str(dist.locate_file(""))).resolve())
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
