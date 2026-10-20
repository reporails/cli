"""Path helpers for the reporails home directory."""

from __future__ import annotations

import os
from pathlib import Path

from reporails_cli.core.platform.contract.errors import ConfigUnreadableError


def env_flag(var_name: str) -> bool:
    """True when the env var is set to anything but blank, 0, false, no or off (case and spaces ignored)."""
    return os.environ.get(var_name, "").strip().lower() not in ("", "0", "false", "no", "off")


def npm_launcher() -> str:
    """The launcher named by AILS_LAUNCHER, stripped; blank when unset."""
    return os.environ.get("AILS_LAUNCHER", "").strip()


def parse_idle_timeout_env(var_name: str, default_s: int) -> int | None:
    """Parse an idle-timeout env var (seconds): unset/blank/non-numeric → default,
    a positive int → that value, 0 or negative → None (idle shutdown disabled)."""
    raw = os.environ.get(var_name, "").strip()
    if not raw:
        return default_s
    try:
        value = int(raw)
    except ValueError:
        return default_s
    return value if value > 0 else None


# Constants
REPORAILS_HOME = Path.home() / ".reporails"


def get_reporails_home() -> Path:
    """Get ~/.reporails directory."""
    return REPORAILS_HOME


def get_daemon_dir() -> Path:
    """Get ~/.reporails/daemon/ — global daemon socket and PID."""
    return REPORAILS_HOME / "daemon"


def get_xray_log_dir() -> Path:
    """Get ~/.reporails/xray/ — per-session event logs of the context x-ray."""
    return REPORAILS_HOME / "xray"


def get_global_cache_dir() -> Path:
    """Get ~/.reporails/cache/ — shared map-cache location."""
    return REPORAILS_HOME / "cache"


def get_global_packages_path() -> Path:
    """Get path to global packages directory (~/.reporails/packages/)."""
    return get_reporails_home() / "packages"


def get_global_config_path() -> Path:
    """Get path to global config file (~/.reporails/config.yml)."""
    return get_reporails_home() / "config.yml"


def get_project_config_path(project_root: Path) -> Path:
    """Get path to the project config file (<root>/.ails/config.yml)."""
    return project_root / ".ails" / "config.yml"


def get_local_config_path(project_root: Path) -> Path:
    """Get path to the project's personal override file (<root>/.ails/config.local.yml)."""
    return project_root / ".ails" / "config.local.yml"


def get_package_paths(project_root: Path, packages: list[str]) -> list[Path]:
    """Resolve package names to directories.

    Checks project-local (.ails/packages/<name>) first, then falls back
    to global (~/.reporails/packages/<name>). Project-local overrides global
    for the same package name. A package found in neither raises ConfigUnreadableError.

    Args:
        project_root: Root directory of the project
        packages: List of package names

    Returns:
        List of existing package directory paths

    Raises:
        ConfigUnreadableError: a listed package is in neither folder
    """
    global_base = get_global_packages_path()
    paths: list[Path] = []
    for name in packages:
        # Project-local takes priority
        local_dir = project_root / ".ails" / "packages" / name
        if local_dir.is_dir():
            paths.append(local_dir)
            continue
        # Fall back to global
        global_dir = global_base / name
        if global_dir.is_dir():
            paths.append(global_dir)
            continue
        raise ConfigUnreadableError(f"packages: rule package '{name}' not found in {local_dir} or {global_dir}")
    return paths
