"""Path helpers for reporails home directory. No lazy downloading."""

from __future__ import annotations

import platform
from pathlib import Path


def get_reporails_home() -> Path:
    """Get ~/.reporails directory."""
    return Path.home() / ".reporails"


def get_opengrep_bin() -> Path:
    """Get path to OpenGrep binary."""
    home = get_reporails_home()
    if platform.system().lower() == "windows":
        return home / "bin" / "opengrep.exe"
    return home / "bin" / "opengrep"


def get_checks_path() -> Path:
    """Get path to user's checks directory (~/.reporails/checks/)."""
    return get_reporails_home() / "checks"


def is_initialized() -> bool:
    """Check if reporails has been initialized (opengrep + rules)."""
    return get_opengrep_bin().exists() and get_checks_path().exists()
