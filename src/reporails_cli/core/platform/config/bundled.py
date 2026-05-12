"""Bundled rules resolution for zero-install mode.

Resolves bundled rules from two locations:
1. Installed wheel — rules/ is inside the reporails_cli package directory
2. Development mode — framework/rules/ is at the repository root (two levels above src/reporails_cli/)
"""

from __future__ import annotations

import importlib.resources
from pathlib import Path

# Cache to avoid repeated filesystem probes
_cached_rules: Path | None = None
_cache_checked = False


def _resolve_bundled_rules() -> Path | None:
    """Locate bundled rules/ directory."""
    global _cached_rules, _cache_checked
    if _cache_checked:
        return _cached_rules

    _cache_checked = True

    try:
        pkg = importlib.resources.files("reporails_cli")
        with importlib.resources.as_file(pkg) as pkg_path:
            # Installed wheel: rules/ lives inside the package
            candidate = pkg_path / "rules"
            if candidate.is_dir() and (candidate / "core").is_dir():
                _cached_rules = candidate
                return _cached_rules

            # Development mode: src/reporails_cli/ → repo root is ../../
            repo_root = pkg_path.parent.parent
            candidate = repo_root / "framework" / "rules"
            if candidate.is_dir() and (candidate / "core").is_dir():
                _cached_rules = candidate
                return _cached_rules
    except (TypeError, FileNotFoundError, OSError):
        pass

    return None


def get_bundled_rules_path() -> Path | None:
    """Return path to bundled rules/ directory."""
    return _resolve_bundled_rules()


def get_bundled_package_root() -> Path | None:
    """Return the root where rules/, schemas/, registry/ live side by side.

    In an installed wheel this is the package directory.
    In development mode this is the repository root.
    """
    bundled = _resolve_bundled_rules()
    return bundled.parent if bundled is not None else None
