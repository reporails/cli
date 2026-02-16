"""Bundled configuration files for reporails CLI.

This package contains CLI-owned configuration:
- capability-patterns.yml: Regex patterns for capability detection
"""

from __future__ import annotations

from pathlib import Path


def get_bundled_path() -> Path:
    """Get path to bundled configuration directory."""
    return Path(__file__).parent


def get_capability_patterns_path() -> Path:
    """Get path to bundled capability-patterns.yml."""
    return get_bundled_path() / "capability-patterns.yml"
