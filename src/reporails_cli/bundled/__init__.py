"""Bundled configuration files for reporails CLI.

This package contains CLI-owned configuration:
- detection.yml: Gate-based capability detection config
- capability-patterns.yml: OpenGrep patterns for capability detection
- .semgrepignore: Default ignore patterns for OpenGrep/Semgrep
"""

from __future__ import annotations

from pathlib import Path


def get_bundled_path() -> Path:
    """Get path to bundled configuration directory."""
    return Path(__file__).parent


def get_detection_path() -> Path:
    """Get path to bundled detection.yml."""
    return get_bundled_path() / "detection.yml"


def get_capability_patterns_path() -> Path:
    """Get path to bundled capability-patterns.yml."""
    return get_bundled_path() / "capability-patterns.yml"


def get_semgrepignore_path() -> Path:
    """Get path to bundled .semgrepignore."""
    return get_bundled_path() / ".semgrepignore"
