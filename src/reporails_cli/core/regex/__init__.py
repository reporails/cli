"""Python regex engine module."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.models import Rule
from reporails_cli.core.regex.runner import (
    checks_per_file,
    run_checks,
    run_validation,
)


def get_checks_paths(rules: dict[str, Rule]) -> list[Path]:
    """Get list of checks.yml paths for rules that have them and exist."""
    return [r.yml_path for r in rules.values() if r.yml_path is not None and r.yml_path.exists()]


__all__ = [
    "checks_per_file",
    "get_checks_paths",
    "run_checks",
    "run_validation",
]
