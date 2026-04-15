"""Reporails - Validate and score CLAUDE.md files."""

from __future__ import annotations

from reporails_cli.core.models import (
    Category,
    Level,
    RuleType,
    Severity,
    ValidationResult,
    Violation,
)

__all__ = [
    "Category",
    "Level",
    "RuleType",
    "Severity",
    "ValidationResult",
    "Violation",
    "__version__",
]


def __getattr__(name: str) -> str:
    if name == "__version__":
        from importlib.metadata import version

        return version("reporails-cli")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
