"""Reporails - Validate and score CLAUDE.md files."""

from __future__ import annotations

from importlib.metadata import version

__version__ = version("reporails-cli")

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
