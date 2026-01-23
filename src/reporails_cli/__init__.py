"""Reporails - Lint and score CLAUDE.md files."""

from __future__ import annotations

__version__ = "0.0.1"

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
