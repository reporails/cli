"""Core domain logic for reporails."""

from __future__ import annotations

from reporails_cli.core.platform.dto.models import (
    Category,
    Check,
    JudgmentRequest,
    JudgmentResponse,
    Level,
    Rule,
    RuleType,
    Severity,
    Violation,
)
from reporails_cli.core.platform.dto.results import ValidationResult

__all__ = [
    "Category",
    "Check",
    "JudgmentRequest",
    "JudgmentResponse",
    "Level",
    "Rule",
    "RuleType",
    "Severity",
    "ValidationResult",
    "Violation",
]
