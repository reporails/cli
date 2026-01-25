"""Core domain logic for reporails."""

from __future__ import annotations

from reporails_cli.core.models import (
    Category,
    Check,
    JudgmentRequest,
    JudgmentResponse,
    Level,
    Rule,
    RuleType,
    Severity,
    ValidationResult,
    Violation,
)
from reporails_cli.core.scorer import (
    calculate_score,
    estimate_friction,
)

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
    "calculate_score",
    "estimate_friction",
]
