"""Core domain logic for reporails."""

from __future__ import annotations

from reporails_cli.core.models import (
    Antipattern,
    Category,
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
    determine_capability_level,
    estimate_time_waste,
)

__all__ = [
    "Antipattern",
    "Category",
    "JudgmentRequest",
    "JudgmentResponse",
    "Level",
    "Rule",
    "RuleType",
    "Severity",
    "ValidationResult",
    "Violation",
    "calculate_score",
    "determine_capability_level",
    "estimate_time_waste",
]
