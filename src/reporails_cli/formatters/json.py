"""Canonical JSON serialization for ValidationResult.

This is the single source of truth for serializing validation results.
All other formatters consume this format internally.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.models import ValidationResult
from reporails_cli.core.scorer import LEVEL_LABELS


def _get_friction_level(total_minutes: int) -> str:
    """Determine friction level from total minutes."""
    if total_minutes >= 20:
        return "high"
    elif total_minutes >= 10:
        return "medium"
    elif total_minutes >= 5:
        return "low"
    return "none"


def format_result(result: ValidationResult) -> dict[str, Any]:
    """Convert ValidationResult to canonical dict format.

    This is the single source of truth for result serialization.

    Args:
        result: ValidationResult from engine

    Returns:
        Canonical dict representation
    """
    total_minutes = result.friction.total_minutes if result.friction else 0

    return {
        "score": result.score,
        "level": result.level.value,
        "capability": LEVEL_LABELS.get(result.level, "Unknown"),
        "feature_summary": result.feature_summary,
        "summary": {
            "rules_checked": result.rules_checked,
            "rules_passed": result.rules_passed,
            "rules_failed": result.rules_failed,
        },
        "violations": [
            {
                "rule_id": v.rule_id,
                "rule_title": v.rule_title,
                "location": v.location,
                "message": v.message,
                "severity": v.severity.value,
                "check_id": v.check_id,
            }
            for v in result.violations
        ],
        "judgment_requests": [
            {
                "rule_id": jr.rule_id,
                "rule_title": jr.rule_title,
                "question": jr.question,
                "location": jr.location,
                "criteria": jr.criteria,
                "examples": jr.examples,
                "choices": jr.choices,
                "pass_value": jr.pass_value,
            }
            for jr in result.judgment_requests
        ],
        "friction": {
            "level": result.friction.level if result.friction else "none",
            "estimated_minutes": total_minutes,
        },
    }


def format_score(result: ValidationResult) -> dict[str, Any]:
    """Convert ValidationResult to minimal score dict.

    Args:
        result: ValidationResult from engine

    Returns:
        Simplified dict with just score info
    """
    total_minutes = result.friction.total_minutes if result.friction else 0

    return {
        "score": result.score,
        "level": result.level.value,
        "capability": LEVEL_LABELS.get(result.level, "Unknown"),
        "feature_summary": result.feature_summary,
        "rules_checked": result.rules_checked,
        "violations_count": len(result.violations),
        "has_critical": any(v.severity.value == "critical" for v in result.violations),
        "friction": _get_friction_level(total_minutes),
    }


def format_rule(rule_id: str, rule_data: dict[str, Any]) -> dict[str, Any]:
    """Format rule explanation as dict.

    Args:
        rule_id: Rule identifier
        rule_data: Rule metadata

    Returns:
        Dict with rule details
    """
    return {
        "id": rule_id,
        "title": rule_data.get("title", ""),
        "category": rule_data.get("category", ""),
        "type": rule_data.get("type", ""),
        "level": rule_data.get("level", ""),
        "description": rule_data.get("description", ""),
        "checks": rule_data.get("checks", rule_data.get("antipatterns", [])),
        "see_also": rule_data.get("see_also", []),
    }
