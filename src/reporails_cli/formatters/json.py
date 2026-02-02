"""Canonical JSON serialization for ValidationResult.

This is the single source of truth for serializing validation results.
All other formatters consume this format internally.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.models import (
    CategoryStats,
    PendingSemantic,
    ScanDelta,
    SkippedExperimental,
    ValidationResult,
)
from reporails_cli.core.scorer import LEVEL_LABELS


def _format_pending_semantic(pending: PendingSemantic | None) -> dict[str, Any] | None:
    """Format pending semantic rules for JSON output."""
    if pending is None:
        return None
    return {
        "rule_count": pending.rule_count,
        "file_count": pending.file_count,
        "rules": list(pending.rules),
    }


def _format_category_summary(summary: tuple[CategoryStats, ...]) -> list[dict[str, Any]]:
    """Format category summary for JSON output."""
    return [
        {
            "code": cs.code,
            "name": cs.name,
            "total": cs.total,
            "passed": cs.passed,
            "failed": cs.failed,
            "worst_severity": cs.worst_severity,
        }
        for cs in summary
    ]


def _format_skipped_experimental(skipped: SkippedExperimental | None) -> dict[str, Any] | None:
    """Format skipped experimental rules for JSON output."""
    if skipped is None:
        return None
    return {
        "rule_count": skipped.rule_count,
        "rules": list(skipped.rules),
    }


def format_result(
    result: ValidationResult,
    delta: ScanDelta | None = None,
) -> dict[str, Any]:
    """Convert ValidationResult to canonical dict format.

    This is the single source of truth for result serialization.

    Args:
        result: ValidationResult from engine
        delta: Optional ScanDelta for comparison with previous run

    Returns:
        Canonical dict representation
    """
    data: dict[str, Any] = {
        "score": result.score,
        "level": result.level.value,
        "capability": LEVEL_LABELS.get(result.level, "Unknown"),
        "has_orphan_features": result.has_orphan_features,
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
        "friction": result.friction.level if result.friction else "none",
        "category_summary": _format_category_summary(result.category_summary),
        # Evaluation completeness
        "evaluation": "partial" if result.is_partial else "complete",
        "is_partial": result.is_partial,
        "pending_semantic": _format_pending_semantic(result.pending_semantic),
        "skipped_experimental": _format_skipped_experimental(result.skipped_experimental),
    }

    # Add delta fields (null if no previous run or unchanged)
    if delta is not None:
        data["score_delta"] = delta.score_delta
        data["level_previous"] = delta.level_previous
        data["level_improved"] = delta.level_improved
        data["violations_delta"] = delta.violations_delta
    else:
        data["score_delta"] = None
        data["level_previous"] = None
        data["level_improved"] = None
        data["violations_delta"] = None

    return data


def format_score(result: ValidationResult) -> dict[str, Any]:
    """Convert ValidationResult to minimal score dict.

    Args:
        result: ValidationResult from engine

    Returns:
        Simplified dict with just score info
    """
    return {
        "score": result.score,
        "level": result.level.value,
        "capability": LEVEL_LABELS.get(result.level, "Unknown"),
        "feature_summary": result.feature_summary,
        "rules_checked": result.rules_checked,
        "violations_count": len(result.violations),
        "has_critical": any(v.severity.value == "critical" for v in result.violations),
        "friction": result.friction.level if result.friction else "none",
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
