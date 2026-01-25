"""MCP output formatter.

Wraps canonical JSON format with MCP-specific transformations if needed.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.models import ScanDelta, ValidationResult
from reporails_cli.formatters import json as json_formatter


def format_result(
    result: ValidationResult,
    delta: ScanDelta | None = None,
) -> dict[str, Any]:
    """
    Format validation result for MCP response.

    Adds instructions for Claude to evaluate JudgmentRequests inline.

    Args:
        result: ValidationResult from engine
        delta: Optional ScanDelta for comparison with previous run

    Returns:
        Dict suitable for MCP tool response
    """
    data = json_formatter.format_result(result, delta)

    # Add evaluation instructions if there are judgment requests
    if data.get("judgment_requests"):
        data["_instructions"] = (
            "SEMANTIC RULE EVALUATION REQUIRED: "
            "For each judgment_request, read the file content and evaluate "
            "against the question and criteria provided. Report violations "
            "where criteria are not met. Include these in your response to the user."
        )

    return data


def format_score(result: ValidationResult) -> dict[str, Any]:
    """
    Format quick score response for MCP.

    Args:
        result: ValidationResult from engine

    Returns:
        Simplified dict with just score info
    """
    return json_formatter.format_score(result)


def format_rule(rule_id: str, rule_data: dict[str, Any]) -> dict[str, Any]:
    """
    Format rule explanation for MCP.

    Args:
        rule_id: Rule identifier
        rule_data: Rule metadata

    Returns:
        Dict with rule details
    """
    return json_formatter.format_rule(rule_id, rule_data)
