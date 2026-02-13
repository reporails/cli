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

    # Add structured workflow for semantic evaluation
    if data.get("judgment_requests"):
        data["_semantic_workflow"] = {
            "action": "evaluate_and_judge",
            "steps": [
                "For each judgment_request: read the content field and evaluate against question + criteria",
                "Collect verdicts",
                "Call the judge tool with verdicts to cache results",
                "Report only failures to user; state pass count at end",
            ],
            "verdict_format": "RULE_ID:FILENAME:pass|fail:reason",
            "example_call": {
                "tool": "judge",
                "arguments": {
                    "path": ".",
                    "verdicts": ["C6:CLAUDE.md:pass:Content is specific"],
                },
            },
        }

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
