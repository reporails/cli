"""MCP output formatter.

Wraps canonical JSON format with MCP-specific transformations if needed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from reporails_cli.core.models import ScanDelta, ValidationResult
from reporails_cli.formatters import json as json_formatter

if TYPE_CHECKING:
    from reporails_cli.core.fixers import FixResult
    from reporails_cli.core.models import JudgmentRequest


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
            "verdict_format": "RULE_ID:FILENAME:pass|fail:brief_reason (under 40 chars)",
            "example_call": {
                "tool": "judge",
                "arguments": {
                    "path": ".",
                    "verdicts": ["CORE:C:0017:CLAUDE.md:pass:Repo-specific paths"],
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


def format_heal_result(
    fixes: list[FixResult],
    judgment_requests: list[JudgmentRequest],
) -> dict[str, Any]:
    """
    Format heal result for MCP response.

    Returns auto-fixes applied and remaining semantic judgment requests.

    Args:
        fixes: List of FixResult from auto-fix phase
        judgment_requests: Remaining semantic JudgmentRequests

    Returns:
        Dict with auto_fixed and judgment_requests
    """
    data: dict[str, Any] = {
        "auto_fixed": [
            {
                "rule_id": f.rule_id,
                "file_path": f.file_path,
                "description": f.description,
            }
            for f in fixes
        ],
        "judgment_requests": [
            {
                "rule_id": jr.rule_id,
                "rule_title": jr.rule_title,
                "question": jr.question,
                "content": jr.content,
                "location": jr.location,
                "criteria": jr.criteria,
                "examples": jr.examples,
                "choices": jr.choices,
                "pass_value": jr.pass_value,
            }
            for jr in judgment_requests
        ],
    }

    if judgment_requests:
        data["_semantic_workflow"] = {
            "action": "evaluate_and_judge",
            "steps": [
                "For each judgment_request: read the content field and evaluate against question + criteria",
                "Collect verdicts",
                "Call the judge tool with verdicts to cache results",
                "Report only failures to user; state pass count at end",
            ],
            "verdict_format": "RULE_ID:FILENAME:pass|fail:brief_reason (under 40 chars)",
        }

    return data


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
