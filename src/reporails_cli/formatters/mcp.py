"""MCP output formatter.

Wraps canonical JSON format with MCP-specific transformations if needed.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.models import ValidationResult
from reporails_cli.formatters import json as json_formatter


def format_result(result: ValidationResult) -> dict[str, Any]:
    """
    Format validation result for MCP response.

    Currently returns canonical dict. Add MCP-specific
    transformations here if needed in the future.

    Args:
        result: ValidationResult from engine

    Returns:
        Dict suitable for MCP tool response
    """
    return json_formatter.format_result(result)


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
