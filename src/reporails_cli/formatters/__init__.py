"""Output formatters for reporails.

Each formatter implements the same interface:
- format_result(result: ValidationResult) -> T
- format_score(result: ValidationResult) -> T
- format_rule(rule_id: str, rule_data: dict) -> T

Where T is dict for json/mcp, str for text.
"""

from __future__ import annotations

from reporails_cli.formatters import github, json, mcp, text

__all__ = [
    "github",
    "json",
    "mcp",
    "text",
]
