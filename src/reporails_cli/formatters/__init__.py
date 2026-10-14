"""Output formatters for reporails.

Each formatter is a submodule (``github``, ``json``, ``mcp``, ``text``) imported by name where used;
this package imports none of them.

Each formatter implements the same interface:
- format_rule(rule_id: str, rule_data: dict) -> T

Where T is dict for json/mcp, str for text.
"""

from __future__ import annotations

__all__ = [
    "github",
    "json",
    "mcp",
    "text",
]
