"""Output formatters for reporails.

Each formatter is a submodule (``github``, ``json``, ``mcp``, ``text``) imported by name where used;
this package imports none of them.

The ``text`` and ``mcp`` formatters each expose ``format_rule(rule_id, rule_data) -> str``.
"""

from __future__ import annotations

__all__ = [
    "github",
    "json",
    "mcp",
    "text",
]
