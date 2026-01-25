"""Terminal text output formatters.

Public API for formatting validation results as terminal text.
"""

from reporails_cli.formatters.text.compact import format_compact, format_score
from reporails_cli.formatters.text.components import format_legend
from reporails_cli.formatters.text.full import format_result
from reporails_cli.formatters.text.rules import format_rule

# Re-export internal functions used by tests
from reporails_cli.formatters.text.components import (
    format_level_delta as _format_level_delta,
    format_score_delta as _format_score_delta,
    format_violations_delta as _format_violations_delta,
)

__all__ = [
    "format_result",
    "format_compact",
    "format_score",
    "format_rule",
    "format_legend",
    # Internal helpers exposed for tests
    "_format_score_delta",
    "_format_level_delta",
    "_format_violations_delta",
]
