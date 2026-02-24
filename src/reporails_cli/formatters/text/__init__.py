"""Terminal text output formatters.

Public API for formatting validation results as terminal text.
"""

from reporails_cli.core.models import ScanDelta as _ScanDelta
from reporails_cli.formatters.text.compact import format_compact, format_score
from reporails_cli.formatters.text.components import format_legend

# Re-export internal functions used by tests (return str only, dropping markup_extra)
from reporails_cli.formatters.text.components import (
    format_level_delta as _format_level_delta_raw,
)
from reporails_cli.formatters.text.components import (
    format_score_delta as _format_score_delta_raw,
)
from reporails_cli.formatters.text.components import (
    format_violations_delta as _format_violations_delta_raw,
)
from reporails_cli.formatters.text.full import format_result
from reporails_cli.formatters.text.rules import format_rule


def _format_score_delta(delta: "_ScanDelta | None", ascii_mode: bool | None = None) -> str:
    return _format_score_delta_raw(delta, ascii_mode)[0]


def _format_level_delta(delta: "_ScanDelta | None", ascii_mode: bool | None = None) -> str:
    return _format_level_delta_raw(delta, ascii_mode)[0]


def _format_violations_delta(delta: "_ScanDelta | None", ascii_mode: bool | None = None) -> str:
    return _format_violations_delta_raw(delta, ascii_mode)[0]


__all__ = [
    "_format_level_delta",
    "_format_score_delta",
    "_format_violations_delta",
    "format_compact",
    "format_legend",
    "format_result",
    "format_rule",
    "format_score",
]
