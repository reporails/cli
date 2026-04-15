"""Terminal text output formatters.

Public API for formatting validation results as terminal text.
Archived: full.py, box.py, violations.py, compact.py moved to _archived/formatters/.
Active: rules.py (explain command), components.py (shared helpers), chars.py (character sets).
"""

from reporails_cli.formatters.text.rules import format_rule

__all__ = [
    "format_rule",
]
