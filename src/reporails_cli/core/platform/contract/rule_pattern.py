"""The one compile of a rule check's regex pattern."""

from __future__ import annotations

import regex


def compile_rule_pattern(text: str) -> regex.Pattern[str]:
    """`text` compiled the way every rule pattern is matched (multiline, dot matches newline).

    Raises `regex.error` when `text` is not a valid pattern.
    """
    return regex.compile(text, regex.MULTILINE | regex.DOTALL)
