"""Inline suppression directives — find them in text and blank them out.

A directive is an inline HTML comment (invisible when the file renders) naming the rules
to silence on its line: `<!-- ails-disable-line CORE:C:0049 -->`.
"""

from __future__ import annotations

import re

_DIRECTIVE_RE = re.compile(r"<!--\s*ails-disable-line\b(?P<rules>[^>]*?)-->")
_RULE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")


def _rule_tokens(captured: str) -> set[str]:
    """Pull valid rule names out of a directive's body, dropping separators."""
    return {tok for tok in re.split(r"[,\s]+", captured.strip()) if _RULE_TOKEN_RE.match(tok)}


def parse_directives(text: str) -> dict[int, set[str]]:
    """Map 1-based line number to the set of rule names suppressed on that line."""
    out: dict[int, set[str]] = {}
    for lineno, line in enumerate(text.split("\n"), start=1):
        for match in _DIRECTIVE_RE.finditer(line):
            rules = _rule_tokens(match.group("rules"))
            if rules:
                out.setdefault(lineno, set()).update(rules)
    return out


def strip_directives(content: str) -> str:
    """Remove suppression-directive comments so they never reach classification.

    Replaces each directive comment with an equal run of spaces, preserving
    every newline and column offset so atom line numbers stay exact.
    """
    return _DIRECTIVE_RE.sub(lambda m: " " * (m.end() - m.start()), content)
