"""Bare negative headings: a heading such as `## Don'ts` that labels a list of prohibitions."""

from __future__ import annotations

import re

from reporails_cli.core.platform.dto.ruleset import LIST_ITEM_FORMATS

# The adjectives that label a prohibition (`## Forbidden`).
PROHIBITION_ADJECTIVES: frozenset[str] = frozenset({"prohibited", "forbidden"})

# Bare negative headings, normalized (lowercase, punctuation dropped). A heading that matches
# one labels a list of prohibitions: every list item under it is a prohibition, whatever its
# own wording. Positive labels (`## Do's`, `## Must`) are deliberately absent. A full-sentence
# heading (`## Never use mocks`) never matches, and neither does a topic heading (`## Testing`).
NEGATIVE_HEADINGS = (
    frozenset(
        {
            "dont",
            "donts",
            "do not",
            "do nots",
            "must not",
            "must nots",
            "mustnt",
            "never",
            "shall not",
        }
    )
    | PROHIBITION_ADJECTIVES
)


def heading_label(text: str) -> str:
    """A heading's label: lowercased, punctuation dropped, whitespace collapsed."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", "", text.lower())).strip()


def is_negative_heading(heading: str) -> bool:
    """True when `heading` is a bare negative label such as `Don'ts` or `Must Not`."""
    return heading_label(heading) in NEGATIVE_HEADINGS


def in_negative_section(kind: str, fmt: str, heading_context: str) -> bool:
    """True for a list item that sits directly under a bare negative heading."""
    return kind != "heading" and fmt in LIST_ITEM_FORMATS and is_negative_heading(heading_context)
