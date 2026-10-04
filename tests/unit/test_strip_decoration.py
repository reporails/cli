"""Decoration stripping runs before any atom exists, so no stage downstream sees it.

The splitter, the classifier, and the embedder all read atom text. When a
pictograph survives into that text it becomes a unit of its own or opens one, and
every downstream stage inherits the artefact. These cases pin the boundary of
what counts as decoration and what counts as content.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.markdown_extract import _strip_decoration
from reporails_cli.core.mapper.parse import tokenize


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A pictograph between two sentences leaves neither one holding it.
        ("Keep it approachable. 🐙 Use short lines.", "Keep it approachable. Use short lines."),
        ("You had the power! 💪 The next step is yours.", "You had the power! The next step is yours."),
        # A variation selector and a skin-tone modifier are part of the sequence.
        ("Deny risky commands! 🛡️ Read the log first.", "Deny risky commands! Read the log first."),
        ("Nice work 👍🏽 — ship it.", "Nice work — ship it."),
        # A flag is a pair of regional indicators, decoration end to end.
        ("Locale 🇬🇧 is the default.", "Locale is the default."),
        # A keycap wraps a digit that IS content — only the enclosing mark goes.
        ("Press 1️⃣ to continue.", "Press 1 to continue."),
        # Dingbats, misc symbols, and technical blocks are decoration too.
        ("Coverage ✅ and latency ⚠ both pass.", "Coverage and latency both pass."),
        ("Runtime ⏳ stays under a second.", "Runtime stays under a second."),
        # Geometric shapes are used as bullets, not as content.
        ("● Install the tool. ▲ Run the check.", "Install the tool. Run the check."),
        ("Status ‼ needs review.", "Status needs review."),
        # A diagram frame decorates the text it encloses, exactly as an emoji does.
        ("│ Deploy to prod │", "Deploy to prod"),
        ("├── src/foo.py and └── tests/", "src/foo.py and tests/"),
        ("The tree shows ├── src/ side by side.", "The tree shows src/ side by side."),
        ("█████ 80% ████", "80%"),
    ],
)
def test_pictographs_are_removed_and_whitespace_collapses(text: str, expected: str) -> None:
    assert _strip_decoration(text) == expected


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "text",
    [
        # A trademark mark attaches to a product name the instruction names.
        "Build with Java™ before packaging.",
        "Ship the © notice in every header.",
        "The ® mark belongs in the footer.",
        # Arrows are gloss markers the sentence splitter reads.
        "Managing via API? → see the reference.",
        "The mapping is one ↔ many.",
        # An ASCII rule keeps its `|` and `-`: a character-level strip would maim
        # every hyphenated word and every real table row. It carries no letter, so
        # it is dropped as a unit downstream instead.
        "|------------+--------------|",
        "Use a well-known-flag and a | pipe.",
        # A shortcode is literal text, and the model reads it as a word.
        "Thank you for being involved! :heart_eyes:",
    ],
)
def test_content_bearing_symbols_survive(text: str) -> None:
    assert _strip_decoration(text) == text


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_pictograph_alone_leaves_an_empty_string() -> None:
    """A line carrying only decoration contributes no instruction at all."""
    assert _strip_decoration("🎉🎉🎉") == ""


def _headings(md: str) -> list:
    return [a for a in tokenize(md, "structure-aware") if a.format == "heading"]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("md", "expected"),
    [
        # A heading reads `.content` raw, unlike inline/table atoms; a leading
        # pictograph must not survive into the heading atom's text.
        ("# ⛔ Method Overloading is HIGHLANDER Violation", "Method Overloading is HIGHLANDER Violation"),
        ("## 🚀 Revolutionary Platform Overview", "Revolutionary Platform Overview"),
        ("### ✅ Latest Enhancements", "Latest Enhancements"),
    ],
)
def test_heading_atom_strips_a_leading_pictograph(md: str, expected: str) -> None:
    atoms = _headings(md)
    assert atoms, "expected a heading atom"
    assert atoms[0].text == expected
