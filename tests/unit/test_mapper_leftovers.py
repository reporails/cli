"""What a line holds, read as the author wrote it.

A bold label before a dash titles the instruction after it (`**Update narrative** — update the date`); a
`never` followed by what it excludes closes a contrast (`…, never the two-file base`) rather than starting a
prohibition; and a task list's checkbox is not a word of its item.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.instructions import instruction_texts
from reporails_cli.core.mapper.parse import tokenize


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "sentence",
    [
        "**Update narrative** — update `last_verified` date in the frontmatter",
        "**Run validator** — `uv run python scripts/validate_registry.py`",
        "*Do not treat the base load as targeted — the targeted rule governs the loads, never the two-file base.*",
        "Keep the rule local, never a global one.",
    ],
)
def test_a_label_or_a_contrast_is_part_of_its_instruction(sentence: str) -> None:
    assert instruction_texts(sentence) == [sentence]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_prohibition_after_a_comma_still_starts_its_own_instruction() -> None:
    assert len(instruction_texts("Keep the rule local, never commit a global one.")) == 2


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.requires_model
def test_a_backticked_span_counts_its_own_subword_tokens_not_one() -> None:
    """A named span's length is its own words, not a single placeholder.

    Before the fix, every backtick span collapsed to one "word" before counting, so a
    named 7-word instruction (`` `pytest tests/unit` `` counted as one) read as terse.
    The span's interior text now counts its own subword tokens.
    """
    (atom,) = tokenize("Run `pytest tests/unit` before you commit any change.")
    assert atom.token_count == 13


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "item", ["- [ ] Cite the evidence for every finding.", "- [x] Cite the evidence for every finding."]
)
@pytest.mark.requires_model
def test_a_task_checkbox_is_not_a_word_of_its_item(item: str) -> None:
    (atom,) = tokenize(item)
    assert atom.text == "Cite the evidence for every finding."
    # Subword count of "Cite the evidence for every finding." (bundled tokenizer): 7 pieces
    # including the closing period, not a bare 6-word split — the checkbox marker itself
    # contributes none of them either way.
    assert atom.token_count == 7


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.requires_model
@pytest.mark.parametrize(
    ("formatted", "plain"),
    [
        ("*Never commit secrets to the repo*", "Never commit secrets to the repo"),
        ("_Never commit secrets to the repo_", "Never commit secrets to the repo"),
        ("**Never commit secrets to the repo**", "Never commit secrets to the repo"),
        ("Never commit [secrets](https://example.com/x) to the repo", "Never commit secrets to the repo"),
        ("Never commit `secrets` to the repo", "Never commit secrets to the repo"),
        ("## *Never commit secrets to the repo*", "## Never commit secrets to the repo"),
    ],
)
def test_a_length_counts_the_instruction_without_its_formatting(formatted: str, plain: str) -> None:
    """An emphasis, bold, link or code-span wrap adds no tokens to the length."""
    (a,) = tokenize(formatted)
    (b,) = tokenize(plain)
    assert a.token_count == b.token_count == 7
