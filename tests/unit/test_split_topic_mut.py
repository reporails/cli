"""Mutation-closing test for `core/mapper/split_topic.py`."""

from __future__ import annotations

import numpy as np
import pytest

from reporails_cli.core.mapper.split_topic import split_over_merged_atoms
from reporails_cli.core.platform.dto.ruleset import Atom


class _StubEncoder:
    def encode(self, texts: list[str]) -> np.ndarray:
        return np.vstack([np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32) for _ in texts])


@pytest.mark.unit
@pytest.mark.subsys_map
def test_split_falls_back_to_raw_text_when_plain_empty() -> None:
    """When `plain_text` is empty the split reads clauses from `text`.

    Kills the `plain_text or text -> plain_text and text` mutant: with `and`,
    an empty `plain_text` collapses the source to "", producing zero clauses so
    a flagged atom is never split.
    """
    atom = Atom(
        line=1,
        text="Use the real service; document the public API",
        kind="excitation",
        charge="IMPERATIVE",
        charge_value=1,
        modality="imperative",
        specificity="abstract",
        plain_text="",
        over_merged=True,
        file_path="/x/CLAUDE.md",
    )
    result, n_split = split_over_merged_atoms([atom], _StubEncoder(), recharge=None)

    assert n_split == 1
    assert [a.text for a in result] == ["Use the real service", "document the public API"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_split_sub_atoms_keep_the_parent_backtick_named_ness() -> None:
    """Clauses come from the AST-clean text; the parent's markers are projected back.

    Reddens when the markers are lost: a sub-atom built straight from the plain
    clause reads `abstract` even though the author backticked the name.
    """
    atom = Atom(
        line=3,
        text="Run `uv run poe qa_fast` first; keep **secrets** out of `CLAUDE.md`",
        kind="excitation",
        charge="IMPERATIVE",
        charge_value=1,
        modality="imperative",
        specificity="named",
        plain_text="Run uv run poe qa_fast first; keep secrets out of CLAUDE.md",
        over_merged=True,
        file_path="/x/CLAUDE.md",
    )
    result, n_split = split_over_merged_atoms([atom], _StubEncoder(), recharge=None)

    assert n_split == 1
    first, second = result
    assert first.text == "Run `uv run poe qa_fast` first"
    assert first.plain_text == "Run uv run poe qa_fast first"
    assert (first.specificity, first.named_tokens) == ("named", ["uv run poe qa_fast"])
    assert second.text == "keep **secrets** out of `CLAUDE.md`"
    assert (second.specificity, second.named_tokens, second.bold_tokens) == ("named", ["CLAUDE.md"], ["secrets"])


@pytest.mark.unit
@pytest.mark.subsys_map
def test_split_sub_atoms_keep_the_parent_plain_clause() -> None:
    # The sub-atom's plain_text is the parent's plain clause, never a re-strip of the
    # reformatted text (which would mangle an underscore identifier).
    atom = Atom(
        line=3,
        text="Wire `__main__` first; keep secrets out",
        kind="excitation",
        charge="IMPERATIVE",
        charge_value=1,
        modality="imperative",
        specificity="named",
        plain_text="Wire __main__ first; keep secrets out",
        over_merged=True,
        file_path="/x/CLAUDE.md",
    )
    result, _ = split_over_merged_atoms([atom], _StubEncoder(), recharge=None)
    first, second = result
    assert (first.text, first.plain_text, first.named_tokens) == (
        "Wire `__main__` first",
        "Wire __main__ first",
        ["__main__"],
    )
    assert (second.text, second.plain_text) == ("keep secrets out", "keep secrets out")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_span_atoms_are_never_re_split_at_lexical_clause_markers() -> None:
    """An already-segmented multislot atom (its `when` clause is a scope slot) is not re-split;
    the lexical clause split is a repair for lexical-charged atoms only."""
    base = {
        "line": 4,
        "text": "Update the bundled rules under `framework/rules/` when a rule changes; run the tests",
        "kind": "excitation",
        "charge": "IMPERATIVE",
        "charge_value": 1,
        "modality": "imperative",
        "specificity": "named",
        "plain_text": "Update the bundled rules under framework/rules/ when a rule changes; run the tests",
        "over_merged": True,
        "file_path": "/x/CLAUDE.md",
    }
    head_atom = Atom(**base, stage="multislot")
    lexical_atom = Atom(**base)
    result, n_split = split_over_merged_atoms([head_atom, lexical_atom], _StubEncoder(), recharge=None)
    assert n_split == 1
    assert result[0] is head_atom
    # "when" stays on the clause it introduces (the marker-retention fix in `lexical.py`);
    # it no longer disappears with the cut.
    assert [a.text for a in result[1:]] == [
        "Update the bundled rules under `framework/rules/`",
        "when a rule changes",
        "run the tests",
    ]
