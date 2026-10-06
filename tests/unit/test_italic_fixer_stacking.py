"""Tests for heal/mechanical_fixers.py — italic fixer never stacks emphasis.

Two behaviors plus an idempotency guard, exercised over a corpus of lines
already carrying an asymmetric mixed-emphasis wrap (a prior heal pass left a
`***...**` or `****...**` stack behind):

1. A bold-negation line (`**Never** commit secrets to the repo.`) must not be
   wrapped in outer italic — `fix_italic_constraints` used to produce
   `***Never** commit secrets to the repo.*`. The chosen clean result is to
   leave the line's existing single-emphasis (bold) state as-is.
2. A line already fully wrapped in emphasis (`*italic*`, `**bold**`,
   `***bold-italic***`, or a deeper stack from a prior heal pass) must not be
   wrapped again — the old guard only recognized a single-level `*...*` wrap,
   so a `**`/`***`-wrapped line fell through and stacked another layer.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.mechanical_fixers import fix_italic_constraints
from reporails_cli.core.platform.dto.ruleset import Atom


def _atom(line: int, text: str) -> Atom:
    return Atom(
        line=line,
        text=text,
        kind="paragraph",
        charge="CONSTRAINT",
        charge_value=-1,
        modality="none",
        specificity="abstract",
        unformatted_code=[],
        file_path="CLAUDE.md",
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_bold_negation_line_is_left_as_its_clean_single_emphasis_state() -> None:
    lines = ["**Never** commit secrets to the repo.\n"]
    atoms = [_atom(1, lines[0])]

    fixes = fix_italic_constraints(atoms, lines)

    assert lines[0] == "**Never** commit secrets to the repo.\n"
    assert fixes == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_already_bold_wrapped_line_is_not_stacked_into_bold_italic() -> None:
    lines = ["**Do not skip the tests.**\n"]
    atoms = [_atom(1, lines[0])]

    fixes = fix_italic_constraints(atoms, lines)

    assert lines[0] == "**Do not skip the tests.**\n"
    assert fixes == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_already_bold_italic_wrapped_line_is_not_stacked_further() -> None:
    lines = ["***Do not skip the tests.***\n"]
    atoms = [_atom(1, lines[0])]

    fixes = fix_italic_constraints(atoms, lines)

    assert lines[0] == "***Do not skip the tests.***\n"
    assert fixes == []


# Corpus lines shaped like the ones the defect actually produced: each is
# already an asymmetric `***...**` / `****...**` stack from a prior heal run.
_ASYMMETRIC_STACK_LINES = [
    # `***Lead sentence.** Body.*` — opens with a 3-star run, closes the lead
    # sentence with a 2-star run, then closes the whole line with 1 star.
    "- ***Do not skip the setup step.** If the docs don't mention a prerequisite, "
    "assume it isn't installed — even if a config file references it somewhere. "
    "Verify before proceeding.*\n",
    "- ***Do not merge without review.** Only approve changes you have actually "
    "read. Never approve based on the diff summary alone.*\n",
    # `****Label**: Body.**` — opens with a 4-star run, closes with a 2-star run
    # at the very end.
    "- ****Naming rule**: identifiers in `output.py` must NOT contain internal "
    "abbreviations (`tmp`, `cfg`, `impl`) or placeholder markers (`TODO`, "
    "`FIXME`).**\n",
]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("line", _ASYMMETRIC_STACK_LINES)
def test_already_stacked_corpus_line_is_left_unchanged(line: str) -> None:
    lines = [line]
    atoms = [_atom(1, line)]

    fixes = fix_italic_constraints(atoms, lines)

    assert lines[0] == line
    assert fixes == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_idempotent_apply_twice_equals_apply_once_over_corpus() -> None:
    corpus = [
        "Do not skip the tests\n",
        "**Never** commit secrets to the repo.\n",
        "**Do not skip the tests.**\n",
        "***Do not skip the tests.***\n",
        *_ASYMMETRIC_STACK_LINES,
    ]

    once = list(corpus)
    atoms_once = [_atom(i + 1, text) for i, text in enumerate(once)]
    fix_italic_constraints(atoms_once, once)

    twice = list(once)
    atoms_twice = [_atom(i + 1, text) for i, text in enumerate(twice)]
    second_fixes = fix_italic_constraints(atoms_twice, twice)

    assert twice == once
    assert second_fixes == []
