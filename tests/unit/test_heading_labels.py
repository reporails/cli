"""Which headings count as category labels: a leading word that is no order, and no instruction after it."""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.heading_labels import is_label_heading
from reporails_cli.core.platform.dto.ruleset import Atom


def _heading(text: str) -> Atom:
    return Atom(
        line=1,
        text=text,
        kind="heading",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity="abstract",
        format="heading",
        depth=2,
    )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Keep — maintainer-ordered notes", True),
        ("Partial: docs cover most, residual scope noted", True),
        ("Always — run the tests before pushing", False),
        ("Never — force-push to main", False),
        ("Keep — never force-push to main", False),
        ("Drop — always rebase before merging", False),
        ("Run the tests before you commit", False),
    ],
)
def test_is_label_heading(text: str, expected: bool) -> None:
    assert is_label_heading(_heading(text)) is expected


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_non_heading_atom_is_no_label() -> None:
    atom = _heading("Keep — notes")
    atom.kind = "prose"
    assert is_label_heading(atom) is False
