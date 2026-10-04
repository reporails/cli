"""A bare negative deontic heading imposes a one-way prohibition floor.

A list item under `## Don'ts` / `## Must Not` is forced to `CONSTRAINT` charge
regardless of the item's own sign (the heading
suppresses the behaviour, so a double-negation stays prohibited). Positive
headings (`## Do's` / `## Must`) carry NO floor (no mandate mirror). A
full-sentence heading (`## Never use mocks`) and a neutral topic heading
(`## Testing`) never match. The floor is charge-level — the item text is never
mutated — and applies at heading→list-item scope only.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.parse import _apply_deontic_floor, tokenize
from reporails_cli.core.platform.dto.ruleset import Atom


def _item(charge: str, cv: int, heading: str, fmt: str = "list") -> Atom:
    """A list/prose atom under `heading`, carrying its own head-assigned charge."""
    return Atom(
        line=1,
        text="use the shared cache",
        kind="excitation",
        charge=charge,
        charge_value=cv,
        modality="imperative",
        specificity="abstract",
        format=fmt,
        heading_context=heading,
    )


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("heading", ["Don'ts", "Must Not", "Never", "Forbidden", "DON'TS"])
def test_prohibition_heading_floors_a_positive_item_to_constraint(heading: str) -> None:
    atom = _item("DIRECTIVE", 1, heading)
    _apply_deontic_floor([atom])
    assert (atom.charge, atom.charge_value) == ("CONSTRAINT", -1)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_prohibition_heading_floors_a_neutral_item_one_way() -> None:
    atom = _item("NEUTRAL", 0, "Don'ts")
    _apply_deontic_floor([atom])
    assert (atom.charge, atom.charge_value) == ("CONSTRAINT", -1)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_double_negation_stays_prohibited() -> None:
    # `## Don'ts` + a "do not X" item — the floor holds it at CONSTRAINT, it does
    # not compose to permission.
    atom = _item("CONSTRAINT", -1, "Don'ts")
    _apply_deontic_floor([atom])
    assert (atom.charge, atom.charge_value) == ("CONSTRAINT", -1)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("heading", ["Do's", "Must", "Always", "Required"])
def test_positive_heading_composes_no_floor(heading: str) -> None:
    # No mandate mirror: a positive deontic heading leaves the item's charge alone.
    atom = _item("DIRECTIVE", 1, heading)
    _apply_deontic_floor([atom])
    assert (atom.charge, atom.charge_value) == ("DIRECTIVE", 1)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("heading", ["Never use mocks", "Testing"])
def test_full_sentence_and_neutral_topic_headings_compose_no_floor(heading: str) -> None:
    atom = _item("DIRECTIVE", 1, heading)
    _apply_deontic_floor([atom])
    assert (atom.charge, atom.charge_value) == ("DIRECTIVE", 1)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_prose_under_a_prohibition_heading_is_not_floored() -> None:
    # List-item scope only — a prose paragraph under `## Don'ts` is untouched.
    atom = _item("DIRECTIVE", 1, "Don'ts", fmt="prose")
    _apply_deontic_floor([atom])
    assert (atom.charge, atom.charge_value) == ("DIRECTIVE", 1)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_segmentation_no_longer_mutates_item_text() -> None:
    # The floor is charge-level; the item text must NOT carry a heading prefix.
    md = "## Don'ts\n\n- use the shared cache\n"
    (atom,) = [a for a in tokenize(md, "structure-aware") if a.kind != "heading"]
    assert atom.text == "use the shared cache"
    assert "Don'ts:" not in atom.text
