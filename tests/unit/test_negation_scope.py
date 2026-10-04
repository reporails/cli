"""Negation on a line: a descriptive "No X is Y" reads neutral and a prohibition chain raises no
`must_constraint` map-validation warning."""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.parse import tokenize
from reporails_cli.core.mapper.serialize import validate_atoms


def _charged(text: str) -> list:
    return [a for a in tokenize(text) if a.kind != "heading"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_descriptive_no_is_neutral_and_not_flagged_must_constraint():
    atoms = _charged("# T\n\nNo pre-display floor is documented in the hook.\n")
    assert atoms[0].charge_value == 0
    assert atoms[0].charge == "NEUTRAL"
    findings = validate_atoms(atoms)
    assert not [f for f in findings if f.rule == "must_constraint"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_governed_clauses_produce_no_must_constraint_warnings():
    atoms = _charged("# T\n\nDo not delete the file; substitute the value; treat the output as final.\n")
    findings = validate_atoms(atoms)
    assert not [f for f in findings if f.rule == "must_constraint"]
