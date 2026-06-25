"""Link/citation/code-span charge words must not promote a neutral atom to AMBIGUOUS."""

import pytest

from reporails_cli.core.mapper.parse import _scan_neutral_for_embedded_markers
from reporails_cli.core.platform.dto.ruleset import Atom


def _neutral(text: str) -> Atom:
    return Atom(
        line=1,
        text=text,
        kind="excitation",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity="abstract",
        rule="p3_neutral",
    )


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_word_inside_link_label_does_not_flag_ambiguous():
    atom = _neutral("See the [never push to main](rules/no-push.md) rule for context.")
    _scan_neutral_for_embedded_markers([atom])
    assert atom.charge == "NEUTRAL"
    assert atom.embedded_charge_markers == []


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_word_in_citation_reference_does_not_flag_ambiguous():
    atom = _neutral("This follows prior guidance.\n[avoid force-add]: rules/no-force.md")
    _scan_neutral_for_embedded_markers([atom])
    assert atom.charge == "NEUTRAL"
    assert atom.embedded_charge_markers == []


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_word_in_code_span_does_not_flag_ambiguous():
    atom = _neutral("The flag `never-fail` controls retry handling.")
    _scan_neutral_for_embedded_markers([atom])
    assert atom.charge == "NEUTRAL"
    assert atom.embedded_charge_markers == []


@pytest.mark.unit
@pytest.mark.subsys_map
def test_genuine_inline_constraint_language_still_flags_ambiguous():
    atom = _neutral("You must never bypass the validation step here.")
    _scan_neutral_for_embedded_markers([atom])
    assert atom.charge == "AMBIGUOUS"
    assert any(m.startswith("constraint:") for m in atom.embedded_charge_markers)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_link_label_charge_word_with_real_marker_outside_still_flags():
    atom = _neutral("Never bypass it; see [the deletion guide](g.md) for why.")
    _scan_neutral_for_embedded_markers([atom])
    assert atom.charge == "AMBIGUOUS"
    assert any(m.startswith("constraint:") for m in atom.embedded_charge_markers)
