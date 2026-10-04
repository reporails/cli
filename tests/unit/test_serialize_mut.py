"""Mutation-killing tests for mapper/serialize.py.

Two seams:
  1. Atom JSON round-trip — style dispatch, ambiguous flag, optional-field
     default coercions must survive serialize→deserialize.
  2. validate_atoms — the schema/consistency invariant tuples and the
     distribution ratio must flag exactly the violating atoms and nothing else.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.serialize import (
    _atom_from_dict,
    _atom_to_dict,
    load_ruleset_map,
    save_ruleset_map,
    validate_atoms,
)
from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots, FileRecord, RulesetMap, RulesetSummary


def _atom(
    *,
    charge_value: int = 0,
    charge: str = "NEUTRAL",
    modality: str = "none",
    kind: str = "excitation",
    text: str = "some plain content",
    line: int = 1,
    **kw,
) -> Atom:
    return Atom(
        line=line,
        text=text,
        kind=kind,
        charge=charge,
        charge_value=charge_value,
        modality=modality,
        specificity="abstract",
        **kw,
    )


# ──────────────────────────────────────────────────────────────────
# Round-trip: style dispatch + ambiguous flag  (L57, L150-156, L182)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_inline_style_dispatch_round_trips_each_bucket() -> None:
    """Each formatting bucket must survive serialize→deserialize into its own list."""
    atom = _atom(
        charge_value=1,
        charge="DIRECTIVE",
        modality="imperative",
        named_tokens=["backtickterm"],
        italic_tokens=["italicterm"],
        bold_tokens=["boldterm"],
        unformatted_code=["plainterm"],
    )
    back = _atom_from_dict(_atom_to_dict(atom))
    # A mutated == on any style branch drops or misroutes the term.
    assert back.named_tokens == ["backtickterm"]
    assert back.italic_tokens == ["italicterm"]
    assert back.bold_tokens == ["boldterm"]
    assert back.unformatted_code == ["plainterm"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_ambiguous_true_round_trips_true() -> None:
    """ambiguous=True must serialize as True and come back True (kills L57 True→False)."""
    atom = _atom(ambiguous=True)
    assert _atom_to_dict(atom)["ambiguous"] is True
    assert _atom_from_dict(_atom_to_dict(atom)).ambiguous is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_ambiguous_false_round_trips_false() -> None:
    """A non-ambiguous atom omits the key; the deserialize default must stay False (L182)."""
    atom = _atom(ambiguous=False)
    assert "ambiguous" not in _atom_to_dict(atom)
    assert _atom_from_dict(_atom_to_dict(atom)).ambiguous is False


@pytest.mark.unit
@pytest.mark.subsys_map
def test_scope_conditional_default_false_on_missing_key() -> None:
    """A dict lacking scope_conditional must deserialize to False (kills L167 default)."""
    d = _atom_to_dict(_atom())
    d.pop("scope_conditional", None)
    assert _atom_from_dict(d).scope_conditional is False


# ──────────────────────────────────────────────────────────────────
# slots (span coordinates) + stage/over_merged/etc.
# round-trip through the JSON serializer (daemon dict path + full-map cache).
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_atom_round_trip_carries_span_coordinates_and_stage_fields() -> None:
    """An Atom with populated slots/stage/over_merged/min_clause_cosine/caps_tokens/
    cell_straddle/abstained must round-trip through _atom_to_dict/_atom_from_dict
    with every field payload.py's _project_atom reads intact, so a daemon or whole-map-cache round-trip serves
    the same payload (`so` block included) as a cold in-process run."""
    atom = _atom(
        charge_value=1,
        charge="DIRECTIVE",
        modality="imperative",
        caps_tokens=["MUST"],
        cell_straddle=True,
        stage="multislot",
        over_merged=True,
        min_clause_cosine=0.37,
        abstained=True,
        slots=AtomSlots(
            subject_span=(0, 2),
            predicate_span=(2, 4),
            object_span=(4, 6),
            scope_span=None,
            subject_conf=0.91,
            predicate_conf=0.88,
            object_conf=0.75,
            scope_conf=0.0,
        ),
    )
    back = _atom_from_dict(_atom_to_dict(atom))
    assert back.caps_tokens == ["MUST"]
    assert back.cell_straddle is True
    assert back.stage == "multislot"
    assert back.over_merged is True
    assert back.min_clause_cosine == pytest.approx(0.37)
    assert back.abstained is True
    assert back.slots is not None
    assert back.slots.subject_span == (0, 2)
    assert back.slots.predicate_span == (2, 4)
    assert back.slots.object_span == (4, 6)
    assert back.slots.scope_span is None
    assert back.slots.subject_conf == pytest.approx(0.91)
    assert back.slots.predicate_conf == pytest.approx(0.88)
    assert back.slots.object_conf == pytest.approx(0.75)
    # Slot TEXT is never round-tripped: cli-local-per-run, not cached/shipped.
    assert back.slots.subject == ""
    assert back.slots.predicate == ""
    assert back.slots.object == ""


@pytest.mark.unit
@pytest.mark.subsys_map
def test_atom_without_slots_round_trips_slots_none() -> None:
    """An atom that never carried spans must come back with slots=None, not an
    all-null AtomSlots (mirrors the `so` wire contract: omit rather than emit null)."""
    atom = _atom()
    d = _atom_to_dict(atom)
    assert "slot_coords" not in d
    assert _atom_from_dict(d).slots is None


@pytest.mark.unit
@pytest.mark.subsys_map
def test_atom_round_trip_via_save_and_load_ruleset_map(tmp_path) -> None:
    """The full save_ruleset_map/load_ruleset_map disk round-trip (what the
    full-map cache and the daemon's temp-file dict path exercise) must carry the
    same fields as the direct dict helpers."""
    atom = _atom(
        charge_value=-1,
        charge="CONSTRAINT",
        modality="absolute",
        stage="multislot",
        over_merged=True,
        min_clause_cosine=0.2,
        slots=AtomSlots(subject_span=(1, 3), subject_conf=0.6),
    )
    rm = RulesetMap(
        schema_version="v3",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(FileRecord(path="SKILL.md", content_hash="h", type="skills"),),
        atoms=(atom,),
        summary=RulesetSummary(n_atoms=1, n_charged=1, n_neutral=0),
    )
    dest = tmp_path / "map.json"
    save_ruleset_map(rm, dest)
    reloaded = load_ruleset_map(dest)
    assert reloaded.files[0].type == "skills"  # a cached map keeps each file's type
    back = reloaded.atoms[0]
    assert back.stage == "multislot"
    assert back.over_merged is True
    assert back.min_clause_cosine == pytest.approx(0.2)
    assert back.slots is not None
    assert back.slots.subject_span == (1, 3)
    assert back.slots.subject_conf == pytest.approx(0.6)


# ──────────────────────────────────────────────────────────────────
# save_ruleset_map parent mkdir  (L213 parents/exist_ok)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_save_creates_nested_parents_and_tolerates_existing(tmp_path) -> None:
    """First save must create a missing parent chain (parents=True); a second save into
    the now-existing parent must not raise (exist_ok=True)."""
    rm = RulesetMap(
        schema_version="v3",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(),
        atoms=(_atom(),),
        summary=RulesetSummary(n_atoms=1, n_charged=0, n_neutral=1),
    )
    dest = tmp_path / "deep" / "nested" / "map.json"
    save_ruleset_map(rm, dest)  # parents don't exist → parents=True required
    assert dest.exists()
    save_ruleset_map(rm, dest)  # parent exists now → exist_ok=True required
    reloaded = load_ruleset_map(dest)
    assert len(reloaded.atoms) == 1


# ──────────────────────────────────────────────────────────────────
# validate_atoms schema/consistency tuples  (L331-334, L357, L370)
# ──────────────────────────────────────────────────────────────────


def _consistency_msgs(atom: Atom) -> list[str]:
    return [f.message for f in validate_atoms([atom]) if f.rule == "consistency"]


def _rules_for(atom: Atom) -> set[str]:
    return {f.rule for f in validate_atoms([atom])}


@pytest.mark.unit
@pytest.mark.subsys_map
def test_clean_atoms_raise_no_schema_or_consistency_finding() -> None:
    """A well-formed neutral/directive/constraint atom must not trip schema or consistency
    (kills the and→or and ==/!= flips that turn clean atoms into false positives)."""
    for atom in (
        _atom(charge_value=0, charge="NEUTRAL", modality="none"),
        _atom(charge_value=1, charge="DIRECTIVE", modality="imperative"),
        _atom(charge_value=-1, charge="CONSTRAINT", modality="absolute"),
    ):
        assert _rules_for(atom).isdisjoint({"schema", "consistency"}), atom.charge


@pytest.mark.unit
@pytest.mark.subsys_map
def test_neutral_value_with_nonneutral_charge_flags(  # L331
) -> None:
    atom = _atom(charge_value=0, charge="DIRECTIVE", modality="none")
    assert "charge_value=0 but charge=DIRECTIVE" in _consistency_msgs(atom)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charged_value_with_neutral_charge_flags(  # L332
) -> None:
    atom = _atom(charge_value=1, charge="NEUTRAL", modality="imperative")
    assert "charge_value!=0 but charge=NEUTRAL" in _consistency_msgs(atom)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_neutral_with_nonnone_modality_flags(  # L333
) -> None:
    atom = _atom(charge_value=0, charge="NEUTRAL", modality="hedged")
    assert "NEUTRAL with modality=hedged" in _consistency_msgs(atom)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charged_with_none_modality_flags(  # L334
) -> None:
    atom = _atom(charge_value=1, charge="DIRECTIVE", modality="none")
    assert "Charged with modality=none" in _consistency_msgs(atom)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_excitation_gate_routes_must_constraint_check() -> None:
    """A negation-led excitation atom under-charged must warn; the kind=='excitation'
    gate (L357) is what admits it — a heading with the same text must NOT warn."""
    exc = _atom(charge_value=0, charge="NEUTRAL", modality="none", text="Never delete the database.")
    head = _atom(charge_value=0, charge="NEUTRAL", modality="none", text="Never delete the database.", kind="heading")
    assert "must_constraint" in _rules_for(exc)
    assert "must_constraint" not in _rules_for(head)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_must_constraint_honours_bare_no_status_guard() -> None:
    """A bare 'No <noun>' status fragment must not warn NEUTRAL — it is the same
    non-prohibition shape `_BARE_NO_RE` already floors upstream;
    a real prohibition with a complement still warns when under-charged."""
    bare = _atom(charge_value=0, charge="NEUTRAL", modality="none", text="No mocks.")
    real = _atom(charge_value=0, charge="NEUTRAL", modality="none", text="Never mock the database.")
    assert "must_constraint" not in _rules_for(bare)
    assert "must_constraint" in _rules_for(real)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_suspicious_neutral_strong_word_gating() -> None:
    """A NEUTRAL atom with an unquoted strong word warns; a charged atom or a quoted
    NEUTRAL atom must NOT (kills L370 ==→!= and both and→or)."""
    unquoted = _atom(charge_value=0, charge="NEUTRAL", modality="none", text="The MUST keyword is reserved.")
    charged = _atom(charge_value=1, charge="DIRECTIVE", modality="imperative", text="MUST run the build.")
    quoted = _atom(charge_value=0, charge="NEUTRAL", modality="none", text='"MUST" is a reserved keyword.')
    assert "suspicious_neutral" in _rules_for(unquoted)
    assert "suspicious_neutral" not in _rules_for(charged)
    assert "suspicious_neutral" not in _rules_for(quoted)


# ──────────────────────────────────────────────────────────────────
# distribution ratio  (L387 n_charged count, L392 low-ratio guard)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_distribution_high_ratio_flags_high_not_low() -> None:
    """11 all-charged excitation atoms → 'unusually high' only. n_charged must count
    charged atoms (L387 !=), and the low-ratio branch must require BOTH conditions
    (L392 and)."""
    atoms = [
        _atom(charge_value=1, charge="DIRECTIVE", modality="imperative", text=f"Use tool number {i}.", line=i)
        for i in range(11)
    ]
    msgs = [f.message for f in validate_atoms(atoms) if f.rule == "distribution"]
    assert any("unusually high" in m for m in msgs)
    assert not any("unusually low" in m for m in msgs)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_checks_use_the_classifier_s_prohibition_and_absolute_words() -> None:
    """The negation opener and the capitalised strong words come from the classifier's own lists, so a
    prohibition it reads (`Refrain from`, `Should not`) and an absolute it carries (`EXCLUSIVELY`) count."""
    for opener in ("Refrain from mocking the database.", "Should not mock the database."):
        assert "must_constraint" in _rules_for(_atom(text=opener)), opener
    assert "suspicious_neutral" in _rules_for(_atom(text="The EXCLUSIVELY keyword is reserved."))
    assert "suspicious_neutral" in _rules_for(_atom(text="Files marked FORBIDDEN stay."))
    assert "suspicious_neutral" not in _rules_for(_atom(text="The never keyword is reserved."))
