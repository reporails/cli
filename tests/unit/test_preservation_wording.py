"""Word-level preservation checks decided from what the mapper reads: a hedge made direct is listed
and passes; a hedge turned into an absolute, a restriction with no condition word, a dropped
condition and a padded rewrite fail.

The atoms are real `Atom`s carrying the modality, condition flag and plain text the mapper gives
them, so the decisions are shown without the model; `tests/integration/test_preservation_wording.py`
runs the same rewrites through it.
"""

from __future__ import annotations

from typing import Any

import pytest

from reporails_cli.core.heal.preservation import compare, take_snapshot
from reporails_cli.core.heal.preservation.snapshot import is_hedge_fragment
from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap

_FILE = "/proj/CLAUDE.md"


def _atom(
    line: int,
    text: str,
    charge_value: int,
    modality: str,
    *,
    cond: bool = False,
    named: tuple[str, ...] = (),
    fmt: str = "prose",
) -> Atom:
    charge = {1: "DIRECTIVE", -1: "CONSTRAINT", 0: "NEUTRAL"}[charge_value]
    return Atom(
        line=line,
        text=text,
        kind="excitation",
        charge=charge,
        charge_value=charge_value,
        modality=modality,
        specificity="named" if named else "abstract",
        scope_conditional=cond,
        format=fmt,
        named_tokens=list(named),
        plain_text=text.replace("`", ""),
        file_path=_FILE,
        position_index=line,
    )


def _map(*atoms: Atom) -> RulesetMap:
    return RulesetMap(schema_version="t", embedding_model="t", generated_at="t", files=(), atoms=atoms)


def _verdict(old: list[Atom], new: list[Atom], before: str, after: str) -> dict[str, Any]:
    snap = take_snapshot(_FILE, before, _map(*old), 5.0)
    return compare(snap, _map(*new), after, 5.0)


def _one(old: Atom, new: Atom) -> dict[str, Any]:
    return _verdict([old], [new], f"# A\n\n{old.text}\n", f"# A\n\n{new.text}\n")


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_lead_in_hedge_alone_is_a_fragment_not_an_instruction() -> None:
    assert is_hedge_fragment(_atom(3, "Consider", 1, "hedged"))
    assert is_hedge_fragment(_atom(3, "You should", 1, "hedged"))
    assert not is_hedge_fragment(_atom(3, "Consider running `ruff`.", 1, "hedged"))
    assert not is_hedge_fragment(_atom(3, "You should not", -1, "hedged"))
    assert not is_hedge_fragment(_atom(3, "Never", -1, "absolute"))


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("old_text", "new_text", "new_modality"),
    [
        ("Prefer real objects in tests.", "Use real objects in tests.", "imperative"),
        ("Try not to use global state.", "Do not use global state.", "imperative"),
        ("You should always run `pytest`.", "Always run `pytest`.", "absolute"),
    ],
)
def test_a_hedged_instruction_made_direct_is_listed_with_both_sentences(
    old_text: str, new_text: str, new_modality: str
) -> None:
    result = _one(_atom(3, old_text, 1, "hedged"), _atom(3, new_text, 1, new_modality))
    assert result["made_direct"] == [{"line": 3, "text": old_text, "new_line": 3, "new_text": new_text}]
    assert result["hedge_made_absolute"] == []
    assert result["ok"] is True


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_hedge_cut_into_a_lead_in_atom_and_a_clause_is_one_sentence_made_direct() -> None:
    old = [_atom(3, "Consider", 1, "hedged"), _atom(3, "avoiding global state.", -1, "hedged")]
    result = _verdict(
        old,
        [_atom(3, "Avoid global state.", -1, "imperative")],
        "# A\n\nConsider avoiding global state.\n",
        "# A\n\nAvoid global state.\n",
    )
    assert result["lost_instructions"] == []
    assert result["made_direct"] == [
        {"line": 3, "text": "Consider avoiding global state.", "new_line": 3, "new_text": "Avoid global state."}
    ]
    assert result["ok"] is True


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_hedged_line_the_mapper_read_as_prose_is_listed_when_the_rewrite_states_it_directly() -> None:
    old = _atom(3, "You might want to run the linter before a commit.", 0, "none")
    new = _atom(3, "Run the linter before a commit.", 1, "imperative")
    result = _verdict([old], [new], f"# A\n\n{old.text}\n", f"# A\n\n{new.text}\n")
    assert [e["new_text"] for e in result["made_direct"]] == [new.text]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_sentence_that_keeps_its_hedge_is_not_listed_as_made_direct() -> None:
    result = _one(
        _atom(3, "Prefer real objects in tests.", 1, "hedged"),
        _atom(3, "Prefer real objects in all tests.", 1, "hedged"),
    )
    assert result["made_direct"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("old_text", "old_charge", "new_text", "new_charge", "failed"),
    [
        ("Prefer not to mock the database.", -1, "Never mock the database.", -1, True),
        ("Consider running `ruff check`.", 1, "Always run `ruff check`.", 1, True),
        ("Prefer not to mock the database.", -1, "Do not mock the database.", -1, False),
    ],
)
def test_a_hedge_turned_into_an_absolute_the_line_never_had_fails(
    old_text: str, old_charge: int, new_text: str, new_charge: int, failed: bool
) -> None:
    modality = "absolute" if failed else "imperative"
    result = _one(_atom(3, old_text, old_charge, "hedged"), _atom(3, new_text, new_charge, modality))
    assert bool(result["hedge_made_absolute"]) is failed
    assert result["ok"] is not failed


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("original", "rewrite", "failed"),
    [
        ("Run the linter.", "Run the linter in CI.", True),
        ("Use real objects in tests.", "Use real objects in unit tests.", True),
        ("Deploy with `make deploy`.", "Deploy with `make deploy` on Fridays.", True),
        ("Format the code.", "Format the code for the api module.", True),
        ("Use real objects in tests.", "Use real objects in tests only for the database layer.", True),
        ("Do not commit secrets.", "Do not commit secrets outside the vault folder.", True),
        ("Run the linter in CI.", "In CI, run the linter.", False),
        ("Run the tests.", "Run the tests with `pytest tests/`.", False),
        ("Use real objects in tests.", "Use real objects in tests, because they catch deployment failures.", False),
    ],
)
def test_words_that_restrict_where_when_or_to_what_an_instruction_applies_fail(
    original: str, rewrite: str, failed: bool
) -> None:
    named = ("pytest tests/",) if "`pytest tests/`" in rewrite else ()
    named += ("make deploy",) if "`make deploy`" in rewrite else ()
    result = _one(_atom(3, original, 1, "imperative"), _atom(3, rewrite, 1, "imperative", named=named))
    assert bool(result["narrowed_instructions"]) is failed


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("original", "old_cond", "rewrite", "new_cond", "failed"),
    [
        ("Run `pytest` before every commit.", True, "Run `pytest`.", False, True),
        ("Run the linter unless you are in a hurry.", True, "Run the linter.", False, True),
        ("Run the smoke tests only on `main`.", False, "Run the smoke tests.", False, True),
        ("Run `pytest` before every commit.", True, "Before every commit, run `pytest`.", True, False),
        ("Run `pytest`.", False, "Run `pytest` before every commit.", True, False),
    ],
)
def test_a_condition_the_rewrite_no_longer_holds_fails(
    original: str, old_cond: bool, rewrite: str, new_cond: bool, failed: bool
) -> None:
    result = _one(_atom(3, original, 1, "imperative", cond=old_cond), _atom(3, rewrite, 1, "imperative", cond=new_cond))
    assert bool(result["dropped_conditions"]) is failed


@pytest.mark.unit
@pytest.mark.subsys_server
def test_atoms_copied_from_atoms_the_file_already_has_are_padding() -> None:
    old = [
        _atom(3, "Run the tests.", 1, "imperative", fmt="list"),
        _atom(4, "Format the code.", 1, "imperative", fmt="list"),
    ]
    new = [
        *old,
        _atom(5, "Run all the tests.", 1, "imperative", fmt="list"),
        _atom(6, "Format the code.", 1, "imperative", fmt="list"),
    ]
    before = "- Run the tests.\n- Format the code.\n"
    after = before + "- Run all the tests.\n- Format the code.\n"
    result = _verdict(old, new, f"# A\n\n{before}", f"# A\n\n{after}")
    assert [e["text"] for e in result["padded_lines"]] == ["Run all the tests.", "Format the code."]
    assert _verdict(old, old, f"# A\n\n{before}", f"# A\n\n{before}")["padded_lines"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_duplicates_the_original_already_had_are_not_padding() -> None:
    atoms = [
        _atom(3, "Run the tests.", 1, "imperative", fmt="list"),
        _atom(4, "Run the tests.", 1, "imperative", fmt="list"),
    ]
    text = "# A\n\n- Run the tests.\n- Run the tests.\n"
    assert _verdict(atoms, atoms, text, text)["padded_lines"] == []
