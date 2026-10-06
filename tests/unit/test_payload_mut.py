"""Mutation-closing test for `core/platform/adapters/payload.py`."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.adapters.payload import _project_atom
from reporails_cli.core.platform.dto.ruleset import Atom, AtomSlots


def _ambiguous_atom() -> Atom:
    return Atom(
        line=1,
        text="",
        plain_text="",
        kind="excitation",
        charge="DIRECTIVE",
        charge_value=1,
        modality="imperative",
        specificity="named",
        scope_conditional=False,
        format="prose",
        named_tokens=("foo",),
        italic_tokens=(),
        bold_tokens=(),
        unformatted_code=(),
        position_index=0,
        token_count=8,
        file_path="CLAUDE.md",
        depth=2,
        ambiguous=True,
        embedded_charge_markers=(),
    )


@pytest.mark.unit
@pytest.mark.subsys_api
def test_ambiguous_atom_projects_true_flag() -> None:
    """An ambiguous atom must carry `a: True` on the wire.

    Kills the `d["a"] = True -> False` mutant: the flag exists to tell the
    backend the atom is ambiguous, so it must project the truthy value.
    """
    d = _project_atom(_ambiguous_atom(), {"CLAUDE.md": 0})
    assert d["a"] is True


@pytest.mark.unit
@pytest.mark.subsys_api
def test_atom_with_no_slot_coords_omits_so_key() -> None:
    """An atom with no span coordinates must NOT carry an `so` key at all — a
    fixed input with no slots (or slots with no offsets) must serialize
    byte-identically to a coordinate-less atom (kills `if so is not None` -> `is None`,
    and a mutant that always sets `d["so"]`)."""
    d = _project_atom(_ambiguous_atom(), {"CLAUDE.md": 0})
    assert "so" not in d

    # Slots present but text-only (no span offsets decoded) is the same as absent.
    atom = _ambiguous_atom()
    atom.slots = AtomSlots(subject="the response", predicate="return", object="JSON", scope="")
    d2 = _project_atom(atom, {"CLAUDE.md": 0})
    assert "so" not in d2


@pytest.mark.unit
@pytest.mark.subsys_api
def test_atom_with_slot_coords_projects_so_block_never_text() -> None:
    """A charged atom with populated span coordinates must project an `so` block
    whose offsets/confidences match the slot data exactly, and which never
    carries slot TEXT (kills any mutant that copies `.subject` instead of
    `.subject_span`, or a wrong key name for the wire's `su`/`pr`/`ob`/`scp`)."""
    atom = _ambiguous_atom()
    atom.slots = AtomSlots(
        subject="the user",
        predicate="must confirm",
        object="the deletion",
        scope="",
        subject_span=(0, 2),
        predicate_span=(2, 4),
        object_span=(4, 6),
        scope_span=None,
        subject_conf=0.95,
        predicate_conf=0.93,
        object_conf=0.90,
        scope_conf=0.0,
    )
    d = _project_atom(atom, {"CLAUDE.md": 0})
    assert d["so"] == {
        "su": [0, 2],
        "pr": [2, 4],
        "ob": [4, 6],
        "scp": None,
        "sconf": 0.95,
        "pconf": 0.93,
        "oconf": 0.90,
        "scconf": 0.0,
    }
    # Never the slot strings, on any key.
    dumped = str(d["so"])
    assert "the user" not in dumped
    assert "must confirm" not in dumped
    assert "the deletion" not in dumped
