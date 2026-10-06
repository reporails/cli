"""Mutation-killing behavioral tests for core/platform/dto/ruleset.py survivors.

The survivors are all `bool = False` field defaults on the Atom / AtomSlots
dataclasses. Three are load-bearing (an atom constructed without the flag takes
the default, and a real code path serializes or branches on it); one is
equivalent:

  - `Atom.abstained`: written by the charge pipeline (`atom.abstained =
    ...`) but never read back as `atom.abstained` and never serialized; only the
    per-span `span.abstained` is consumed. The default drives no decision —
    equivalent.

Load-bearing (closed below): `scope_conditional` (always serialized as "sc"),
`ambiguous` (conditionally emits the "a" key), and `over_merged` (gates the
clause-split in `split_over_merged_atoms`).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.split_topic import split_over_merged_atoms
from reporails_cli.core.platform.adapters.payload import project_payload
from reporails_cli.core.platform.dto.ruleset import (
    EMBEDDING_MODEL,
    SCHEMA_VERSION,
    Atom,
    FileRecord,
    RulesetMap,
    RulesetSummary,
)


def _min_atom(**overrides: object) -> Atom:
    base: dict[str, object] = {
        "line": 1,
        "text": "x",
        "kind": "excitation",
        "charge": "DIRECTIVE",
        "charge_value": 1,
        "modality": "imperative",
        "specificity": "named",
        "file_path": "CLAUDE.md",
    }
    base.update(overrides)
    return Atom(**base)  # type: ignore[arg-type]


def _ruleset(atom: Atom) -> RulesetMap:
    return RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at="2026-07-06T00:00:00Z",
        files=(FileRecord(path="CLAUDE.md", content_hash="sha256:abc"),),
        atoms=(atom,),
        summary=RulesetSummary(n_atoms=1, n_charged=1, n_neutral=0),
    )


# --- scope_conditional default -> payload "sc" (L73) ----------------------
@pytest.mark.unit
@pytest.mark.subsys_server
def test_default_scope_conditional_ships_false() -> None:
    atom = _min_atom()  # scope_conditional omitted -> default
    proj = project_payload(_ruleset(atom), Path("/p"))
    # `False -> True` would ship "sc": True for every unflagged atom.
    assert proj["atoms"][0]["sc"] is False


# --- ambiguous default -> payload "a" key omitted (L88) -------------------
@pytest.mark.unit
@pytest.mark.subsys_server
def test_default_ambiguous_omits_payload_key() -> None:
    atom = _min_atom()  # ambiguous omitted -> default
    proj = project_payload(_ruleset(atom), Path("/p"))
    # `if a.ambiguous: d["a"] = True` — `False -> True` would emit "a" for every
    # unflagged atom.
    assert "a" not in proj["atoms"][0]


# --- over_merged default -> split gate (L93) ------------------------------
@pytest.mark.unit
@pytest.mark.subsys_map
def test_default_over_merged_does_not_split() -> None:
    # Multi-clause text that WOULD split if over_merged were True.
    atom = _min_atom(plain_text="Do X; then do Y and also do Z here.")
    result, n_split = split_over_merged_atoms([atom], encoder=None)
    # `False -> True` would attempt a clause split (and re-embed) on every atom.
    assert n_split == 0
    assert result == [atom]
