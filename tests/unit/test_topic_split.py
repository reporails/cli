"""Boundary-aware topic split of over-merged atoms.

Splits atoms the granularity audit flagged `over_merged` at clause boundaries,
re-classifying and re-embedding each sub-atom and marking the shared-sentence
join. Tested with a stub encoder (no detector) so no ONNX model is required.
"""

from __future__ import annotations

import numpy as np
import pytest

from reporails_cli.core.mapper.split_topic import split_over_merged_atoms
from reporails_cli.core.platform.dto.ruleset import Atom


def _atom(text: str, *, over_merged: bool, kind: str = "excitation", file_path: str = "/x/CLAUDE.md") -> Atom:
    return Atom(
        line=1,
        text=text,
        kind=kind,
        charge="IMPERATIVE",
        charge_value=1,
        modality="imperative",
        specificity="abstract",
        plain_text=text,
        over_merged=over_merged,
        file_path=file_path,
    )


class _StubEncoder:
    def encode(self, texts: list[str]) -> np.ndarray:
        # One deterministic unit vector per text; content-independent is fine —
        # the split does not re-decide over_merged, it acts on the flag.
        return np.vstack([np.array([1.0, 0.0, 0.0, 0.0], dtype=np.float32) for _ in texts])


@pytest.mark.unit
@pytest.mark.subsys_map
def test_over_merged_atom_splits_into_clause_subatoms() -> None:
    atom = _atom("Use the real service; document the public API", over_merged=True)
    result, n_split = split_over_merged_atoms([atom], _StubEncoder(), recharge=None)

    assert n_split == 1
    assert len(result) == 2
    assert [a.text for a in result] == ["Use the real service", "document the public API"]
    assert all(a.embedding_int8 is not None for a in result)
    assert [a.position_index for a in result] == [0, 1]
    # Sub-atoms carry the parent's file/format context.
    assert all(a.file_path == "/x/CLAUDE.md" for a in result)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_non_flagged_atom_passes_through_unchanged() -> None:
    atom = _atom("Use the real service; document the public API", over_merged=False)
    result, n_split = split_over_merged_atoms([atom], _StubEncoder(), recharge=None)

    assert n_split == 0
    assert result == [atom]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_positions_reindex_across_mixed_set() -> None:
    title = _atom("Rules", over_merged=False, kind="heading")
    title.charge, title.charge_value, title.modality = "NEUTRAL", 0, "none"
    keep = _atom("Run the linter", over_merged=False)
    rule_heading = _atom("Always pin versions", over_merged=False, kind="heading")
    split = _atom("Pin the version; write the changelog", over_merged=True)
    result, n_split = split_over_merged_atoms([title, keep, rule_heading, split], _StubEncoder(), recharge=None)

    assert n_split == 1
    # A section-title heading holds no place; a charged heading takes its place in document order,
    # then keep + two sub-atoms.
    assert [(a.kind, a.position_index) for a in result] == [
        ("heading", 0),
        ("excitation", 0),
        ("heading", 1),
        ("excitation", 2),
        ("excitation", 3),
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_positions_reindex_per_file_not_globally() -> None:
    """An over-merge split in file a.md must not push file b.md's positions past zero.

    `position_index` is re-indexed per `file_path`, in document order within each file, not
    with a single counter over the whole atom list.
    """
    a1 = _atom("Pin the version; write the changelog", over_merged=True, file_path="/x/a.md")
    a2 = _atom("Review the diff", over_merged=False, file_path="/x/a.md")
    b1 = _atom("Run the linter", over_merged=False, file_path="/x/b.md")
    b2 = _atom("Ship the release", over_merged=False, file_path="/x/b.md")
    b3 = _atom("Tag the commit", over_merged=False, file_path="/x/b.md")

    result, n_split = split_over_merged_atoms([a1, a2, b1, b2, b3], _StubEncoder(), recharge=None)

    assert n_split == 1
    by_file: dict[str, list[int]] = {}
    for atom in result:
        by_file.setdefault(atom.file_path, []).append(atom.position_index)

    # a.md: the split parent yields 2 sub-atoms + the untouched sibling = 3 atoms.
    assert sorted(by_file["/x/a.md"]) == list(range(3))
    # b.md must start back at 0 — NOT continue from a.md's running count.
    assert sorted(by_file["/x/b.md"]) == list(range(3))
    # Document order is preserved within each file.
    assert by_file["/x/b.md"] == [0, 1, 2]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_reclassifies_subatom_charge_independently() -> None:
    # A directive joined with a prohibition — the two clauses carry opposite sign.
    atom = _atom("Use the real service; never mock the database", over_merged=True)
    result, _ = split_over_merged_atoms([atom], _StubEncoder(), recharge=None)

    charges = {a.text: a.charge_value for a in result}
    assert charges["Use the real service"] == 1
    assert charges["never mock the database"] == -1
