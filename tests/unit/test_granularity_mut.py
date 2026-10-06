"""Mutation-closing tests for `core/mapper/granularity.py`.

The audit reads an atom's embedding text as `plain_text or text` — the raw
`text` is the fallback when `plain_text` (the AST-stripped field) is empty. A
stub encoder keeps these model-free.
"""

from __future__ import annotations

import numpy as np
import pytest

from reporails_cli.core.mapper.granularity import audit_over_merged
from reporails_cli.core.platform.dto.ruleset import Atom


def _atom_text_only(text: str) -> Atom:
    """Atom whose stripped `plain_text` is empty, so `text` is the only source."""
    return Atom(
        line=1,
        text=text,
        kind="excitation",
        charge="IMPERATIVE",
        charge_value=1,
        modality="imperative",
        specificity="abstract",
        plain_text="",
    )


class _StubEncoder:
    def __init__(self, vectors: dict[str, list[float]]) -> None:
        self._vectors = vectors

    def encode(self, texts: list[str]) -> np.ndarray:
        rows = []
        for t in texts:
            v = np.asarray(self._vectors[t], dtype=np.float32)
            rows.append(v / (float(np.linalg.norm(v)) or 1.0))
        return np.vstack(rows)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_empty_plain_text_falls_back_to_raw_text() -> None:
    """When `plain_text` is empty the audit must fall back to `text`.

    Kills both `plain_text or text -> plain_text and text` mutants: with `and`
    an empty `plain_text` collapses the source to "", so the atom is neither
    eligible nor splittable and nothing is flagged.
    """
    atom = _atom_text_only("Use the real service; formatting lives in the style guide")
    enc = _StubEncoder(
        {
            "Use the real service": [1.0, 0.0, 0.0, 0.0],
            "formatting lives in the style guide": [0.0, 1.0, 0.0, 0.0],
        }
    )
    flagged = audit_over_merged([atom], enc)
    assert flagged == 1
    assert atom.over_merged is True
    assert atom.min_clause_cosine is not None and atom.min_clause_cosine < 0.5
