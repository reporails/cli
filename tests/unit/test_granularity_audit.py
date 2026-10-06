"""Granularity audit — flag over-merged multi-clause atoms.

The load-bearing logic — split an atom into clauses, embed them, flag the atom
when its clauses span unrelated topics — is tested with a stub encoder so no ONNX
model is required. A real-embedder test skips when the model is not bundled.
"""

from __future__ import annotations

import numpy as np
import pytest

from reporails_cli.core.mapper.granularity import audit_over_merged
from reporails_cli.core.platform.dto.ruleset import Atom


def _atom(text: str, *, kind: str = "excitation") -> Atom:
    return Atom(
        line=1,
        text=text,
        kind=kind,
        charge="IMPERATIVE",
        charge_value=1,
        modality="imperative",
        specificity="abstract",
        plain_text=text,
    )


class _StubEncoder:
    """Returns an L2-normalized vector per text from a fixed mapping."""

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
def test_flags_topically_split_atom() -> None:
    # Two clauses on unrelated topics → orthogonal vectors → over-merged.
    atom = _atom("Use the real service; formatting lives in the style guide")
    enc = _StubEncoder(
        {
            "Use the real service": [1.0, 0.0, 0.0, 0.0],
            "formatting lives in the style guide": [0.0, 1.0, 0.0, 0.0],
        }
    )
    flagged = audit_over_merged([atom], enc)
    assert flagged == 1
    assert atom.over_merged is True
    assert atom.min_clause_cosine is not None
    assert atom.min_clause_cosine < 0.5


@pytest.mark.unit
@pytest.mark.subsys_map
def test_coherent_multiclause_atom_not_flagged() -> None:
    # Two clauses on the same topic → near-identical vectors → not over-merged.
    atom = _atom("Cache the result; cache the lookup table")
    enc = _StubEncoder(
        {
            "Cache the result": [1.0, 0.0, 0.0, 0.0],
            "cache the lookup table": [0.98, 0.2, 0.0, 0.0],
        }
    )
    flagged = audit_over_merged([atom], enc)
    assert flagged == 0
    assert atom.over_merged is False
    assert atom.min_clause_cosine is not None
    assert atom.min_clause_cosine > 0.5


@pytest.mark.unit
@pytest.mark.subsys_map
def test_single_clause_atom_is_skipped() -> None:
    # No clause marker → single clause → not eligible → untouched.
    atom = _atom("Run all the unit tests")
    enc = _StubEncoder({"Run all the unit tests": [1.0, 0.0, 0.0, 0.0]})
    flagged = audit_over_merged([atom], enc)
    assert flagged == 0
    assert atom.over_merged is False
    assert atom.min_clause_cosine is None


@pytest.mark.unit
@pytest.mark.subsys_map
def test_heading_atom_is_skipped() -> None:
    # Heading atoms carry no topical vector — excluded even when multi-clause.
    atom = _atom("Setup; teardown", kind="heading")
    enc = _StubEncoder({"Setup": [1.0, 0.0], "teardown": [0.0, 1.0]})
    flagged = audit_over_merged([atom], enc)
    assert flagged == 0
    assert atom.over_merged is False


class _ExplodingEncoder:
    """Any `.encode()` call fails the test — used to assert zero embed calls."""

    def encode(self, texts: list[str]) -> np.ndarray:  # pragma: no cover - should never run
        raise AssertionError(f"encoder.encode() called with {texts!r}; expected zero calls")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_multislot_stage_atom_is_skipped() -> None:
    # A unit the classifier already segmented is excluded —
    # The later split skips it too, so an audit flag on it reaches no consumer.
    atom = _atom("Use the real service; formatting lives in the style guide")
    atom.stage = "multislot"
    enc = _StubEncoder(
        {
            "Use the real service": [1.0, 0.0, 0.0, 0.0],
            "formatting lives in the style guide": [0.0, 1.0, 0.0, 0.0],
        }
    )
    flagged = audit_over_merged([atom], enc)
    assert flagged == 0
    assert atom.over_merged is False
    assert atom.min_clause_cosine is None


@pytest.mark.unit
@pytest.mark.subsys_map
def test_all_multislot_atoms_trigger_zero_embed_calls() -> None:
    # An all-multislot atom list must never reach the encoder at all.
    atoms = [_atom("Use the real service; formatting lives in the style guide")]
    for atom in atoms:
        atom.stage = "multislot"
    flagged = audit_over_merged(atoms, _ExplodingEncoder())
    assert flagged == 0
    assert atom.min_clause_cosine is None


@pytest.mark.unit
@pytest.mark.subsys_map
def test_count_and_clause_dedup_across_atoms() -> None:
    # A shared clause string is encoded once; both atoms are audited independently.
    a1 = _atom("Use the real service; formatting lives in the style guide")
    a2 = _atom("Use the real service; document the public API")
    enc = _StubEncoder(
        {
            "Use the real service": [1.0, 0.0, 0.0, 0.0],
            "formatting lives in the style guide": [0.0, 1.0, 0.0, 0.0],
            "document the public API": [0.0, 0.0, 1.0, 0.0],
        }
    )
    flagged = audit_over_merged([a1, a2], enc)
    assert flagged == 2
    assert a1.over_merged is True
    assert a2.over_merged is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_real_embedder_flags_two_topic_atom() -> None:
    """Smoke test on the bundled encoder; skips when the model is absent."""
    try:
        from reporails_cli.core.mapper.onnx_embedder import OnnxEmbedder

        encoder = OnnxEmbedder()
    except (RuntimeError, ImportError) as exc:
        pytest.skip(f"bundled embedder unavailable: {exc}")

    atom = _atom("Pin every dependency version; write the release notes in the changelog")
    flagged = audit_over_merged([atom], encoder)
    assert flagged == 1
    assert atom.over_merged is True
    assert atom.min_clause_cosine is not None
    assert atom.min_clause_cosine < 0.5


@pytest.mark.unit
@pytest.mark.subsys_map
def test_wholly_quoted_atom_is_skipped() -> None:
    atom = _atom('"Use the real service; formatting lives in the style guide."')
    flagged = audit_over_merged([atom], _StubEncoder({}))
    assert flagged == 0
    assert atom.over_merged is False
    assert atom.min_clause_cosine is None
