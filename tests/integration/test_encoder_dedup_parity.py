"""Distinct-text bucketed encoding must equal the per-text path for every input position."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

_onnx_path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
)
requires_model = pytest.mark.skipif(not _onnx_path.exists(), reason="Bundled ONNX model not available")

_LONG = " ".join(f"word{i} alpha beta" for i in range(80)) + "."
_TEXTS = [
    "Always run the tests before committing.",
    "Ok.",
    "Always run the tests before committing.",
    "Never push to main without review, and keep commits small.",
    "",
    "Ok.",
    _LONG,
    "Use `uv run` to invoke python.",
    _LONG,
]


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_model
def test_decode_logits_batch_with_duplicates_equals_per_text(deterministic_ort: None) -> None:
    from reporails_cli.core.mapper.multislot_frames import _decode_logits, _decode_logits_batch

    progress: list[tuple[int, int]] = []
    batch = _decode_logits_batch(_TEXTS, lambda d, t: progress.append((d, t)))
    assert len(batch) == len(_TEXTS)
    for text, got in zip(_TEXTS, batch, strict=True):
        want = _decode_logits(text)
        if want is None:
            assert got is None
            continue
        assert got is not None
        assert list(got[0]) == list(want[0])
        for key in want[0]:
            assert np.array_equal(got[0][key], want[0][key]), key
        assert got[1] == want[1]
        assert got[2] == want[2]
    distinct = len(set(_TEXTS))
    assert progress
    assert progress[-1] == (distinct, distinct)


@pytest.mark.integration
@pytest.mark.subsys_map
@requires_model
def test_embedder_with_duplicates_equals_per_text(deterministic_ort: None) -> None:
    from reporails_cli.core.mapper.onnx_embedder import OnnxEmbedder

    embedder = OnnxEmbedder()
    batch = embedder.encode(_TEXTS)
    assert batch.shape[0] == len(_TEXTS)
    for i, text in enumerate(_TEXTS):
        assert np.array_equal(batch[i], embedder.encode([text])[0]), i
