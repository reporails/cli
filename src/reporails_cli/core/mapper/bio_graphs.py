"""Paths of the classification model graph files."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from reporails_cli.core.mapper.graph_hash import graph_content_hash
from reporails_cli.core.mapper.model_manifest import EMBEDDER_SUBDIR, get_models_path

# Bundled classification model file names, resolved to on-disk paths below.
# The axis-name aliases live in `bio_tagger._MULTISLOT_RENAME`, defined
# locally in that module — not restated here.
_ENC_A_NAME = "charge_encoder_encA.onnx"
_HEAD_A_NAME = "multislot_head_encA.onnx"
_ENC_B_NAME = "charge_encoder_encB.onnx"
_HEAD_B_NAME = "multislot_head_encB.onnx"


def _enc_a_path() -> Path:
    """Path to the bundled `_ENC_A_NAME` model file."""
    return get_models_path() / _ENC_A_NAME


def _head_a_path() -> Path:
    """Path to the bundled `_HEAD_A_NAME` model file."""
    return get_models_path() / _HEAD_A_NAME


def _enc_b_path() -> Path:
    """Path to the bundled `_ENC_B_NAME` model file."""
    return get_models_path() / _ENC_B_NAME


def _head_b_path() -> Path:
    """Path to the bundled `_HEAD_B_NAME` model file."""
    return get_models_path() / _HEAD_B_NAME


def multislot_available() -> bool:
    """True when onnxruntime + tokenizers import and all four model graphs exist."""
    have_libs = all(importlib.util.find_spec(m) is not None for m in ("onnxruntime", "tokenizers"))
    graphs = (_enc_a_path(), _head_a_path(), _enc_b_path(), _head_b_path())
    return have_libs and all(p.is_file() for p in graphs)


def multislot_fingerprint() -> str:
    """Cache-identity token for the classification models the mapper reads.

    Returns a content hash (see `graph_content_hash`) over the model files, so
    any change to those files invalidates the per-file atom cache and the
    whole-map identity cache. The hash is memoized on disk, so a repeat process
    pays no re-hash for an unchanged install. Returns ``"none"`` when a
    required file is missing.
    """
    paths = (
        _enc_a_path(),
        _head_a_path(),
        _enc_b_path(),
        _head_b_path(),
        get_models_path() / EMBEDDER_SUBDIR / "onnx" / "model.onnx",
        get_models_path() / EMBEDDER_SUBDIR / "tokenizer.json",
    )
    parts = []
    for path in paths:
        if not path.is_file():
            return "none"
        parts.append(graph_content_hash(path))
    return "|".join(parts)
