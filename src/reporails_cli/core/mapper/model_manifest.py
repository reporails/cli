"""What the model set is and where it lives on disk, free of any network code.

The manifest (model version, required files, pinned digests) is the single source of truth
for WHAT ships; ``get_models_path`` resolves WHERE it is read from. ``model_fetch`` downloads
into the cache directory defined here and ``model_store`` repairs it.

The model directory is the in-package tree ``bundled/models/`` when populated (a dev
checkout or a fat build), otherwise the persistent user cache that ``model_fetch``
fills once on first use.
"""

from __future__ import annotations

import functools
from pathlib import Path

from reporails_cli.bundled import get_bundled_path
from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir


class ModelFetchError(RuntimeError):
    """Raised when the model set cannot be fetched or verified."""


# Model-set identity, independent of the CLI version. Bump to ship a new
# encoder set: the runtime fetches into a fresh cache dir. After a fetch the
# cache keeps the new set and the most recent other one (a downgrade by one
# model version still finds its cache); older sets are removed.
MODEL_VERSION = "m1"

# ─── Manifest (single source of truth for WHAT ships) ─────────────────

# The embedder subtree, mirrored from the current ``bundled/models/`` layout. Only the
# model graph and the self-contained ``tokenizer.json`` are read at runtime; the other
# metadata files that sit beside them in the source layout are never read, so they are
# excluded from the fetch.
EMBEDDER_SUBDIR = "minilm-l6-v2"
EMBEDDER_FILES: tuple[str, ...] = (
    "onnx/model.onnx",
    "tokenizer.json",
)

# The classifier files, at the models root.
GATED_FILES: tuple[str, ...] = (
    "charge_encoder_encA.onnx",
    "charge_encoder_encB.onnx",
    "multislot_head_encA.onnx",
    "multislot_head_encB.onnx",
)

# The licence files travel with the model set: a file pulled from a user's cache carries its own
# grant (the model licence, the third-party notice and the Apache-2.0 text that notice refers to).
# The fetch is strict about them — a licence file the host cannot serve fails the whole fetch, so
# no weight reaches a cache without its grant. They are not part of the functional present-check
# below, because loading the model does not read them.
LICENSE_FILES: tuple[str, ...] = ("LICENSE-weights", "NOTICE", "LICENSE-APACHE-2.0")


def _required_relpaths() -> tuple[str, ...]:
    """Functional files that must all be present for the model to load."""
    return GATED_FILES + tuple(f"{EMBEDDER_SUBDIR}/{f}" for f in EMBEDDER_FILES)


# Everything the resolver requires (functional) vs. everything fetched.
REQUIRED_RELPATHS: tuple[str, ...] = _required_relpaths()
FETCH_RELPATHS: tuple[str, ...] = (*REQUIRED_RELPATHS, *LICENSE_FILES)

# Pinned sha256 of every functional file for ``MODEL_VERSION``. A download whose
# digest differs is rejected before it can enter the cache. Regenerate these
# together with a ``MODEL_VERSION`` bump; the published set must match byte for byte.
FETCH_SHA256: dict[str, str] = {
    "charge_encoder_encA.onnx": "b0003d88d3073bbd319d257b2c6048366c862f7fcfe562a9dd016fdfc0380a3d",
    "charge_encoder_encB.onnx": "e60c2835dbfe7ba19ab6b8d8445bd03944edc1db270e5b519d1e77c820b526c3",
    "multislot_head_encA.onnx": "a843c33ba1305801d11fb9ded04dc93ea4408c0aee912946dc9596b9aa8b4a62",
    "multislot_head_encB.onnx": "374d906000690083c1a991d8c5df3e614ff7d855d0eaaa112a57385aec852b63",
    "minilm-l6-v2/onnx/model.onnx": "759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e",
    "minilm-l6-v2/tokenizer.json": "da0e79933b9ed51798a3ae27893d3c5fa4a201126cef75586296df9b4d2c62a0",
}


def models_present(root: Path, relpaths: tuple[str, ...] = REQUIRED_RELPATHS) -> bool:
    """Whether every file in *relpaths* (default: the functional set) exists and is non-empty under *root*."""
    for rel in relpaths:
        f = root / rel
        try:
            if not f.is_file() or f.stat().st_size == 0:
                return False
        except OSError:
            return False
    return True


def cache_models_dir(version: str = MODEL_VERSION) -> Path:
    """The persistent cache dir for a model version: ``~/.reporails/cache/models/<version>/``."""
    return get_global_cache_dir() / "models" / version


@functools.cache
def in_package_tree_present() -> bool:
    """Whether the in-package model tree is populated, checked once per process."""
    return models_present(get_bundled_path() / "models")


def get_models_path() -> Path:
    """Resolve the ML model directory. Never downloads.

    Resolution order:

    1. The in-package tree ``bundled/models/`` when populated — a dev checkout
       or a fat build serves the files straight from the package.
    2. Otherwise the persistent user cache
       ``~/.reporails/cache/models/<MODEL_VERSION>/``, which holds the set once
       ``ensure_models_available`` has fetched it. Until then its files are
       absent, and consumers see the model as unavailable.

    See ``core/mapper/onnx_embedder.py`` / ``core/mapper/bio_graphs.py`` for the
    consumers.
    """
    if in_package_tree_present():
        return get_bundled_path() / "models"
    return cache_models_dir(MODEL_VERSION)
