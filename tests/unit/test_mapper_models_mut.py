"""Mutation-killing behavioral tests for core/mapper/models.py survivors.

Covers the lazy `.st` double-checked-lock `is None` gates and the `get_models`
singleton `is None` gate. Each assertion reddens when the identity operator
flips (verified against the mutation probe). The embedder load is stubbed so no
real model is instantiated.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from reporails_cli.core.mapper import models as models_mod
from reporails_cli.core.mapper.models import Models, get_models


# --- Models.st: double-checked-lock load gates (L31/L33) ------------------
@pytest.mark.unit
@pytest.mark.subsys_map
def test_st_loads_embedder_on_first_access() -> None:
    handle = Models()
    sentinel = object()
    with patch(
        "reporails_cli.core.mapper.onnx_embedder.OnnxEmbedder",
        return_value=sentinel,
    ):
        loaded = handle.st
    # `is None`->`is not None` on either the outer or inner guard skips the load
    # and returns the still-unset (None) handle instead of the loaded embedder.
    assert loaded is sentinel


# --- get_models: singleton creation gate (L65) ----------------------------
@pytest.mark.unit
@pytest.mark.subsys_map
def test_get_models_creates_singleton_when_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(models_mod, "_models", None)
    result = get_models()
    # `is None`->`is not None` skips creation and returns None.
    assert result is not None
    assert get_models() is result  # subsequent calls reuse the singleton
