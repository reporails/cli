"""Mutation-killing behavioral tests for core/mapper/models.py survivors.

Covers the lazy `.st` double-checked-lock `is None` gates and the `charge_encoders` and
`head_session` load gates. Each assertion reddens when the identity operator
flips (verified against the mutation probe). The embedder load is stubbed so no
real model is instantiated.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from tests.fake_models import fresh_models


# --- Models.st: double-checked-lock load gates (L31/L33) ------------------
@pytest.mark.unit
@pytest.mark.subsys_map
def test_st_loads_embedder_on_first_access() -> None:
    handle = fresh_models()
    sentinel = object()
    with patch(
        "reporails_cli.core.mapper.onnx_embedder.OnnxEmbedder",
        return_value=sentinel,
    ):
        loaded = handle.st
    # `is None`->`is not None` on either the outer or inner guard skips the load
    # and returns the still-unset (None) handle instead of the loaded embedder.
    assert loaded is sentinel


# --- charge_encoders / head_session: load once, reuse ----------------------
@pytest.mark.unit
@pytest.mark.subsys_map
def test_charge_encoders_load_once_and_are_reused() -> None:
    handle = fresh_models()
    built: list[str] = []

    def fake_encoder(path):
        built.append(str(path))
        return object()

    with patch("reporails_cli.core.mapper.bio_tagger._BioEncoder", side_effect=fake_encoder):
        first = handle.charge_encoders()
        second = handle.charge_encoders()
    assert first is second
    assert len(built) == 2  # one encoder per pass, built once


@pytest.mark.unit
@pytest.mark.subsys_map
def test_head_session_is_built_once_per_head() -> None:
    handle = fresh_models()
    built: list[str] = []

    def fake_build(path: str) -> object:
        built.append(path)
        return object()

    with patch("reporails_cli.core.mapper.bio_tagger._build_head_session", side_effect=fake_build):
        a1 = handle.head_session(Path("/heads/a.onnx"))
        a2 = handle.head_session(Path("/heads/a.onnx"))
        b = handle.head_session(Path("/heads/b.onnx"))
    assert a1 is a2
    assert a1 is not b
    assert built == [str(Path("/heads/a.onnx")), str(Path("/heads/b.onnx"))]
