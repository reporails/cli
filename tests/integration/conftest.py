"""Shared fixtures for the integration tier."""

from __future__ import annotations

import pytest


@pytest.fixture
def deterministic_ort(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the ONNX intra-op thread count to 1 and drop any cached charge encoder.

    A real-model byte-identity comparison (in-process vs sharded / per-file vs
    batched) only holds at a FIXED intra-op thread count: ONNX intra-op parallelism
    reorders float reductions, so a session another test cached at intra_op>1 (e.g.
    a run that set ``AILS_MAP_ENCODE_WORKERS=1``, which drives intra-op to the core
    count) would diverge from the shard workers, which pin ``AILS_ORT_THREADS=1``.
    Pinning here and clearing the cached encoders makes the in-process arm rebuild at
    the same single-threaded intra-op the workers use, so the comparison is not at the
    mercy of test ordering. Production is unaffected — the default map path already
    runs the encoders single intra-op (the encode thread pool carries the parallelism).
    """
    monkeypatch.setenv("AILS_ORT_THREADS", "1")
    from tests.fake_models import reset_models

    def _reset() -> None:
        # The embedder is a process-wide singleton created once at whatever intra-op
        # the first access set; drop it so it reloads single intra-op too.
        reset_models()

    _reset()
    yield
    _reset()
