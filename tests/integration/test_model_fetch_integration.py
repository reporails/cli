"""Integration seam: the model loads end-to-end from a freshly fetched cache.

This drives the real composed path — resolver miss → one-time fetch → atomic
swap → real ONNX load from the cache — with the host mocked to serve the real
model bytes. It reddens if the resolver stops routing a lean install to the
cache, if the fetch leaves the cache unloadable, or if a cache hit is not silent
and offline on the second run.

Marked ``slow`` + ``requires_model``: it needs the real model files present in
the dev tree (the mock host serves them) and loads a real ONNX graph.
"""

from __future__ import annotations

import functools
from contextlib import contextmanager
from pathlib import Path

import pytest

from reporails_cli.core.mapper import model_fetch, model_manifest
from tests.fake_models import no_fetch


def _real_models_root() -> Path:
    # tests/integration/ -> repo root -> src/reporails_cli/bundled/models
    return Path(__file__).resolve().parents[2] / "src" / "reporails_cli" / "bundled" / "models"


class _Resp:
    def __init__(self, status: int, content: bytes):
        self.status = status
        self.content = content

    def header(self, name: str) -> str:
        return "application/octet-stream" if name == "content-type" else ""

    def chunks(self, size: int = 1 << 20):
        for i in range(0, len(self.content), size):
            yield self.content[i : i + size]


class _RealServingClient:
    """Mock host that serves each requested asset from the real dev tree."""

    def __init__(self, real_root: Path, calls: list[str]):
        self._root = real_root
        self._calls = calls

    @contextmanager
    def __call__(self, url: str, *, headers, timeout: float):
        self._calls.append(url)
        rel = url.rsplit("/", 1)[-1].replace("__", "/")
        source = self._root / rel
        # A dev tree holds the model files; the licence texts ship with the release host only.
        body = source.read_bytes() if source.is_file() or rel not in model_manifest.LICENSE_FILES else b"licence text"
        yield _Resp(200, body)


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.requires_model
@pytest.mark.subsys_map
def test_first_use_fetches_then_loads_from_cache(tmp_path, monkeypatch):
    real_root = _real_models_root()
    if not model_fetch.models_present(real_root):
        pytest.skip("real model files not present in the dev tree")

    from reporails_cli.core.mapper import model_store as bundled

    # Route the resolver away from the dev tree so it must use the cache.
    empty_pkg = tmp_path / "pkg"
    empty_pkg.mkdir()
    monkeypatch.setattr(model_manifest, "get_bundled_path", lambda: empty_pkg)
    monkeypatch.setattr(
        model_manifest,
        "in_package_tree_present",
        functools.cache(model_manifest.in_package_tree_present.__wrapped__),
    )
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    monkeypatch.delenv("AILS_OFFLINE", raising=False)

    cache_root = tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION
    monkeypatch.setattr(model_fetch, "cache_models_dir", lambda version=model_fetch.MODEL_VERSION: cache_root)
    monkeypatch.setattr(model_manifest, "cache_models_dir", lambda version=model_manifest.MODEL_VERSION: cache_root)

    calls: list[str] = []
    host = _RealServingClient(real_root, calls)

    # First use: the tree is absent, the ensure step fetches, the cache is populated.
    resolved = bundled.ensure_models_available(host)
    assert resolved == cache_root
    assert model_fetch.models_present(cache_root)
    assert len(calls) == len(model_fetch.FETCH_RELPATHS)

    # The embedder loads from the cache and produces a real embedding.
    from reporails_cli.core.mapper.onnx_embedder import OnnxEmbedder

    emb = OnnxEmbedder(no_fetch).encode(["a short instruction line"])
    assert emb.shape == (1, 384)

    # Second run is silent + offline: make the host unreachable — a cache hit
    # must not touch it.

    def _no_host(url, *, headers, timeout):
        raise AssertionError("second run must not hit the host")

    assert bundled.ensure_models_available(_no_host) == cache_root
    assert model_manifest.get_models_path() == cache_root
    assert OnnxEmbedder(no_fetch).encode(["another line"]).shape == (1, 384)
