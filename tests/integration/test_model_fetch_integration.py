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

from contextlib import contextmanager
from pathlib import Path

import pytest

from reporails_cli.core.mapper import model_fetch


def _real_models_root() -> Path:
    # tests/integration/ -> repo root -> src/reporails_cli/bundled/models
    return Path(__file__).resolve().parents[2] / "src" / "reporails_cli" / "bundled" / "models"


class _Resp:
    def __init__(self, status_code: int, content: bytes):
        self.status_code = status_code
        self.content = content
        self.headers = {"content-type": "application/octet-stream"}

    def iter_bytes(self, chunk_size: int = 1 << 20):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i : i + chunk_size]


class _RealServingClient:
    """Mock host that serves each requested asset from the real dev tree."""

    def __init__(self, real_root: Path, calls: list[str]):
        self._root = real_root
        self._calls = calls

    @contextmanager
    def stream(self, method: str, url: str):
        self._calls.append(url)
        rel = url.rsplit("/", 1)[-1].replace("__", "/")
        yield _Resp(200, (self._root / rel).read_bytes())

    def __enter__(self) -> _RealServingClient:
        return self

    def __exit__(self, *a) -> None:
        return None


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.requires_model
@pytest.mark.subsys_map
def test_first_use_fetches_then_loads_from_cache(tmp_path, monkeypatch):
    real_root = _real_models_root()
    if not model_fetch.models_present(real_root):
        pytest.skip("real model files not present in the dev tree")

    import reporails_cli.bundled as bundled

    # Route the resolver away from the dev tree so it must use the cache.
    empty_pkg = tmp_path / "pkg"
    empty_pkg.mkdir()
    monkeypatch.setattr(bundled, "get_bundled_path", lambda: empty_pkg)
    monkeypatch.setattr(bundled, "_tree_present", None)
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)

    cache_root = tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION
    monkeypatch.setattr(model_fetch, "cache_models_dir", lambda version=model_fetch.MODEL_VERSION: cache_root)

    calls: list[str] = []
    monkeypatch.setattr(model_fetch, "_http_client", lambda headers=None: _RealServingClient(real_root, calls))

    # First use: the tree is absent, the ensure step fetches, the cache is populated.
    resolved = bundled.ensure_models_available()
    assert resolved == cache_root
    assert model_fetch.models_present(cache_root)
    assert len(calls) == len(model_fetch.FETCH_RELPATHS)

    # The embedder loads from the cache and produces a real embedding.
    from reporails_cli.core.mapper.onnx_embedder import OnnxEmbedder

    emb = OnnxEmbedder().encode(["a short instruction line"])
    assert emb.shape == (1, 384)

    # Second run is silent + offline: make the host unreachable — a cache hit
    # must not touch it.

    def _no_host(headers=None):
        raise AssertionError("second run must not hit the host")

    monkeypatch.setattr(model_fetch, "_http_client", _no_host)
    assert bundled.ensure_models_available() == cache_root
    assert bundled.get_models_path() == cache_root
    assert OnnxEmbedder().encode(["another line"]).shape == (1, 384)
