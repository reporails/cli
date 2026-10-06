"""Behavioral tests for the runtime model fetch, the resolver, and the ensure step.

The fetch downloads once into a persistent cache and is silent + offline on a
cache hit; a bad host, an HTML interstitial, or a checksum mismatch never leaves
an artifact behind; an incomplete cache repairs itself; the swap is safe under a
concurrent run. The resolver never downloads; `ensure_models_available` is the
one place that does, and `AILS_MODEL_OFFLINE` turns it off.

Network is always mocked — no test here reaches a real host.
"""

from __future__ import annotations

import hashlib
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from reporails_cli.core.mapper import model_fetch
from reporails_cli.core.mapper.model_fetch import ModelFetchError


class _Resp:
    def __init__(self, status_code: int, content: bytes = b"", headers: dict | None = None):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {"content-type": "application/octet-stream"}

    def iter_bytes(self, chunk_size: int = 1 << 20):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i : i + chunk_size]


class _FakeClient:
    """httpx.Client stand-in: streams per-asset bytes, or a scripted override.

    An override value may be a list of responses, served one per request.
    """

    def __init__(self, *, ok_bytes: bytes = b"MODELBYTES", raiser=None, overrides: dict | None = None):
        self.ok_bytes = ok_bytes
        self._raiser = raiser
        self._overrides = overrides or {}
        self.calls: list[str] = []
        self.headers: dict | None = None

    def body(self, rel: str) -> bytes:
        return self.ok_bytes + model_fetch.asset_name(rel).encode()

    @contextmanager
    def stream(self, method: str, url: str):
        self.calls.append(url)
        if self._raiser is not None:
            raise self._raiser
        asset = url.rsplit("/", 1)[-1]
        if asset in self._overrides:
            scripted = self._overrides[asset]
            yield scripted.pop(0) if isinstance(scripted, list) else scripted
            return
        yield _Resp(200, content=self.ok_bytes + asset.encode())

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *a) -> None:
        return None


def _use_fake(monkeypatch, client: _FakeClient) -> None:
    """Serve downloads from *client*, with digests pinned to what it serves."""

    def _client(headers=None):
        client.headers = headers
        return client

    monkeypatch.setattr(model_fetch, "_http_client", _client)
    pins = {rel: hashlib.sha256(client.body(rel)).hexdigest() for rel in model_fetch.REQUIRED_RELPATHS}
    monkeypatch.setattr(model_fetch, "FETCH_SHA256", pins)


def _cache_at(monkeypatch, root: Path) -> Path:
    monkeypatch.setattr(model_fetch, "cache_models_dir", lambda version=model_fetch.MODEL_VERSION: root)
    return root


def _populate(root: Path) -> None:
    """Create every fetched file under *root* with non-empty dummy bytes."""
    for rel in model_fetch.FETCH_RELPATHS:
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"x" + rel.encode())


# ─── ensure_models_present ────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cache_hit_skips_download(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    root.mkdir(parents=True)
    _populate(root)

    def _boom(*a, **k):
        raise AssertionError("download must not run on a cache hit")

    monkeypatch.setattr(model_fetch, "_download_all", _boom)

    assert model_fetch.ensure_models_present() == root


@pytest.mark.unit
@pytest.mark.subsys_map
def test_download_populates_and_passes_integrity(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)

    result = model_fetch.ensure_models_present()

    assert result == root
    assert model_fetch.models_present(root)
    # Every fetched file (functional set + licence) landed with the served bytes.
    for rel in model_fetch.FETCH_RELPATHS:
        assert (root / rel).read_bytes() == fake.body(rel)
    # One request per fetched file.
    assert len(fake.calls) == len(model_fetch.FETCH_RELPATHS)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_checksum_mismatch_rejected_and_cache_untouched(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    # The host serves different bytes than the pinned digest for one graph.
    tampered = model_fetch.asset_name("charge_encoder_encA.onnx")
    fake._overrides[tampered] = _Resp(200, content=b"TAMPERED")

    with pytest.raises(ModelFetchError, match="checksum"):
        model_fetch.ensure_models_present()

    assert not root.exists()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_html_interstitial_rejected_and_cache_untouched(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    html = _Resp(200, content=b"<!DOCTYPE html><html>login</html>", headers={"content-type": "text/html"})
    # First fetched asset comes back as an HTML page.
    first_asset = model_fetch.asset_name(model_fetch.FETCH_RELPATHS[0])
    fake = _FakeClient(overrides={first_asset: html})
    _use_fake(monkeypatch, fake)

    with pytest.raises(ModelFetchError, match="HTML"):
        model_fetch.ensure_models_present()

    # No partial artifact survives — the cache dir was never swapped into place.
    assert not root.exists()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_host_unreachable_empty_cache_raises_clear_error(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient(raiser=OSError("connection refused"))
    _use_fake(monkeypatch, fake)

    with pytest.raises(ModelFetchError) as exc:
        model_fetch.ensure_models_present()

    msg = str(exc.value)
    assert "AILS_MODEL_URL" in msg  # points at the override escape hatch
    assert "network" in msg.lower()
    assert not root.exists()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_incomplete_cache_is_repaired(tmp_path, monkeypatch):
    # A file of an installed set was deleted (cleanup, antivirus quarantine).
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    _populate(root)
    (root / "charge_encoder_encB.onnx").unlink()
    assert not model_fetch.models_present(root)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)

    assert model_fetch.ensure_models_present() == root

    assert model_fetch.models_present(root)
    assert (root / "charge_encoder_encB.onnx").read_bytes() == fake.body("charge_encoder_encB.onnx")


# ─── swap safety ──────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_swap_moves_staging_into_place(tmp_path):
    staging = tmp_path / "staging"
    _populate(staging)
    root = tmp_path / "models" / model_fetch.MODEL_VERSION
    root.parent.mkdir(parents=True)

    model_fetch._swap_into_place(staging, root)

    assert model_fetch.models_present(root)
    assert not staging.exists()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_swap_yields_to_concurrent_peer(tmp_path):
    # A peer run populated root first; our staging must be discarded, theirs kept.
    root = tmp_path / "models" / model_fetch.MODEL_VERSION
    _populate(root)
    (root / "two_encoder_contract.json").write_bytes(b"PEER-WON")

    staging = tmp_path / "staging"
    _populate(staging)
    (staging / "two_encoder_contract.json").write_bytes(b"OURS-LOST")

    model_fetch._swap_into_place(staging, root)

    # Peer's copy survives untouched.
    assert (root / "two_encoder_contract.json").read_bytes() == b"PEER-WON"


# ─── URL builder ──────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_env_override_wins_over_default_host(monkeypatch):
    monkeypatch.setenv("AILS_MODEL_URL", "https://cdn.example/models/")
    assert model_fetch._base_url(model_fetch.MODEL_VERSION) == "https://cdn.example/models"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_default_host_used_when_no_override(monkeypatch):
    monkeypatch.delenv("AILS_MODEL_URL", raising=False)
    # The dev script's variable does not redirect the runtime fetch.
    monkeypatch.setenv("AILS_MODEL_BUCKET_URL", "https://bucket.example/models")
    assert model_fetch._base_url("m9") == "https://models.reporails.com/m9"
    assert (
        model_fetch._remote_url(model_fetch._base_url("m1"), "sample/onnx/model.onnx")
        == "https://models.reporails.com/m1/sample__onnx__model.onnx"
    )


def _fetch_headers(tmp_path, monkeypatch) -> dict | None:
    """Run a real first fetch against a fake host; return the client headers it used."""
    _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    model_fetch.ensure_models_present()
    return fake.headers


@pytest.mark.unit
@pytest.mark.subsys_map
def test_api_key_sent_to_default_host(tmp_path, monkeypatch):
    monkeypatch.delenv("AILS_MODEL_URL", raising=False)
    monkeypatch.delenv("AILS_SERVER_URL", raising=False)
    monkeypatch.setenv("AILS_API_KEY", "rr_test_key")
    assert _fetch_headers(tmp_path, monkeypatch) == {"Authorization": "Bearer rr_test_key"}


@pytest.mark.unit
@pytest.mark.subsys_map
def test_api_key_never_sent_to_a_mirror(tmp_path, monkeypatch):
    monkeypatch.setenv("AILS_MODEL_URL", "https://mirror.example/models")
    monkeypatch.delenv("AILS_SERVER_URL", raising=False)
    monkeypatch.setenv("AILS_API_KEY", "rr_test_key")
    assert _fetch_headers(tmp_path, monkeypatch) == {}


@pytest.mark.unit
@pytest.mark.subsys_map
def test_key_for_another_server_not_sent(tmp_path, monkeypatch):
    # A key paired with a local/staging diagnostics server stays off the default model host.
    monkeypatch.delenv("AILS_MODEL_URL", raising=False)
    monkeypatch.setenv("AILS_SERVER_URL", "http://localhost:8001")
    monkeypatch.setenv("AILS_API_KEY", "rr_dev_key")
    assert _fetch_headers(tmp_path, monkeypatch) == {}


# ─── busy host ────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_busy_host_is_retried_after_retry_after(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    busy = _Resp(429, headers={"retry-after": "7"})
    fake = _FakeClient()
    fake._overrides = {"LICENSE-weights": [busy, _Resp(200, content=fake.body("LICENSE-weights"))]}
    _use_fake(monkeypatch, fake)
    waits: list[float] = []
    monkeypatch.setattr(model_fetch.time, "sleep", waits.append)

    assert model_fetch.ensure_models_present() == root

    assert waits == [7]
    assert model_fetch.models_present(root)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_busy_host_gives_up_after_bounded_attempts(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    fake._overrides = {"charge_encoder_encA.onnx": [_Resp(429, headers={"retry-after": "600"}) for _ in range(5)]}
    _use_fake(monkeypatch, fake)
    waits: list[float] = []
    monkeypatch.setattr(model_fetch.time, "sleep", waits.append)

    with pytest.raises(ModelFetchError, match="HTTP 429"):
        model_fetch.ensure_models_present()

    assert waits == [60] * (model_fetch._MAX_ATTEMPTS - 1)  # Retry-After capped
    assert not root.exists()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_asset_name_flattens_subtree():
    # A subtree path becomes a single flat asset key.
    assert model_fetch.asset_name("sample/onnx/model.onnx") == "sample__onnx__model.onnx"
    assert "/" not in model_fetch.asset_name("sample/onnx/model.onnx")
    # A root-level file is unchanged.
    assert model_fetch.asset_name("LICENSE-weights") == "LICENSE-weights"


# ─── the model-contract sidecar is downloaded and pinned, but not required ─


@pytest.mark.unit
@pytest.mark.subsys_map
def test_contract_file_is_not_fetched_required_or_pinned():
    # The routing sidecar is not part of the download, the
    # functional-presence set, or the pin table.
    assert "two_encoder_contract.json" not in model_fetch.FETCH_RELPATHS
    assert "two_encoder_contract.json" not in model_fetch.REQUIRED_RELPATHS
    assert "two_encoder_contract.json" not in model_fetch.GATED_FILES
    assert "two_encoder_contract.json" not in model_fetch.FETCH_SHA256


# ─── repair on a load failure (same-size corruption) ──────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repair_cache_redownloads_only_the_mismatched_file(tmp_path, monkeypatch):
    # tests/conftest.py defaults AILS_MODEL_OFFLINE=1 for the whole suite (never
    # hit the network by accident); this test exercises the online repair path.
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    model_fetch.ensure_models_present()
    # Corrupt one cached file in place, same size, wrong content — the
    # presence check (existence + non-zero size) does not catch this.
    good = (root / "charge_encoder_encA.onnx").read_bytes()
    (root / "charge_encoder_encA.onnx").write_bytes(bytes(b ^ 0xFF for b in good))
    assert model_fetch.models_present(root)  # presence check is blind to it
    fake.calls.clear()

    result = model_fetch.repair_cache()

    assert result == root
    assert (root / "charge_encoder_encA.onnx").read_bytes() == fake.body("charge_encoder_encA.onnx")
    # Every other pinned file was kept (hard-linked/copied), not re-streamed.
    # The licence files carry no pin, so they are always re-fetched on a repair,
    # independent of this fix — see LICENSE_FILES.
    corrupted_asset = model_fetch.asset_name("charge_encoder_encA.onnx")
    license_assets = {model_fetch.asset_name(f) for f in model_fetch.LICENSE_FILES}
    unexpected_calls = [
        c for c in fake.calls if not (c.endswith(corrupted_asset) or c.rsplit("/", 1)[-1] in license_assets)
    ]
    assert unexpected_calls == []
    assert any(c.endswith(corrupted_asset) for c in fake.calls)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repair_cache_refuses_to_download_when_offline(tmp_path, monkeypatch):
    """REGRESSION: `AILS_MODEL_OFFLINE` means never download — a corrupted file
    under offline mode must raise before touching the network, not attempt a
    repair download and only incidentally fail. Distinguishes an early offline
    short-circuit from the generic "download failed" path, which also happens
    to mention AILS_MODEL_OFFLINE in its hint text but reaches `_http_client` first."""
    monkeypatch.setenv("AILS_MODEL_OFFLINE", "1")
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    root.mkdir(parents=True)
    for rel in model_fetch.FETCH_RELPATHS:
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"corrupted-not-the-real-bytes")

    calls: list[object] = []

    def _track(*a, **k):
        calls.append((a, k))
        raise AssertionError("must not reach the network while AILS_MODEL_OFFLINE is set")

    monkeypatch.setattr(model_fetch, "_http_client", _track)

    with pytest.raises(ModelFetchError) as exc_info:
        model_fetch.repair_cache()

    assert calls == []  # the network layer was never reached
    message = str(exc_info.value)
    assert "AILS_MODEL_OFFLINE" in message
    assert "could not download" not in message.lower()  # not the generic network-failure text


# ─── cache_damaged: the direct on-disk check `reload_after_repair` gates on ─


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cache_damaged_true_for_a_missing_required_file(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    _populate(root)
    (root / "charge_encoder_encB.onnx").unlink()
    assert model_fetch.cache_damaged() is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cache_damaged_true_for_a_same_size_corrupted_file(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    model_fetch.ensure_models_present()
    good = (root / "charge_encoder_encA.onnx").read_bytes()
    (root / "charge_encoder_encA.onnx").write_bytes(bytes(b ^ 0xFF for b in good))

    assert model_fetch.cache_damaged() is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cache_damaged_false_when_every_pinned_file_matches(tmp_path, monkeypatch):
    _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    model_fetch.ensure_models_present()

    assert model_fetch.cache_damaged() is False


# ─── repair_cache re-verifies after the lock, skipping an already-fixed set ─


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repair_cache_skips_the_swap_when_already_valid_after_the_lock(tmp_path, monkeypatch):
    """REGRESSION: a forced repair must not rmtree/swap when every pinned file
    already matches its pin after the lock is taken — the shape of a peer
    (another thread or process) having just repaired the set while this call
    waited. `_download_all` (and its rmtree) must never run in that case."""
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    model_fetch.ensure_models_present()
    assert model_fetch.cache_damaged() is False  # nothing is actually wrong

    called = {"n": 0}
    real_download_all = model_fetch._download_all

    def _spy_download_all(*a, **k):
        called["n"] += 1
        return real_download_all(*a, **k)

    monkeypatch.setattr(model_fetch, "_download_all", _spy_download_all)

    result = model_fetch.repair_cache()

    assert result == root
    assert called["n"] == 0  # no download, no swap — the cache was already valid


@pytest.mark.unit
@pytest.mark.subsys_map
def test_two_threads_repairing_the_same_corruption_never_get_filenotfound(tmp_path, monkeypatch):
    """REGRESSION: a real two-thread race on the exact `repair_cache` path.
    Two encode-pool threads both discover the same same-size corrupted file
    and both call `repair_cache`. The first does the real repair while
    holding the fetch lock; the second, once unblocked, must re-verify and
    find the set already fixed rather than blindly rmtree+swap again — which
    used to open a window where the file did not exist and a concurrent
    retry saw `FileNotFoundError`."""
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    model_fetch.ensure_models_present()
    good = (root / "charge_encoder_encA.onnx").read_bytes()
    (root / "charge_encoder_encA.onnx").write_bytes(bytes(b ^ 0xFF for b in good))
    fake.calls.clear()

    # Gate the corrupted file's request so thread 1 is provably still holding
    # the fetch lock (mid-"download") when thread 2 starts and queues behind
    # it — the real shape of two encode-pool threads hitting the same
    # corrupted file back to back.
    thread1_holding = threading.Event()
    release_thread1 = threading.Event()
    orig_stream = fake.stream
    corrupted_asset = model_fetch.asset_name("charge_encoder_encA.onnx")

    @contextmanager
    def gated_stream(method, url):
        if url.endswith(corrupted_asset):
            thread1_holding.set()
            release_thread1.wait(timeout=5)
        with orig_stream(method, url) as resp:
            yield resp

    monkeypatch.setattr(fake, "stream", gated_stream)

    errors: list[BaseException] = []
    results: list[Path] = []

    def run():
        try:
            results.append(model_fetch.repair_cache())
        except BaseException as exc:
            errors.append(exc)

    t1 = threading.Thread(target=run)
    t2 = threading.Thread(target=run)
    t1.start()
    assert thread1_holding.wait(timeout=5)  # t1 is inside the download, holding the fetch lock
    t2.start()
    time.sleep(0.2)  # give t2 a real chance to queue on the fetch lock behind t1
    release_thread1.set()
    t1.join(timeout=5)
    t2.join(timeout=5)

    assert errors == []  # neither thread raised — in particular, no FileNotFoundError
    assert len(results) == 2
    assert (root / "charge_encoder_encA.onnx").read_bytes() == fake.body("charge_encoder_encA.onnx")
    # thread 2's repair found the set already valid after the lock and redownloaded nothing.
    redownloads = [c for c in fake.calls if c.endswith(corrupted_asset)]
    assert len(redownloads) == 1


# ─── resolver + ensure step ───────────────────────────────────────────


@pytest.fixture
def _bundled(monkeypatch):
    import reporails_cli.bundled as bundled

    monkeypatch.setattr(bundled, "_tree_present", None)
    return bundled


def _no_fetch(*a, **k):
    raise AssertionError("must not download")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_resolver_prefers_dev_tree(tmp_path, monkeypatch, _bundled):
    tree = tmp_path / "pkg" / "models"
    _populate(tree)
    monkeypatch.setattr(_bundled, "get_bundled_path", lambda: tmp_path / "pkg")
    monkeypatch.setattr(model_fetch, "ensure_models_present", _no_fetch)

    assert _bundled.get_models_path() == tree


@pytest.mark.unit
@pytest.mark.subsys_map
def test_resolver_never_downloads(tmp_path, monkeypatch, _bundled):
    # No dev tree and an empty cache: the resolver points at the cache, fetches nothing.
    monkeypatch.setattr(_bundled, "get_bundled_path", lambda: tmp_path / "empty")
    cache = _cache_at(monkeypatch, tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION)
    monkeypatch.setattr(model_fetch, "ensure_models_present", _no_fetch)

    assert _bundled.get_models_path() == cache


@pytest.mark.unit
@pytest.mark.subsys_map
def test_ensure_downloads_when_absent(tmp_path, monkeypatch, _bundled):
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    monkeypatch.setattr(_bundled, "get_bundled_path", lambda: tmp_path / "empty")
    root = _cache_at(monkeypatch, tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION)
    _use_fake(monkeypatch, _FakeClient())

    assert _bundled.ensure_models_available() == root
    assert model_fetch.models_present(root)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_ensure_offline_skips_download(tmp_path, monkeypatch, _bundled):
    monkeypatch.setenv("AILS_MODEL_OFFLINE", "1")
    monkeypatch.setattr(_bundled, "get_bundled_path", lambda: tmp_path / "empty")
    _cache_at(monkeypatch, tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION)
    monkeypatch.setattr(model_fetch, "ensure_models_present", _no_fetch)

    assert _bundled.ensure_models_available() is None


@pytest.mark.unit
@pytest.mark.subsys_map
def test_ensure_offline_uses_a_model_on_disk(tmp_path, monkeypatch, _bundled):
    monkeypatch.setenv("AILS_MODEL_OFFLINE", "1")
    monkeypatch.setattr(_bundled, "get_bundled_path", lambda: tmp_path / "empty")
    root = _cache_at(monkeypatch, tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION)
    _populate(root)
    pins = {rel: hashlib.sha256((root / rel).read_bytes()).hexdigest() for rel in model_fetch.REQUIRED_RELPATHS}
    monkeypatch.setattr(model_fetch, "FETCH_SHA256", pins)

    assert _bundled.ensure_models_available() == root


@pytest.mark.unit
@pytest.mark.subsys_map
def test_ensure_repairs_a_same_size_damaged_file_in_the_cache(tmp_path, monkeypatch, _bundled):
    """A cached file damaged at the same size is re-fetched when the set is made available."""
    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    monkeypatch.setattr(_bundled, "get_bundled_path", lambda: tmp_path / "empty")
    root = _cache_at(monkeypatch, tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    assert _bundled.ensure_models_available() == root
    good = (root / "charge_encoder_encA.onnx").read_bytes()
    (root / "charge_encoder_encA.onnx").write_bytes(bytes(b ^ 0xFF for b in good))

    assert _bundled.ensure_models_available() == root

    assert (root / "charge_encoder_encA.onnx").read_bytes() == good


@pytest.mark.unit
@pytest.mark.subsys_map
def test_ensure_rehashes_nothing_for_an_unchanged_cache(tmp_path, monkeypatch, _bundled):
    """A cached set whose files did not change is not hashed again by a later run."""
    from reporails_cli.core.mapper import bio_graphs

    monkeypatch.delenv("AILS_MODEL_OFFLINE", raising=False)
    monkeypatch.setattr(_bundled, "get_bundled_path", lambda: tmp_path / "empty")
    root = _cache_at(monkeypatch, tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION)
    _use_fake(monkeypatch, _FakeClient())
    _bundled.ensure_models_available()  # downloads
    _bundled.ensure_models_available()  # verifies the set once and records it
    bio_graphs._graph_hash_cache.clear()
    monkeypatch.setattr(bio_graphs, "_sidecar_data", None)
    calls: list[Path] = []
    monkeypatch.setattr(bio_graphs, "_hash_file_bytes", lambda p: calls.append(p) or "unused")

    assert _bundled.ensure_models_available() == root

    assert calls == []


@pytest.mark.unit
@pytest.mark.subsys_map
def test_ensure_offline_with_a_damaged_cache_raises_the_repair_error(tmp_path, monkeypatch, _bundled):
    """With `AILS_MODEL_OFFLINE` set, a damaged cached file is reported, not used silently."""
    monkeypatch.setenv("AILS_MODEL_OFFLINE", "1")
    monkeypatch.setattr(_bundled, "get_bundled_path", lambda: tmp_path / "empty")
    root = _cache_at(monkeypatch, tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION)
    _populate(root)

    with pytest.raises(ModelFetchError, match="damaged"):
        _bundled.ensure_models_available()


# ─── `ails check` entry ───────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_check_exits_2_when_the_model_cannot_be_fetched(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    import reporails_cli.bundled as bundled
    from reporails_cli.interfaces.cli.main import app

    def _fail():
        raise ModelFetchError("could not download the reporails model from https://host.example: refused")

    monkeypatch.setattr(bundled, "ensure_models_available", _fail)
    monkeypatch.setenv("AILS_CHECK_TIMEOUT_S", "0")  # no alarm left running in the test process
    (tmp_path / "CLAUDE.md").write_text("# Project\n\nRun `pytest` before committing.\n")

    result = CliRunner().invoke(app, ["check", str(tmp_path)])

    assert result.exit_code == 2
    assert "could not download the reporails model" in result.output


@pytest.mark.unit
@pytest.mark.subsys_map
def test_functional_file_without_a_pin_is_refused(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    pins = dict(model_fetch.FETCH_SHA256)
    del pins["multislot_head_encA.onnx"]
    monkeypatch.setattr(model_fetch, "FETCH_SHA256", pins)

    with pytest.raises(ModelFetchError, match="no pinned checksum"):
        model_fetch.ensure_models_present()

    assert not root.exists()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_stale_staging_from_a_killed_run_is_swept(tmp_path, monkeypatch):
    import os

    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    stale = root.parent / f".{model_fetch.MODEL_VERSION}.staging.dead"
    stale.mkdir(parents=True)
    (stale / "partial.onnx").write_bytes(b"x" * 10)
    old = stale.stat().st_mtime - model_fetch._STALE_STAGING_S - 60
    os.utime(stale, (old, old))
    _use_fake(monkeypatch, _FakeClient())

    model_fetch.ensure_models_present()

    assert not stale.exists()
    assert model_fetch.models_present(root)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_mcp_validate_reports_downloading_without_blocking(tmp_path, monkeypatch):
    import reporails_cli.bundled as bundled
    from reporails_cli.interfaces.mcp import tools

    monkeypatch.setattr(bundled, "_tree_present", None)
    monkeypatch.setattr(bundled, "get_bundled_path", lambda: tmp_path / "empty")
    _cache_at(monkeypatch, tmp_path / "cache" / "models" / model_fetch.MODEL_VERSION)
    monkeypatch.setattr(model_fetch, "ensure_models_present", _no_fetch)

    with model_fetch._FETCH_LOCK:  # another thread holds the first download
        result = tools.model_not_ready_error()

    assert result is not None
    assert result["error"] == "model_downloading"


# ─── cross-process lock ───────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_parallel_first_run_waits_for_the_peer_and_downloads_nothing(tmp_path, monkeypatch, capfd):
    # Another process holds the cache lock and completes the download; this run
    # must wait for it and then use the peer's set instead of downloading its own.
    import subprocess
    import sys
    import threading

    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    root.parent.mkdir(parents=True)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    monkeypatch.setattr(model_fetch, "_ANNOUNCE_AFTER_S", 0.1)
    peer = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys, time; from pathlib import Path; from filelock import FileLock;"
            "root = Path(sys.argv[1]); rels = sys.argv[2:];"
            "lock = FileLock(str(root.parent / ('.' + root.name + '.lock'))); lock.acquire();"
            "print('held', flush=True);"
            "time.sleep(1.0);"
            "[((root / r).parent.mkdir(parents=True, exist_ok=True), (root / r).write_bytes(b'peer')) for r in rels];"
            "lock.release()",
            str(root),
            *model_fetch.FETCH_RELPATHS,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert peer.stdout is not None and peer.stdout.readline().strip() == "held"

    result: list[Path] = []
    worker = threading.Thread(target=lambda: result.append(model_fetch.ensure_models_present()))
    worker.start()
    worker.join(timeout=30)
    peer.wait(timeout=30)

    assert result == [root]
    assert fake.calls == []  # the peer's set was used; nothing was downloaded here
    assert (root / "charge_encoder_encA.onnx").read_bytes() == b"peer"
    assert "Waiting for another reporails model download" in capfd.readouterr().err


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(sys.platform == "win32", reason="cross-process file-lock release timing differs on Windows")
def test_download_in_another_process_is_reported_in_progress(tmp_path, monkeypatch):
    import subprocess
    import sys

    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    root.parent.mkdir(parents=True)
    peer = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import sys, time; from filelock import FileLock;"
            "lock = FileLock(sys.argv[1]); lock.acquire(); print('held', flush=True); time.sleep(30)",
            str(root.parent / f".{model_fetch.MODEL_VERSION}.lock"),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert peer.stdout is not None and peer.stdout.readline().strip() == "held"
        assert model_fetch.download_in_progress()
    finally:
        peer.kill()
        peer.wait(timeout=10)
    assert not model_fetch.download_in_progress()


# ─── repair keeps valid files ─────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repair_downloads_only_missing_or_mismatched_files(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    for rel in model_fetch.FETCH_RELPATHS:
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(fake.body(rel))
    (root / "charge_encoder_encB.onnx").unlink()  # deleted
    (root / "multislot_head_encA.onnx").write_bytes(b"CORRUPTED")  # no longer matches its pin

    assert model_fetch.ensure_models_present() == root

    fetched = {url.rsplit("/", 1)[-1] for url in fake.calls}
    assert fetched == {"charge_encoder_encB.onnx", "multislot_head_encA.onnx", *model_fetch.LICENSE_FILES}
    for rel in model_fetch.FETCH_RELPATHS:
        assert (root / rel).read_bytes() == fake.body(rel)


# ─── old model versions ───────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fetch_keeps_the_previous_model_version_and_prunes_older(tmp_path, monkeypatch):
    import os

    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    parent = root.parent
    now = os.path.getmtime(tmp_path)
    for name, age in (("m-oldest", 300), ("m-previous", 100)):
        d = parent / name
        _populate(d)
        os.utime(d, (now - age, now - age))
    _use_fake(monkeypatch, _FakeClient())

    model_fetch.ensure_models_present()

    remaining = sorted(p.name for p in parent.iterdir() if not p.name.startswith("."))
    assert remaining == sorted([model_fetch.MODEL_VERSION, "m-previous"])


# ─── `ails check` fetches only once there is something to map ─────────


def _record_ensure(monkeypatch) -> list[float]:
    """Replace the ensure step with one that records the wall-clock timer left while it runs."""
    import signal

    import reporails_cli.bundled as bundled

    seen: list[float] = []

    def _ensure():
        seen.append(signal.getitimer(signal.ITIMER_REAL)[0])
        return None

    monkeypatch.setattr(bundled, "ensure_models_available", _ensure)
    monkeypatch.setenv("AILS_CHECK_TIMEOUT_S", "0")  # no alarm left running in the test process
    return seen


@pytest.mark.unit
@pytest.mark.subsys_map
def test_check_on_a_mistyped_path_does_not_fetch_the_model(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from reporails_cli.interfaces.cli.main import app

    seen = _record_ensure(monkeypatch)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, ["check", str(tmp_path / "CLAUDE.mdd")])

    assert result.exit_code == 2
    assert "Path not found" in result.output
    assert seen == []


@pytest.mark.unit
@pytest.mark.subsys_map
def test_check_with_no_instruction_files_does_not_fetch_the_model(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from reporails_cli.interfaces.cli.main import app

    seen = _record_ensure(monkeypatch)
    (tmp_path / "README.md").write_text("# Not an instruction file\n")
    monkeypatch.chdir(tmp_path)

    CliRunner().invoke(app, ["check", str(tmp_path)])

    assert seen == []


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(__import__("sys").platform == "win32", reason="no SIGALRM timer on Windows")
def test_model_fetch_runs_with_the_check_timer_paused(tmp_path, monkeypatch):
    import signal

    from reporails_cli.interfaces.cli import check_support

    seen = _record_ensure(monkeypatch)
    monkeypatch.setenv("AILS_CHECK_TIMEOUT_S", "600")
    check_support._arm_check_timeout()
    try:
        check_support._ensure_model_or_exit()
        left_after = signal.getitimer(signal.ITIMER_REAL)[0]
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)

    assert seen == [0.0]  # no wall-clock limit is running while the model downloads
    assert 0 < left_after <= 600  # and the limit is back afterwards


def _flock_failing_with(monkeypatch, err: int) -> None:
    """Make every exclusive flock fail with *err*, as on a filesystem without file locking."""
    import fcntl

    real = fcntl.flock

    def _flock(fd, op):
        if op & fcntl.LOCK_UN:
            return real(fd, op)
        raise OSError(err, "file locking not available")

    monkeypatch.setattr(fcntl, "flock", _flock)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(__import__("sys").platform == "win32", reason="POSIX file locking")
@pytest.mark.parametrize("err", ["ENOSYS", "ENOLCK"])
def test_fetch_works_where_file_locking_is_unsupported(tmp_path, monkeypatch, recwarn, err):
    # A home directory on a filesystem without file locking (ENOSYS), or on a
    # network mount with locking disabled (ENOLCK), still downloads the model and
    # prints no warning.
    import errno

    _flock_failing_with(monkeypatch, getattr(errno, err))
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    _use_fake(monkeypatch, _FakeClient())

    assert model_fetch.ensure_models_present() == root
    assert model_fetch.models_present(root)
    assert not model_fetch.download_in_progress()
    assert [str(w.message) for w in recwarn] == []


def _hold_lock_in_thread(lock_path: Path, *, hold_s: float, grow: Path | None = None, grow_every: float = 0.05):
    """Hold the cache lock from a separate lock handle for *hold_s*; optionally grow *grow* every *grow_every* s."""
    import threading

    held = threading.Event()

    def _run():
        holder = model_fetch._file_lock_class()(str(lock_path))
        with holder:
            held.set()
            deadline = time.monotonic() + hold_s
            while time.monotonic() < deadline:
                if grow is not None:
                    with grow.open("ab") as f:
                        f.write(b"x" * 1024)
                time.sleep(grow_every)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    assert held.wait(timeout=10)
    return t


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_momentary_lock_holder_prints_no_waiting_line(tmp_path, monkeypatch, capfd):
    # A status check holds the lock for a moment; a run starting then must not
    # announce that it is waiting for another download.
    cache_dir = tmp_path / "models"
    cache_dir.mkdir()
    lock_path = cache_dir / f".{model_fetch.MODEL_VERSION}.lock"
    t = _hold_lock_in_thread(lock_path, hold_s=0.3)
    lock = model_fetch._file_lock_class()(str(lock_path))
    try:
        assert model_fetch._acquire_file_lock(lock, cache_dir, model_fetch.MODEL_VERSION)
    finally:
        lock.release()
        t.join()
    assert "Waiting" not in capfd.readouterr().err


@pytest.mark.unit
@pytest.mark.subsys_map
def test_waits_as_long_as_the_other_download_makes_progress(tmp_path, monkeypatch, capfd):
    # On a slow link the other download outlasts the no-progress limit several
    # times over, growing in bursts with quiet polls between them; this run keeps
    # waiting because each burst restarts the no-progress limit.
    monkeypatch.setattr(model_fetch, "_ANNOUNCE_AFTER_S", 0.05)
    monkeypatch.setattr(model_fetch, "_WAIT_POLL_S", 0.05)
    monkeypatch.setattr(model_fetch, "_STALL_S", 0.4)
    cache_dir = tmp_path / "models"
    staging = cache_dir / f".{model_fetch.MODEL_VERSION}.staging.peer"
    staging.mkdir(parents=True)
    lock_path = cache_dir / f".{model_fetch.MODEL_VERSION}.lock"
    t = _hold_lock_in_thread(lock_path, hold_s=1.5, grow=staging / "charge_encoder_encA.onnx", grow_every=0.25)
    lock = model_fetch._file_lock_class()(str(lock_path))
    try:
        assert model_fetch._acquire_file_lock(lock, cache_dir, model_fetch.MODEL_VERSION)
    finally:
        lock.release()
        t.join()
    err = capfd.readouterr().err
    assert "Waiting for another reporails model download" in err
    assert "no progress" not in err


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_stalled_download_elsewhere_does_not_block_this_run(tmp_path, monkeypatch, capfd):
    # Another process holds the lock but its download no longer grows: this run
    # stops waiting and downloads the model itself instead of failing.
    monkeypatch.setattr(model_fetch, "_ANNOUNCE_AFTER_S", 0.05)
    monkeypatch.setattr(model_fetch, "_WAIT_POLL_S", 0.05)
    monkeypatch.setattr(model_fetch, "_STALL_S", 0.3)
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    root.parent.mkdir(parents=True)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    t = _hold_lock_in_thread(root.parent / f".{model_fetch.MODEL_VERSION}.lock", hold_s=3.0)
    try:
        assert model_fetch.ensure_models_present() == root
    finally:
        t.join()
    assert model_fetch.models_present(root)
    assert len(fake.calls) == len(model_fetch.FETCH_RELPATHS)
    assert "made no progress" in capfd.readouterr().err


@pytest.mark.unit
@pytest.mark.subsys_map
def test_waiting_stops_once_another_run_has_put_the_model_in_place(tmp_path, monkeypatch, capfd):
    # A stuck run still holds the lock, but another run has meanwhile put the
    # model in place: this run stops waiting at once and uses it.
    import threading

    monkeypatch.setattr(model_fetch, "_ANNOUNCE_AFTER_S", 0.05)
    monkeypatch.setattr(model_fetch, "_WAIT_POLL_S", 0.05)
    monkeypatch.setattr(model_fetch, "_STALL_S", 5.0)
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    root.parent.mkdir(parents=True)
    fake = _FakeClient()
    _use_fake(monkeypatch, fake)
    t = _hold_lock_in_thread(root.parent / f".{model_fetch.MODEL_VERSION}.lock", hold_s=3.0)
    threading.Timer(0.3, _populate, args=(root,)).start()
    start = time.monotonic()
    try:
        assert model_fetch.ensure_models_present() == root
        elapsed = time.monotonic() - start
    finally:
        t.join()
    assert elapsed < 1.5  # not held until the stuck run lets go
    assert fake.calls == []
    assert "no progress" not in capfd.readouterr().err


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.skipif(
    __import__("sys").platform == "win32" or __import__("os").geteuid() == 0,
    reason="POSIX permissions; root ignores them",
)
def test_an_unwritable_model_cache_is_reported_as_such(tmp_path, monkeypatch):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    root.parent.mkdir(parents=True)
    _use_fake(monkeypatch, _FakeClient())
    root.parent.chmod(0o555)
    try:
        with pytest.raises(ModelFetchError) as exc:
            model_fetch.ensure_models_present()
    finally:
        root.parent.chmod(0o755)
    assert "could not write the model cache" in str(exc.value)
    assert "network" not in str(exc.value).lower()


# ─── GitHub Actions ───────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(("env", "shown"), [("true", True), (None, False)])
def test_download_in_github_actions_points_at_the_ci_cache(tmp_path, monkeypatch, capfd, env, shown):
    if env is None:
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    else:
        monkeypatch.setenv("GITHUB_ACTIONS", env)
    _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    _use_fake(monkeypatch, _FakeClient())

    model_fetch.ensure_models_present()

    err = capfd.readouterr().err
    assert err.count("docs/configuration.md#caching-the-model-in-ci") == (1 if shown else 0)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cached_model_in_github_actions_prints_nothing(tmp_path, monkeypatch, capfd):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    _populate(root)

    model_fetch.ensure_models_present()

    assert capfd.readouterr().err == ""


# ─── licence files travel with the model set ──────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("name", model_fetch.LICENSE_FILES)
def test_a_missing_licence_file_fails_the_whole_fetch(tmp_path, monkeypatch, name):
    root = _cache_at(monkeypatch, tmp_path / "models" / model_fetch.MODEL_VERSION)
    fake = _FakeClient()
    fake._overrides = {model_fetch.asset_name(name): _Resp(404)}
    _use_fake(monkeypatch, fake)

    with pytest.raises(ModelFetchError, match="HTTP 404"):
        model_fetch.ensure_models_present()

    assert not root.exists()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_licence_names_agree_across_fetch_manifest_package_metadata_and_release_check():
    import re
    import tomllib

    repo = Path(__file__).resolve().parents[2]
    metadata = tomllib.loads((repo / "pyproject.toml").read_text(encoding="utf-8"))["project"]["license-files"]
    release = (repo / ".github" / "workflows" / "release-wheel.yml").read_text(encoding="utf-8")
    checked = re.search(r"for name in \(([^)]*)\):", release)
    assert checked is not None
    release_names = re.findall(r"'([^']+)'", checked.group(1))

    assert set(model_fetch.LICENSE_FILES) <= set(metadata)
    assert set(metadata) - set(model_fetch.LICENSE_FILES) == {"LICENSE"}
    assert tuple(release_names) == model_fetch.LICENSE_FILES
    for name in metadata:
        assert (repo / name).is_file()
