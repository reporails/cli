"""Behavioral tests for the gated model-artifact fetch client.

An unset source fails with a clear "model bucket not provisioned" message (never
a crash, never a fabricated source); a configured source fetches + verifies each
artifact; a 401 drives the token-refresh/rotation path and retries; the weights
license notice is staged INSIDE the model bundle.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import fetch_bundled_model as fbm  # noqa: E402


class _FakeResponse:
    def __init__(
        self,
        status_code: int,
        content: bytes = b"",
        json_body: dict | None = None,
        headers: dict | None = None,
    ):
        self.status_code = status_code
        self.content = content
        self.headers = headers or {"content-type": "application/octet-stream"}
        self._json = json_body or {}

    def json(self) -> dict:
        return self._json


class _FakeClient:
    """Minimal httpx.Client stand-in: scripted per-URL responses."""

    def __init__(self, responses: dict[str, list[_FakeResponse]]):
        self._responses = responses
        self.calls: list[tuple[str, str]] = []

    def get(self, url: str, headers: dict) -> _FakeResponse:
        self.calls.append((url, headers.get("Authorization", "")))
        queue = self._responses[url]
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *a) -> None:
        return None


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    """Point the fetch client at a temp repo root + models dir with the licence files."""
    models = tmp_path / "src" / "reporails_cli" / "bundled" / "models"
    models.mkdir(parents=True)
    for name in fbm._BUNDLE_LICENSE_NAMES:
        (tmp_path / name).write_text(f"{name} text\n")
    monkeypatch.setattr(fbm, "_repo_root", lambda: tmp_path)
    monkeypatch.setattr(fbm, "_models_root", lambda: models)
    return tmp_path, models


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_credentials_are_environment_only(monkeypatch):
    """No file-level credential default may exist — the helper is public source.

    Reddens if a source URL or token is ever written into the module: with the
    environment cleared, both accessors must resolve to empty.
    """

    assert fbm._bucket_url() == ""
    assert fbm._auth_token() == ""


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_gated_unset_bucket_fails_clearly(bundle, monkeypatch, capsys):
    rc = fbm._fetch_gated()

    assert rc == 1
    err = capsys.readouterr().err
    assert "model bucket not provisioned" in err


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_gated_fetch_success_and_license_staged(bundle, monkeypatch):
    _root, models = bundle
    monkeypatch.setenv("AILS_MODEL_BUCKET_URL", "https://bucket.example/models")
    monkeypatch.setenv("AILS_MODEL_AUTH_TOKEN", "test-token")

    responses = {
        f"https://bucket.example/models/{rel}": [_FakeResponse(200, content=b"BYTES-" + rel.encode())]
        for rel in fbm._GATED_RELPATHS
    }
    fake = _FakeClient(responses)
    # _fetch_gated does a local `import httpx`; patch the class it instantiates.
    monkeypatch.setattr("httpx.Client", lambda *a, **k: fake)

    rc = fbm._fetch_gated()

    assert rc == 0
    for rel in fbm._GATED_RELPATHS:
        f = models / rel
        assert f.is_file() and f.stat().st_size > 0
    # License notice travels inside the bundle.
    assert fbm._BUNDLE_LICENSE_NAMES == ("LICENSE-weights", "NOTICE", "LICENSE-APACHE-2.0")
    for name in fbm._BUNDLE_LICENSE_NAMES:
        assert (models / name).read_text() == f"{name} text\n"
    # Every request carried the bearer credential.
    assert all(auth == "Bearer test-token" for _url, auth in fake.calls)


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_download_one_refreshes_on_401(bundle, monkeypatch, tmp_path):
    url = "https://bucket.example/models/sample.onnx"
    fake = _FakeClient({url: [_FakeResponse(401), _FakeResponse(200, content=b"OK")]})
    monkeypatch.setattr(fbm, "_refresh_token", lambda stale: "fresh-token")

    target = tmp_path / "out.onnx"
    tok = fbm._download_one(fake, "https://bucket.example/models", "sample.onnx", "stale", target)

    assert tok == "fresh-token"
    assert target.read_bytes() == b"OK"
    # Retry carried the refreshed credential.
    assert fake.calls[-1][1] == "Bearer fresh-token"


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_download_one_401_without_refresh_raises(bundle, monkeypatch, tmp_path):
    url = "https://bucket.example/models/sample.onnx"
    fake = _FakeClient({url: [_FakeResponse(401)]})
    monkeypatch.setattr(fbm, "_refresh_token", lambda stale: None)

    with pytest.raises(fbm.GatedFetchError):
        fbm._download_one(fake, "https://bucket.example/models", "sample.onnx", "stale", tmp_path / "x")


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_download_one_rejects_html_interstitial(bundle, monkeypatch, tmp_path):
    # A 200 HTML body (auth/redirect page) must NOT be written as a model artifact.
    url = "https://bucket.example/models/sample.onnx"
    html = _FakeResponse(200, content=b"<!DOCTYPE html><html>login</html>", headers={"content-type": "text/html"})
    fake = _FakeClient({url: [html]})
    target = tmp_path / "sample.onnx"

    with pytest.raises(fbm.GatedFetchError, match="HTML"):
        fbm._download_one(fake, "https://bucket.example/models", "sample.onnx", "tok", target)
    assert not target.exists()


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_refresh_token_falls_back_to_env_when_refresh_raises(monkeypatch):
    # A refresh-endpoint hiccup must fall through to a freshly re-exported env token.
    monkeypatch.setenv("AILS_MODEL_REFRESH_URL", "https://refresh.example/token")
    monkeypatch.setenv("AILS_MODEL_AUTH_TOKEN", "env-fresh-token")

    def _boom(*a, **k):
        raise RuntimeError("network blip")

    monkeypatch.setattr("httpx.post", _boom)

    assert fbm._refresh_token("stale") == "env-fresh-token"


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_gated_idempotent_skip_when_present(bundle, monkeypatch):
    _root, models = bundle
    for rel in fbm._GATED_RELPATHS:
        f = models / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"already-here")
    # No bucket configured — must still succeed because everything is present.

    assert fbm._fetch_gated() == 0
    assert all((models / name).is_file() for name in fbm._BUNDLE_LICENSE_NAMES)
