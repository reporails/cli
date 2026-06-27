"""Offline coverage for auth-failure messaging.

`_resolve_client_id` must surface a reachable-but-unexpected platform response as a
clear, actionable error (transient network/edge issue) instead of swallowing it into
an empty client_id and a misleading "OAuth not configured" message. The CLI
gives a generic helpful message — it does not fingerprint the proxy's response.
"""

from __future__ import annotations

import httpx
import pytest

from reporails_cli.interfaces.cli.auth_command import (
    PlatformUnavailableError,
    _resolve_client_id,
)


class _FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text

    def json(self) -> dict[str, str]:
        if self.text.strip().startswith("{"):
            return {"client_id": "abc123"}
        raise ValueError("not json")


@pytest.mark.unit
@pytest.mark.subsys_api
def test_resolve_client_id_non_200_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-200 raises PlatformUnavailableError with a retry/contact-support message."""
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(403, "<html>blocked</html>"))
    with pytest.raises(PlatformUnavailableError, match="HTTP 403"):
        _resolve_client_id("https://reporails.com")


@pytest.mark.unit
@pytest.mark.subsys_api
def test_resolve_client_id_non_json_is_actionable(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 200 with a non-JSON body raises a clear unexpected-response error, not an
    empty client_id / misleading 'OAuth not configured'."""
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(200, "<html>interstitial</html>"))
    with pytest.raises(PlatformUnavailableError, match="non-JSON"):
        _resolve_client_id("https://reporails.com")


@pytest.mark.unit
@pytest.mark.subsys_api
def test_resolve_client_id_returns_client_id_on_200(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 200 JSON body returns the embedded client id."""
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(200, '{"client_id": "abc123"}'))
    assert _resolve_client_id("https://reporails.com") == "abc123"
