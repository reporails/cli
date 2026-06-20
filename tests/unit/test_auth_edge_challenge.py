"""Offline coverage for the Cloudflare edge-challenge disambiguation in auth.

The live test (`test_auth_live.py`) only exercises the happy path. These mock
the network hop so the challenge branch — the regression REQ-213 fixes — is
guarded without a network round-trip.
"""

from __future__ import annotations

import httpx
import pytest

from reporails_cli.interfaces.cli.auth_command import (
    PlatformUnavailableError,
    _is_edge_challenge,
    _resolve_client_id,
)


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    "body",
    [
        "<title>Just a moment...</title>",
        "Attention Required! | Cloudflare",
        '<script src="/cdn-cgi/challenge-platform/h/b/orchestrate">',
        "cf-mitigated: challenge",
    ],
)
def test_is_edge_challenge_matches_markers(body: str) -> None:
    """Each known interstitial marker is detected."""
    assert _is_edge_challenge(body) is True


@pytest.mark.unit
@pytest.mark.subsys_api
def test_is_edge_challenge_ignores_ordinary_body() -> None:
    """A plain JSON-ish error body is not mistaken for a challenge."""
    assert _is_edge_challenge('{"error": "not found"}') is False


class _FakeResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text

    def json(self) -> dict[str, str]:
        return {"client_id": "abc123"}


@pytest.mark.unit
@pytest.mark.subsys_api
def test_resolve_client_id_names_edge_challenge_on_403(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 403 challenge page raises PlatformUnavailableError naming the edge challenge."""
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(403, "<title>Just a moment...</title>"))
    with pytest.raises(PlatformUnavailableError, match="Cloudflare edge challenge"):
        _resolve_client_id("https://reporails.com")


@pytest.mark.unit
@pytest.mark.subsys_api
def test_resolve_client_id_keeps_generic_message_for_plain_non_200(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-challenge non-200 keeps the generic HTTP message, not the edge-challenge one."""
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(500, "internal error"))
    with pytest.raises(PlatformUnavailableError, match="HTTP 500"):
        _resolve_client_id("https://reporails.com")


@pytest.mark.unit
@pytest.mark.subsys_api
def test_resolve_client_id_returns_client_id_on_200(monkeypatch: pytest.MonkeyPatch) -> None:
    """A 200 JSON body returns the embedded client id."""
    monkeypatch.setattr(httpx, "get", lambda *a, **k: _FakeResponse(200, '{"client_id": "abc123"}'))
    assert _resolve_client_id("https://reporails.com") == "abc123"
