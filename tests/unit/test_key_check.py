"""The key-check adapter: request shape and reply classification."""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from reporails_cli.core.platform.adapters import key_check
from reporails_cli.core.platform.adapters.key_check import check_api_key, key_check_server


def _reply(status: int, body: object = None, *, text: str | None = None, headers: dict[str, str] | None = None):
    request = httpx.Request("POST", "http://srv/v1/diagnose")
    if text is not None:
        return httpx.Response(status, text=text, headers=headers, request=request)
    return httpx.Response(status, json=body, headers=headers, request=request)


def _patch(monkeypatch: pytest.MonkeyPatch, reply: httpx.Response | Exception) -> dict[str, object]:
    seen: dict[str, object] = {}

    def fake_post(url: str, **kwargs: object) -> httpx.Response:
        seen["url"] = url
        seen.update(kwargs)
        if isinstance(reply, Exception):
            raise reply
        return reply

    monkeypatch.setattr(key_check.httpx, "post", fake_post)
    return seen


def _header(notices: list[dict[str, str]]) -> dict[str, str]:
    raw = base64.urlsafe_b64encode(json.dumps(notices).encode()).decode().rstrip("=")
    return {"X-Reporails-Notices": raw}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_request_is_an_empty_json_body_with_the_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_DEV_MODE", "1")
    seen = _patch(monkeypatch, _reply(200, {"tier": "free"}))
    check_api_key("tok_1", base_url="http://srv/")
    assert seen["url"] == "http://srv/v1/diagnose"
    headers = seen["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "Bearer tok_1"
    assert headers["Content-Type"] == "application/json"
    assert seen["content"] == b"{}"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_accepted_reply_carries_the_tier_and_the_notices(monkeypatch: pytest.MonkeyPatch) -> None:
    notice = {"id": "n1", "level": "warn", "text": "Renew soon", "url": "https://reporails.com/account"}
    _patch(monkeypatch, _reply(400, {"error": "bad_request", "tier": "pro"}, headers=_header([notice])))
    result = check_api_key("tok_1")
    assert (result.status, result.tier) == ("accepted", "pro")
    assert [(n.id, n.level, n.text) for n in result.notices] == [("n1", "warn", "Renew soon")]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_accepted_reply_without_the_header_has_no_notices(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(200, {"tier": "free"}))
    result = check_api_key("tok_1")
    assert (result.tier, result.notices) == ("free", ())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_401_is_rejected_with_error_and_message(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(401, {"error": "invalid_api_key", "message": "nope"}))
    result = check_api_key("tok_1")
    assert (result.status, result.error, result.reason) == ("rejected", "invalid_api_key", "nope")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_401_with_a_non_json_body_is_still_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(401, text="unauthorized"))
    assert check_api_key("tok_1").status == "rejected"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_key_error_body_is_rejected_whatever_the_status(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(403, {"error": "missing_or_invalid_api_key", "message": "revoked"}))
    assert check_api_key("tok_1").status == "rejected"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_403_page_without_a_key_error_is_unavailable_not_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(403, text="<html>Just a moment...</html>"))
    result = check_api_key("tok_1", base_url="http://srv")
    assert result.status == "unavailable"
    assert "403" in result.reason


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_network_error_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, httpx.ConnectError("down"))
    result = check_api_key("tok_1", base_url="http://srv")
    assert (result.status, result.reason) == ("unavailable", "could not reach http://srv")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "reply",
    [_reply(404, text="Not Found"), _reply(500, {"x": 1}), _reply(200, {"tier": "anonymous"}), _reply(200, {})],
)
def test_other_replies_are_unavailable(monkeypatch: pytest.MonkeyPatch, reply: httpx.Response) -> None:
    _patch(monkeypatch, reply)
    result = check_api_key("tok_1")
    assert result.status == "unavailable"
    assert f"HTTP {reply.status_code}" in result.reason


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_server_uses_env_or_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_SERVER_URL", " http://localhost:8001/ ")
    assert key_check_server() == "http://localhost:8001"
    monkeypatch.delenv("AILS_SERVER_URL")
    assert key_check_server() == "https://api.reporails.com"
