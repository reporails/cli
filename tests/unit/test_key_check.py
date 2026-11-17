"""The key-check adapter: request shape and reply classification."""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager

import httpx
import pytest

from reporails_cli.core.platform.adapters.key_check import check_api_key, handshake
from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.contract.http_get import HttpReply


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

    monkeypatch.setattr(httpx, "post", fake_post)
    return seen


def _header(notices: list[dict[str, str]]) -> dict[str, str]:
    raw = base64.urlsafe_b64encode(json.dumps(notices).encode()).decode().rstrip("=")
    return {"X-Reporails-Notices": raw}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_request_is_an_empty_json_body_with_the_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _patch(monkeypatch, _reply(200, {"tier": "free"}))
    monkeypatch.setenv("AILS_SERVER_URL", "http://srv/")
    check_api_key("tok_1", "free")
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
    result = check_api_key("tok_1", "free")
    assert (result.status, result.tier) == ("accepted", "pro")
    assert [(n.id, n.level, n.text) for n in result.notices] == [("n1", "warn", "Renew soon")]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_accepted_reply_without_the_header_has_no_notices(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(200, {"tier": "free"}))
    result = check_api_key("tok_1", "free")
    assert (result.tier, result.notices) == ("free", ())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_401_is_rejected_with_error_and_message(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(401, {"error": "invalid_api_key", "message": "nope"}))
    result = check_api_key("tok_1", "free")
    assert (result.status, result.error, result.reason) == ("rejected", "invalid_api_key", "nope")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_401_with_a_non_json_body_is_still_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(401, text="unauthorized"))
    assert check_api_key("tok_1", "free").status == "rejected"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_key_error_body_is_rejected_whatever_the_status(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(403, {"error": "missing_or_invalid_api_key", "message": "revoked"}))
    assert check_api_key("tok_1", "free").status == "rejected"


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_403_page_without_a_key_error_is_unavailable_not_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _reply(403, text="<html>Just a moment...</html>"))
    monkeypatch.setenv("AILS_SERVER_URL", "http://srv")
    result = check_api_key("tok_1", "free")
    assert result.status == "unavailable"
    assert "403" in result.reason


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_network_error_is_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, httpx.ConnectError("down"))
    monkeypatch.setenv("AILS_SERVER_URL", "http://srv")
    result = check_api_key("tok_1", "free")
    assert (result.status, result.reason) == ("unavailable", "could not reach http://srv/v1/diagnose")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "reply",
    [_reply(404, text="Not Found"), _reply(500, {"x": 1}), _reply(200, {"tier": "anonymous"}), _reply(200, {})],
)
def test_other_replies_are_unavailable(monkeypatch: pytest.MonkeyPatch, reply: httpx.Response) -> None:
    _patch(monkeypatch, reply)
    result = check_api_key("tok_1", "free")
    assert result.status == "unavailable"
    assert f"HTTP {reply.status_code}" in result.reason


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_probe_goes_where_the_client_goes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_SERVER_URL", "http://localhost:8001/")
    seen = _patch(monkeypatch, _reply(200, {"tier": "free"}))
    check_api_key("tok_1", "free")
    assert seen["url"] == "http://localhost:8001/v1/diagnose"
    monkeypatch.setenv("AILS_DEV_MODE", "1")
    check_api_key("tok_1", "free")
    assert seen["url"] == "http://localhost:8001/diagnose"
    assert seen["content"] == b"{}"
    assert seen["headers"]["Content-Type"] == "application/json"


class _FakeReply:
    """An `HttpReply` over a canned status and body."""

    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def header(self, name: str) -> str:
        return ""

    def chunks(self) -> Iterator[bytes]:
        mid = len(self._body) // 2
        yield self._body[:mid]
        yield self._body[mid:]


class _FakeGet:
    """An `HttpGet` that records its call and answers with a reply, or raises."""

    def __init__(self, reply: _FakeReply | Exception) -> None:
        self._reply = reply
        self.seen: dict[str, object] = {}

    @contextmanager
    def __call__(
        self, url: str, *, headers: Mapping[str, str], timeout: float, follow_redirects: bool
    ) -> Iterator[HttpReply]:
        self.seen = {"url": url, "headers": dict(headers), "timeout": timeout, "follow_redirects": follow_redirects}
        if isinstance(self._reply, Exception):
            raise self._reply
        yield self._reply


def _handshake_reply(status: int, body: object = None, *, text: str | None = None) -> _FakeReply:
    return _FakeReply(status, (text if text is not None else json.dumps(body)).encode())


_REFUSED = {"verdict": "refused", "reason": "rate", "message": "Sign up with `ails login`", "tier": "anonymous"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        (_handshake_reply(200, {"verdict": "ok", "reason": None, "message": None, "tier": "free"}), ("ok", "", "free")),
        (_handshake_reply(200, _REFUSED), ("refused", "rate", "anonymous")),
        (_handshake_reply(401, {"error": "invalid_api_key", "message": "nope"}), ("rejected", "", "")),
        (_handshake_reply(403, {"error": "forbidden"}), ("no_verdict", "", "")),
        (_handshake_reply(302, text=""), ("no_verdict", "", "")),
        (_handshake_reply(404, text="Not Found"), ("no_verdict", "", "")),
        (_handshake_reply(500, text="boom"), ("no_verdict", "", "")),
        (_handshake_reply(200, text="<html>proxy</html>"), ("no_verdict", "", "")),
        (_handshake_reply(200, {"verdict": "maybe"}), ("no_verdict", "", "")),
        (_handshake_reply(200, ["ok"]), ("no_verdict", "", "")),
        (PlatformUnavailableError("slow"), ("unreachable", "", "")),
        (OSError("refused"), ("unreachable", "", "")),
    ],
    ids=[
        "ok",
        "refused",
        "401",
        "302",
        "403",
        "404",
        "500",
        "html-200",
        "unknown-verdict",
        "list-200",
        "timeout",
        "no-reply",
    ],
)
def test_handshake_classifies_every_reply(
    monkeypatch: pytest.MonkeyPatch, reply: _FakeReply | Exception, expected: tuple[str, str, str]
) -> None:
    fetch = _FakeGet(reply)
    monkeypatch.setenv("AILS_SERVER_URL", "http://srv/")
    answer = handshake("mcp", tier="free", fetch=fetch)
    assert (answer.status, answer.reason, answer.tier) == expected
    assert fetch.seen["url"] == "http://srv/v1/handshake"
    headers = fetch.seen["headers"]
    assert isinstance(headers, dict)
    assert headers["X-Reporails-Surface"] == "mcp"
    assert fetch.seen["timeout"] == 5.0
    assert fetch.seen["follow_redirects"] is False


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_refused_handshake_carries_the_servers_message_and_a_rejected_one_its_error() -> None:
    refused = handshake("cli", tier="free", fetch=_FakeGet(_handshake_reply(200, _REFUSED)))
    assert refused.message == "Sign up with `ails login`"
    rejected = handshake(
        "cli", tier="free", fetch=_FakeGet(_handshake_reply(401, {"error": "invalid_api_key", "message": "nope"}))
    )
    assert (rejected.error, rejected.message) == ("invalid_api_key", "nope")
