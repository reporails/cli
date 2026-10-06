"""The website sign-in adapter: request shapes, reply classification, transport faults."""

from __future__ import annotations

from urllib.parse import parse_qs

import httpx
import pytest

from reporails_cli.core.platform.adapters import sign_in
from reporails_cli.core.platform.adapters.sign_in import poll_sign_in, revoke_sign_in, start_sign_in
from reporails_cli.core.platform.config.endpoints import DEFAULT_PLATFORM_URL, platform_url
from reporails_cli.core.platform.contract.errors import PlatformUnavailableError

_SITE = "http://site"
_GRANT = {
    "device_code": "dev-1",
    "user_code": "ABCD-EFGH",
    "verification_uri_complete": "http://site/oauth/device?user_code=ABCD-EFGH",
    "expires_in": 600,
    "interval": 5,
}


def _serve(monkeypatch: pytest.MonkeyPatch, handler) -> list[httpx.Request]:
    """Route `httpx.post` through a mock transport; returns the requests the adapter made."""
    seen: list[httpx.Request] = []

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        result = handler(request)
        if isinstance(result, Exception):
            raise result
        return result

    client = httpx.Client(transport=httpx.MockTransport(_record))
    monkeypatch.setattr(sign_in.httpx, "post", lambda url, **kw: client.post(url, **kw))
    return seen


def _form(request: httpx.Request) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(request.content.decode()).items()}


@pytest.mark.unit
@pytest.mark.subsys_api
def test_start_posts_the_form_and_reads_the_grant(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _serve(monkeypatch, lambda r: httpx.Response(200, json=_GRANT))
    grant = start_sign_in(_SITE, "laptop")
    assert str(seen[0].url) == "http://site/oauth/device_authorization"
    assert _form(seen[0]) == {"client_id": "ails-cli", "scope": "ails", "machine": "laptop"}
    assert seen[0].headers["user-agent"].startswith("reporails-cli/")
    assert (grant.device_code, grant.user_code, grant.expires_in, grant.interval) == ("dev-1", "ABCD-EFGH", 600, 5)
    assert grant.verification_url.endswith("user_code=ABCD-EFGH")


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    "reply",
    [
        httpx.Response(500, text="oops"),
        httpx.Response(403, text="<html>blocked</html>"),
        httpx.Response(200, text="<html>interstitial</html>"),
        httpx.Response(200, json={"device_code": "x"}),
        httpx.Response(200, json=[1]),
        httpx.Response(200, json={**_GRANT, "interval": "soon"}),
    ],
)
def test_start_that_is_refused_or_unreadable_raises(monkeypatch: pytest.MonkeyPatch, reply: httpx.Response) -> None:
    _serve(monkeypatch, lambda r: reply)
    with pytest.raises(PlatformUnavailableError):
        start_sign_in(_SITE, "laptop")


@pytest.mark.unit
@pytest.mark.subsys_api
def test_start_on_a_network_fault_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, lambda r: httpx.ConnectError("down"))
    with pytest.raises(PlatformUnavailableError):
        start_sign_in(_SITE, "laptop")


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"error": "authorization_pending"}, "pending"),
        ({"error": "slow_down"}, "slow_down"),
        ({"error": "access_denied"}, "denied"),
        ({"error": "expired_token"}, "expired"),
    ],
)
def test_poll_maps_the_error_codes(monkeypatch: pytest.MonkeyPatch, body: dict[str, str], status: str) -> None:
    seen = _serve(monkeypatch, lambda r: httpx.Response(400, json=body))
    assert poll_sign_in(_SITE, "dev-1").status == status
    assert str(seen[0].url) == "http://site/oauth/token"
    assert _form(seen[0]) == {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": "dev-1",
        "client_id": "ails-cli",
    }


@pytest.mark.unit
@pytest.mark.subsys_api
def test_poll_success_reads_the_credential_account_and_notices(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {
        "access_token": "tok-1",
        "expires_in": 31536000,
        "account": {"login": "octo", "tier": "pro"},
        "machine": "laptop",
        "notices": [{"id": "n1", "level": "info", "text": "Hello", "url": ""}, {"bad": True}],
    }
    _serve(monkeypatch, lambda r: httpx.Response(200, json=body))
    outcome = poll_sign_in(_SITE, "dev-1")
    assert outcome.status == "signed_in"
    assert outcome.signed_in is not None
    got = outcome.signed_in
    assert (got.access_token, got.login, got.tier, got.machine) == ("tok-1", "octo", "pro", "laptop")
    assert [n.id for n in got.notices] == ["n1"]


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize("body", [{}, {"access_token": ""}, {"access_token": "t"}, {"access_token": "t", "account": 3}])
def test_poll_success_without_a_credential_is_a_failure_not_a_sign_in(
    monkeypatch: pytest.MonkeyPatch, body: dict[str, object]
) -> None:
    _serve(monkeypatch, lambda r: httpx.Response(200, json=body))
    outcome = poll_sign_in(_SITE, "dev-1")
    assert (outcome.status, outcome.code, outcome.signed_in) == ("failed", "invalid_response", None)


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize("reply", [httpx.Response(502, text="bad gateway"), httpx.ConnectError("down")])
def test_poll_transient_faults_are_retry(monkeypatch: pytest.MonkeyPatch, reply: httpx.Response | Exception) -> None:
    _serve(monkeypatch, lambda r: reply)
    assert poll_sign_in(_SITE, "dev-1").status == "retry"


@pytest.mark.unit
@pytest.mark.subsys_api
def test_poll_names_an_unknown_error_code(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve(monkeypatch, lambda r: httpx.Response(400, json={"error": "invalid_client"}))
    outcome = poll_sign_in(_SITE, "dev-1")
    assert (outcome.status, outcome.code) == ("failed", "invalid_client")
    _serve(monkeypatch, lambda r: httpx.Response(403, text="<html>blocked</html>"))
    assert poll_sign_in(_SITE, "dev-1").code == "http_403"


@pytest.mark.unit
@pytest.mark.subsys_api
def test_revoke_posts_the_bearer(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = _serve(monkeypatch, lambda r: httpx.Response(204))
    revoke_sign_in(_SITE, "tok-1")
    assert str(seen[0].url) == "http://site/api/auth/logout"
    assert seen[0].headers["authorization"] == "Bearer tok-1"


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize("reply", [httpx.Response(500), httpx.ConnectError("down")])
def test_revoke_that_fails_raises(monkeypatch: pytest.MonkeyPatch, reply: httpx.Response | Exception) -> None:
    _serve(monkeypatch, lambda r: reply)
    with pytest.raises(PlatformUnavailableError):
        revoke_sign_in(_SITE, "tok-1")


@pytest.mark.unit
@pytest.mark.subsys_api
def test_platform_url_uses_env_or_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_PLATFORM_URL", " http://127.0.0.1:9000/ ")
    assert platform_url() == "http://127.0.0.1:9000"
    monkeypatch.delenv("AILS_PLATFORM_URL")
    assert platform_url() == DEFAULT_PLATFORM_URL == "https://reporails.com"
