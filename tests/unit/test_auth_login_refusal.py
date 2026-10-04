"""`ails auth login` names why the website refused the sign-in instead of a raw HTTP error."""

from __future__ import annotations

import httpx
import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli import auth_command
from reporails_cli.interfaces.cli.auth_command import auth_app

_SUPPORT = "us at reporails.com/contact"


class _Reply:
    def __init__(self, status_code: int, text: str, payload: dict | None = None) -> None:
        self.status_code = status_code
        self.text = text
        self._payload = payload

    def json(self) -> dict:
        if self._payload is None:
            raise ValueError("not json")
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            req = httpx.Request("POST", "https://reporails.com/api/auth/cli-exchange")
            raise httpx.HTTPStatusError(
                f"Server error '{self.status_code}' for url",
                request=req,
                response=self,  # type: ignore[arg-type]
            )


def _run(
    monkeypatch: pytest.MonkeyPatch, tmp_path, exchange: _Reply | None, client_id: _Reply | None = None
) -> tuple[int, str]:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("AILS_API_KEY", raising=False)
    monkeypatch.setattr(auth_command, "_load_credentials", lambda: {}, raising=False)
    monkeypatch.setattr(auth_command, "GITHUB_CLIENT_ID", "" if client_id else "cid")
    if client_id:
        monkeypatch.setattr(httpx, "get", lambda *a, **k: client_id)

    def fake_post(url: str, *a: object, **k: object) -> _Reply:
        if "github.com" in url:
            return _Reply(200, "{}", {"device_code": "d", "user_code": "U-1", "interval": 1})
        assert exchange is not None
        return exchange

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr(auth_command, "_poll_github_token", lambda *a, **k: "gho_x")
    result = CliRunner().invoke(auth_app, ["login", "--platform-url", "https://reporails.com"])
    return result.exit_code, " ".join(result.output.split())


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("status", "code", "expected"),
    [
        (
            500,
            "user_creation_failed",
            "use Regenerate and set the key as AILS_API_KEY. Otherwise contact us at reporails.com/contact.",
        ),
        (401, "invalid_github_token", "GitHub did not accept the sign-in. Run `ails auth login` again."),
        (400, "missing_token", "The sign-in was refused (HTTP 400: missing_token). Contact " + _SUPPORT),
        (502, "", "The sign-in was refused (HTTP 502). Contact " + _SUPPORT),
    ],
)
def test_exchange_refusal_is_actionable(monkeypatch, tmp_path, status: int, code: str, expected: str) -> None:
    text = f'{{"error":"{code}"}}' if code else "<html>bad gateway</html>"
    payload = {"error": code} if code else None
    exit_code, out = _run(monkeypatch, tmp_path, _Reply(status, text, payload))
    assert exit_code == 1
    assert expected in out
    assert "developer.mozilla.org" not in out
    assert "Failed to exchange token" not in out


@pytest.mark.unit
@pytest.mark.subsys_api
def test_client_id_503_not_configured(monkeypatch, tmp_path) -> None:
    reply = _Reply(503, '{"error":"github_oauth_not_configured"}', {"error": "github_oauth_not_configured"})
    exit_code, out = _run(monkeypatch, tmp_path, None, client_id=reply)
    assert exit_code == 1
    assert "Sign-in is not available right now. Contact " + _SUPPORT in out
    assert "transient" not in out
