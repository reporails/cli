"""A busy server, a slow request and the client's own timeout read as 'try again', not as a bug."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.dto.diagnostics import FunnelError
from reporails_cli.core.platform.dto.ruleset import FileRecord, RulesetMap, RulesetSummary
from reporails_cli.core.platform.policy.preflight import parse_error_body
from reporails_cli.formatters.json import format_server_error
from reporails_cli.formatters.text import display
from reporails_cli.interfaces.mcp.tools import _attach_funnel

_ROOT = Path("/tmp/reporails-test-scan-root")

BUSY = "The diagnostics server is busy. Try again in 5 seconds."
SLOW = "The diagnostics request took too long. Try again in 10 seconds."


def _map() -> RulesetMap:
    return RulesetMap(
        schema_version="1.0.0",
        embedding_model="test",
        generated_at="2026-01-01T00:00:00Z",
        files=(FileRecord(path="CLAUDE.md", category="main", content_hash="", token_count=0, atom_count=0),),
        atoms=(),
        summary=RulesetSummary(n_atoms=0, n_charged=0, n_neutral=0),
    )


def _payload() -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "embedding_model": "test",
        "generated_at": "2026-01-01T00:00:00Z",
        "files": [{"path": "CLAUDE.md"}],
        "atoms": [],
        "summary": {"n_atoms": 0, "n_charged": 0, "n_neutral": 0},
    }


class _Reply:
    def __init__(self, status: int, body: dict[str, Any] | str, headers: dict[str, str] | None = None) -> None:
        self.status_code = status
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.headers = headers or {}

    def raise_for_status(self) -> None:
        raise httpx.HTTPStatusError(str(self.status_code), request=None, response=self)  # type: ignore[arg-type]


def _lint(post: Any) -> FunnelError:
    with (
        patch("reporails_cli.core.platform.adapters.payload.project_payload", return_value=_payload()),
        patch("httpx.post", side_effect=post),
    ):
        response = AilsClient(base_url="https://example.test", tier="pro").lint(_map(), root=_ROOT)
    assert response.funnel_error is not None
    return response.funnel_error


def _render(err: FunnelError) -> str:
    with display.console.capture() as cap:
        display._render_funnel_cta(err)
    return cap.get()


def _busy_error() -> FunnelError:
    return _lint(lambda *a, **k: _Reply(503, {"error": "server_busy"}, {"Retry-After": "5"}))


def _timeout_reply_error() -> FunnelError:
    return _lint(lambda *a, **k: _Reply(504, {"error": "scoring_timeout"}))


def _client_timeout_error() -> FunnelError:
    def _raise(*a: object, **k: object) -> None:
        raise httpx.TimeoutException("timed out")

    return _lint(_raise)


@pytest.mark.unit
@pytest.mark.subsys_api
def test_busy_reply_reads_as_try_again_with_the_servers_wait() -> None:
    err = _busy_error()
    assert err.error == "server_busy"
    assert err.status == 503
    out = _render(err)
    assert BUSY in " ".join(out.split())
    assert "Did you see an error" not in out


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize("make", [_timeout_reply_error, _client_timeout_error])
def test_slow_request_reads_as_try_again(make: Any) -> None:
    err = make()
    out = _render(err)
    assert SLOW in " ".join(out.split())
    assert "Did you see an error" not in out


@pytest.mark.unit
@pytest.mark.subsys_api
def test_busy_reply_without_a_wait_uses_a_default() -> None:
    err = _lint(lambda *a, **k: _Reply(503, {"error": "server_busy"}))
    assert "Try again in 10 seconds." in " ".join(_render(err).split())


@pytest.mark.unit
@pytest.mark.subsys_api
def test_unexpected_500_keeps_the_bug_report_invitation() -> None:
    err = _lint(lambda *a, **k: _Reply(500, {"error": "upstream_error"}))
    assert err.error == "http_error"
    assert "Did you see an error" in _render(err)


@pytest.mark.unit
@pytest.mark.subsys_api
def test_json_and_mcp_carry_the_same_message() -> None:
    for err, text in ((_busy_error(), BUSY), (_client_timeout_error(), SLOW)):
        assert format_server_error(err)["message"] == text  # type: ignore[index]
        assert _attach_funnel({"offline": True}, err)["funnel"]["message"] == text


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("status", "error", "retry_after", "wait"),
    [(503, "server_busy", "5", 5), (503, "server_busy", None, 10), (504, "scoring_timeout", "abc", 10)],
)
def test_a_busy_or_slow_reply_is_parsed_with_the_servers_wait(
    status: int, error: str, retry_after: str | None, wait: int
) -> None:
    err = parse_error_body(status, json.dumps({"error": error}), retry_after)
    assert err is not None
    assert (err.error, err.status, err.reset_in, err.retryable) == (error, status, wait, True)


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("status", "body"),
    [
        (503, json.dumps({"error": "upstream_error"})),
        (503, "<html>busy</html>"),
        (504, json.dumps(["server_busy"])),
        (500, json.dumps({"error": "server_busy"})),
        (502, json.dumps({"error": "scoring_timeout"})),
    ],
)
def test_any_other_server_error_reply_is_not_parsed(status: int, body: str) -> None:
    assert parse_error_body(status, body, "5") is None


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (401, {"error": "invalid_api_key", "tier": "free", "message": "Your API key was revoked."}, "revoked"),
        (401, {"error": "missing_or_invalid_api_key"}, "key"),
        (429, {"error": "rate_limit_exceeded"}, "limit"),
        (413, {"error": "payload_too_large"}, "large"),
        (402, {"error": "project_limit_reached"}, "limit"),
    ],
)
def test_a_known_refusal_does_not_ask_for_a_bug_report(status: int, body: dict[str, Any], expected: str) -> None:
    err = parse_error_body(status, json.dumps(body))
    assert err is not None
    assert not err.retryable
    out = _render(err)
    assert "Did you see an error" not in out
    assert expected in out.lower()


@pytest.mark.unit
@pytest.mark.subsys_api
def test_an_unrecognised_4xx_keeps_the_bug_report_invitation() -> None:
    err = parse_error_body(418, json.dumps({"error": "teapot"}))
    assert err is not None
    assert "Did you see an error" in _render(err)
