"""Ask the diagnostics server whether it accepts a credential and which tier it gets."""

from __future__ import annotations

import httpx

from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.adapters.notices_wire import NOTICES_HEADER, notices_from_header
from reporails_cli.core.platform.adapters.rate_cooldown import RATE_LIMIT_ERROR, active_cooldown, record_cooldown
from reporails_cli.core.platform.contract.errors import PlatformUnavailableError
from reporails_cli.core.platform.contract.http_get import HttpGet
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import ACCOUNT_TIERS, AUTH_REJECTED_ERRORS, FunnelError
from reporails_cli.core.platform.dto.sign_in import Handshake, HandshakeStatus, KeyCheck, Surface
from reporails_cli.core.platform.policy.preflight import parse_error_body
from reporails_cli.core.platform.utils.utils import json_object

# Seconds to wait for the server's reply to a key check.
_TIMEOUT_S = 10.0

# Seconds to wait for the server's reply to a handshake.
_HANDSHAKE_TIMEOUT_S = 5.0


def _rejection(status: int, text: str) -> FunnelError | None:
    """The server's refusal of the credential when the reply is one (a 401, or a body naming a rejected key)."""
    err = parse_error_body(status, text)
    if err is not None and (status == 401 or err.error in AUTH_REJECTED_ERRORS):
        return err
    return None


def check_api_key(api_key: str, tier: str) -> KeyCheck:
    """Sends an empty request with the key; reads the tier and notices the reply carries, or the rejection."""
    url, headers = AilsClient(tier, api_key=api_key).diagnose_request("application/json")
    try:
        resp = httpx.post(url, content=b"{}", headers=headers, timeout=_TIMEOUT_S)
    except (httpx.HTTPError, OSError):
        return KeyCheck("unavailable", reason=f"could not reach {url}")

    rejected = _rejection(resp.status_code, resp.text)
    if rejected is not None:
        return KeyCheck("rejected", error=rejected.error, reason=rejected.message)
    granted = json_object(resp.text).get("tier")
    if isinstance(granted, str) and granted in ACCOUNT_TIERS:
        return KeyCheck("accepted", tier=granted, notices=notices_from_header(resp.headers.get(NOTICES_HEADER)))
    return KeyCheck("unavailable", reason=f"the server answered HTTP {resp.status_code}")


def handshake(surface: Surface, *, tier: str, fetch: HttpGet) -> Handshake:
    """Asks the server whether it serves this caller: its verdict, or why there is none.

    No reply is `unreachable`, a rejected credential is `rejected` (worded as a sign-in still
    arriving when the key was just made), and any reply that holds no verdict (a missing route,
    a gateway error, an unreadable body) is `no_verdict`. While a rate-limit window is open (a 429 this
    caller received, here or on a check) the answer is a `refused` naming when it resets, with no request.
    """
    client = AilsClient(tier)
    cooldown = active_cooldown(client.base_url, client.api_key)
    if cooldown is not None:
        return _rate_limited(cooldown)
    url, headers = client.diagnose_request("application/json", surface)
    try:
        with fetch(url, headers=headers, timeout=_HANDSHAKE_TIMEOUT_S, follow_redirects=False) as reply:
            status = reply.status
            text = b"".join(reply.chunks()).decode("utf-8", errors="replace")
    except (PlatformUnavailableError, OSError):
        return Handshake("unreachable")
    early = _error_answer(client, status, text)
    if early is not None:
        return early
    body = json_object(text)
    verdict = body.get("verdict")
    if verdict == "ok":
        return _verdict("ok", body)
    if verdict == "refused":
        return _verdict("refused", body)
    return Handshake("no_verdict")


def _error_answer(client: AilsClient, status: int, text: str) -> Handshake | None:
    """The handshake for a reply that holds no verdict: a rate limit (its window is kept), a rejected
    credential or any other non-200; `None` for a 200 to read the verdict from."""
    limited = parse_error_body(status, text)
    if limited is not None and limited.error == RATE_LIMIT_ERROR:
        record_cooldown(client.base_url, client.api_key, limited)
        return _rate_limited(limited)
    rejected = _rejection(status, text)
    if rejected is not None:
        rejected = client.early_rejection(rejected)
        return Handshake("rejected", error=rejected.error, message=rejected.message)
    return Handshake("no_verdict") if status != 200 else None


def _rate_limited(err: FunnelError) -> Handshake:
    """The refused handshake for a rate-limit window: the reset time, then the server's own wording."""
    return Handshake(
        "refused", reason=RATE_LIMIT_ERROR, message=f"{err.reset_phrase}{err.message}".strip(), tier=err.tier
    )


def _verdict(status: HandshakeStatus, body: JsonObject) -> Handshake:
    """The handshake for a reply holding a verdict: its reason, message and tier, empty where the reply has none."""
    reason, message, tier = body.get("reason"), body.get("message"), body.get("tier")
    return Handshake(
        status,
        reason=reason if isinstance(reason, str) else "",
        message=message if isinstance(message, str) else "",
        tier=tier if isinstance(tier, str) else "",
    )
