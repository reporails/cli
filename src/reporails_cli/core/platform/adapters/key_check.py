"""Ask the diagnostics server whether it accepts a credential and which tier it gets."""

from __future__ import annotations

import httpx

from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.adapters.notices_wire import NOTICES_HEADER, notices_from_header
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import ACCOUNT_TIERS, AUTH_REJECTED_ERRORS, FunnelError
from reporails_cli.core.platform.dto.sign_in import Handshake, HandshakeStatus, KeyCheck, Surface
from reporails_cli.core.platform.policy.preflight import parse_error_body
from reporails_cli.core.platform.utils.utils import json_object

# Seconds to wait for the server's reply to a key check.
_TIMEOUT_S = 10.0

# Seconds to wait for the server's reply to a handshake.
_HANDSHAKE_TIMEOUT_S = 5.0


def _rejection(resp: httpx.Response) -> FunnelError | None:
    """The server's refusal of the credential when the reply is one (a 401, or a body naming a rejected key)."""
    err = parse_error_body(resp.status_code, resp.text)
    if err is not None and (resp.status_code == 401 or err.error in AUTH_REJECTED_ERRORS):
        return err
    return None


def check_api_key(api_key: str) -> KeyCheck:
    """Sends an empty request with the key; reads the tier and notices the reply carries, or the rejection."""
    url, headers = AilsClient(api_key=api_key).diagnose_request("application/json")
    try:
        resp = httpx.post(url, content=b"{}", headers=headers, timeout=_TIMEOUT_S)
    except (httpx.HTTPError, OSError):
        return KeyCheck("unavailable", reason=f"could not reach {url}")

    rejected = _rejection(resp)
    if rejected is not None:
        return KeyCheck("rejected", error=rejected.error, reason=rejected.message)
    tier = json_object(resp.text).get("tier")
    if isinstance(tier, str) and tier in ACCOUNT_TIERS:
        return KeyCheck("accepted", tier=tier, notices=notices_from_header(resp.headers.get(NOTICES_HEADER)))
    return KeyCheck("unavailable", reason=f"the server answered HTTP {resp.status_code}")


def handshake(surface: Surface) -> Handshake:
    """Asks the server whether it serves this caller: its verdict, or why there is none.

    No reply is `unreachable`, a rejected credential is `rejected` (worded as a sign-in still
    arriving when the key was just made), and any reply that holds no verdict (a missing route,
    a gateway error, an unreadable body) is `no_verdict`.
    """
    client = AilsClient()
    url, headers = client.diagnose_request("application/json", surface)
    try:
        resp = httpx.get(url, headers=headers, timeout=_HANDSHAKE_TIMEOUT_S)
    except (httpx.HTTPError, OSError):
        return Handshake("unreachable")
    rejected = _rejection(resp)
    if rejected is not None:
        rejected = client.early_rejection(rejected)
        return Handshake("rejected", error=rejected.error, message=rejected.message)
    if resp.status_code != 200:
        return Handshake("no_verdict")
    body = json_object(resp.text)
    verdict = body.get("verdict")
    if verdict == "ok":
        return _verdict("ok", body)
    if verdict == "refused":
        return _verdict("refused", body)
    return Handshake("no_verdict")


def _verdict(status: HandshakeStatus, body: JsonObject) -> Handshake:
    """The handshake for a reply holding a verdict: its reason, message and tier, empty where the reply has none."""
    reason, message, tier = body.get("reason"), body.get("message"), body.get("tier")
    return Handshake(
        status,
        reason=reason if isinstance(reason, str) else "",
        message=message if isinstance(message, str) else "",
        tier=tier if isinstance(tier, str) else "",
    )
