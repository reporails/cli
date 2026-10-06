"""Ask the diagnostics server whether it accepts a credential and which tier it gets."""

from __future__ import annotations

import os

import httpx

from reporails_cli.core.platform.adapters.api_client import DEFAULT_SERVER_URL, _user_agent
from reporails_cli.core.platform.adapters.notices_wire import NOTICES_HEADER, notices_from_header
from reporails_cli.core.platform.dto.sign_in import KeyCheck
from reporails_cli.core.platform.utils.utils import json_object

_KEY_TIERS = {"free", "pro", "team"}
_KEY_ERRORS = {"invalid_api_key", "missing_or_invalid_api_key"}


def key_check_server() -> str:
    """The server URL checks go to: `AILS_SERVER_URL` without a trailing slash, else the default."""
    return os.environ.get("AILS_SERVER_URL", "").strip().rstrip("/") or DEFAULT_SERVER_URL


def check_api_key(api_key: str, *, base_url: str | None = None, timeout: float = 10.0) -> KeyCheck:
    """Sends an empty request with the key; reads the tier and notices the reply carries, or the rejection."""
    base = (base_url or key_check_server()).rstrip("/")
    try:
        resp = httpx.post(
            f"{base}/v1/diagnose",
            content=b"{}",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": _user_agent(),
            },
            timeout=timeout,
        )
    except (httpx.HTTPError, OSError):
        return KeyCheck("unavailable", reason=f"could not reach {base}")

    body = json_object(resp.text)
    if resp.status_code == 401 or body.get("error") in _KEY_ERRORS:
        return KeyCheck(
            "rejected",
            error=str(body.get("error") or ""),
            reason=str(body.get("message") or ""),
        )
    tier = body.get("tier")
    if isinstance(tier, str) and tier in _KEY_TIERS:
        return KeyCheck("accepted", tier=tier, notices=notices_from_header(resp.headers.get(NOTICES_HEADER)))
    return KeyCheck("unavailable", reason=f"the server answered HTTP {resp.status_code}")
