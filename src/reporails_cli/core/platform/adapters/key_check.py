"""Ask the diagnostics server whether it accepts a credential and which tier it gets."""

from __future__ import annotations

from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.adapters.notices_wire import NOTICES_HEADER, notices_from_header
from reporails_cli.core.platform.dto.diagnostics import ACCOUNT_TIERS, AUTH_REJECTED_ERRORS
from reporails_cli.core.platform.dto.sign_in import KeyCheck
from reporails_cli.core.platform.utils.utils import json_object


def check_api_key(api_key: str, *, base_url: str | None = None, timeout: float = 10.0) -> KeyCheck:
    """Sends an empty request with the key; reads the tier and notices the reply carries, or the rejection."""
    import httpx

    url, headers = AilsClient(base_url=base_url, api_key=api_key).diagnose_request("application/json")
    try:
        resp = httpx.post(url, content=b"{}", headers=headers, timeout=timeout)
    except (httpx.HTTPError, OSError):
        return KeyCheck("unavailable", reason=f"could not reach {url}")

    body = json_object(resp.text)
    if resp.status_code == 401 or body.get("error") in AUTH_REJECTED_ERRORS:
        return KeyCheck(
            "rejected",
            error=str(body.get("error") or ""),
            reason=str(body.get("message") or ""),
        )
    tier = body.get("tier")
    if isinstance(tier, str) and tier in ACCOUNT_TIERS:
        return KeyCheck("accepted", tier=tier, notices=notices_from_header(resp.headers.get(NOTICES_HEADER)))
    return KeyCheck("unavailable", reason=f"the server answered HTTP {resp.status_code}")
