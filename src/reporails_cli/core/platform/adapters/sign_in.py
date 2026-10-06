"""The website's browser sign-in: start one, ask once whether it is finished, revoke one.

Each function makes one request. A fault that stops a start or a revoke is raised as
`PlatformUnavailableError`; a poll names its faults in the outcome it returns, so the caller
decides whether to ask again.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from reporails_cli.core.platform.adapters.api_client import _user_agent
from reporails_cli.core.platform.adapters.notices_wire import notices_from_list
from reporails_cli.core.platform.contract.errors import PlatformRefusedError, PlatformUnavailableError
from reporails_cli.core.platform.dto.sign_in import PollOutcome, PollStatus, SignedIn, SignInGrant
from reporails_cli.core.platform.utils.utils import json_object

if TYPE_CHECKING:
    import httpx

logger = logging.getLogger(__name__)

CLIENT_ID = "ails-cli"
_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
_TIMEOUT_S = 10.0
# The error codes the website answers a poll with, and what each means for the sign-in.
_ERROR_STATUS: dict[str, PollStatus] = {
    "authorization_pending": "pending",
    "slow_down": "slow_down",
    "access_denied": "denied",
    "expired_token": "expired",
}


def _headers() -> dict[str, str]:
    return {"User-Agent": _user_agent(), "Accept": "application/json"}


def _post(url: str, **kwargs: Any) -> httpx.Response:
    """One POST; a transport fault is raised as `PlatformUnavailableError`."""
    import httpx

    try:
        return httpx.post(url, headers=_headers() | kwargs.pop("headers", {}), timeout=_TIMEOUT_S, **kwargs)
    except (httpx.HTTPError, OSError) as exc:
        logger.debug("Could not reach %s: %s", url, exc)
        raise PlatformUnavailableError(f"Could not reach {url}: {exc}") from exc


def _retry_after(resp: httpx.Response) -> int | None:
    """The whole seconds in the reply's `Retry-After` header; None when absent or not a number."""
    raw = resp.headers.get("Retry-After", "").strip()
    return int(raw) if raw.isdigit() else None


def start_sign_in(site: str, machine: str) -> SignInGrant:
    """Ask the website to start a sign-in for `machine`.

    Raises `PlatformRefusedError` (status and wait) on a non-2xx answer, and
    `PlatformUnavailableError` when the website is unreachable or answers without the fields a
    sign-in needs.
    """
    resp = _post(
        f"{site}/oauth/device_authorization",
        data={"client_id": CLIENT_ID, "scope": "ails", "machine": machine},
    )
    if not 200 <= resp.status_code < 300:
        raise PlatformRefusedError(
            f"The website answered the sign-in start with HTTP {resp.status_code}",
            status=resp.status_code,
            retry_after=_retry_after(resp),
        )
    body = json_object(resp.text)
    try:
        return SignInGrant(
            device_code=str(body["device_code"]),
            user_code=str(body["user_code"]),
            verification_url=str(body["verification_uri_complete"]),
            expires_in=int(body["expires_in"]),
            interval=int(body["interval"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise PlatformUnavailableError("The website answered the sign-in start without the expected fields") from exc


def _signed_in(body: dict[str, Any]) -> PollOutcome:
    """A 200 token reply as an outcome; `failed` when it carries no credential."""
    token = body.get("access_token")
    account = body.get("account")
    if not isinstance(token, str) or not token or not isinstance(account, dict):
        return PollOutcome("failed", code="invalid_response")
    return PollOutcome(
        "signed_in",
        SignedIn(
            access_token=token,
            login=str(account.get("login") or ""),
            tier=str(account.get("tier") or ""),
            machine=str(body.get("machine") or ""),
            notices=notices_from_list(body.get("notices")),
        ),
    )


def poll_sign_in(site: str, device_code: str) -> PollOutcome:
    """Ask once whether the sign-in for `device_code` is finished.

    A network fault or a 5xx answer is a `retry`: the website may answer the next ask.
    """
    try:
        resp = _post(
            f"{site}/oauth/token",
            data={"grant_type": _GRANT_TYPE, "device_code": device_code, "client_id": CLIENT_ID},
        )
    except PlatformUnavailableError:
        return PollOutcome("retry")
    if resp.status_code >= 500:
        return PollOutcome("retry")
    body = json_object(resp.text)
    if resp.status_code == 200:
        return _signed_in(body)
    code = str(body.get("error") or f"http_{resp.status_code}")
    if code in _ERROR_STATUS:
        return PollOutcome(_ERROR_STATUS[code])
    return PollOutcome("failed", code=code)


def revoke_sign_in(site: str, token: str) -> None:
    """Ask the website to end the sign-in `token` belongs to.

    Raises `PlatformUnavailableError` when the website is unreachable or does not answer 2xx.
    """
    resp = _post(f"{site}/api/auth/logout", headers={"Authorization": f"Bearer {token}"})
    if not 200 <= resp.status_code < 300:
        raise PlatformUnavailableError(f"The website answered the sign-out with HTTP {resp.status_code}")
