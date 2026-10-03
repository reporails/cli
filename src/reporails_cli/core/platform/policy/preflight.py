"""Local preflight gates and server 4xx body parsing.

Pure decision functions that turn a projected payload or a server error body
into a `FunnelError`. The preflight gates cover only the absolute caps
(atoms, files), checked locally before anything is uploaded. Limits that depend
on the plan (byte cap, rate cap) are reported by the server and not checked here.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from reporails_cli.core.platform.dto.diagnostics import (
    DEFAULT_RETRY_AFTER_S,
    ENTITLED_TIERS,
    RETRYABLE_ERRORS,
    FunnelError,
)

logger = logging.getLogger(__name__)


UNIVERSAL_ATOM_CAP = 10_000
WIRE_MAX_FILES = 500

# Error tokens kept verbatim (with the body's own tier / limits / message).
# Anything else collapses to `unknown_error`, which renders the bug-report link.
# The 401 tokens are listed so an auth rejection renders its sign-in message.
# `server_busy` and `scoring_timeout` are the 503/504 tokens: they read as "try again".
_KNOWN_ERRORS = {
    "rate_limit_exceeded",
    "payload_too_large",
    "atom_cap_exceeded",
    "file_cap_exceeded",
    "project_limit_reached",
    "invalid_api_key",
    "missing_or_invalid_api_key",
    *RETRYABLE_ERRORS,
}
# A 5xx reply is parsed only when it names a failure that clears on its own.
_RETRYABLE_STATUSES = (503, 504)

_CONTACT_SUFFIXES = {
    "payload_too_large": "payload",
    "atom_cap_exceeded": "atoms",
}


def _preflight_url(error: str, tier: str) -> str:
    """Contact-form URL for an entitled session that hit an absolute cap.

    Gated on the shared entitled-tier set, not on the single string `"pro"` — a
    `team` session is a paying session and must get the same contact form, not
    the unentitled upgrade CTA.
    """
    if tier not in ENTITLED_TIERS or error not in _CONTACT_SUFFIXES:
        return ""
    return f"https://reporails.com/contact/{_CONTACT_SUFFIXES[error]}?utm_source=cli"


def parse_error_body(status_code: int, body_text: str, retry_after: str | None = None) -> FunnelError | None:
    """Parse a 4xx body, or a 503/504 body naming a busy or slow server, into a FunnelError.

    `retry_after` is the reply's `Retry-After` header, in seconds. Returns None for a non-4xx
    status and for any other 5xx reply, which is reported as a plain HTTP error.
    """
    retryable_status = status_code in _RETRYABLE_STATUSES
    if not (400 <= status_code < 500 or retryable_status):
        return None
    try:
        body = json.loads(body_text)
    except (json.JSONDecodeError, ValueError):
        logger.debug("Non-JSON %d response body: %r", status_code, body_text[:200])
        return None if retryable_status else _unknown_error(status_code, "")
    if not isinstance(body, dict):
        logger.debug("Unexpected %d response shape: %r", status_code, body_text[:200])
        return None if retryable_status else _unknown_error(status_code, "")
    error = body.get("error", "")
    if retryable_status and error not in RETRYABLE_ERRORS:
        return None
    if error not in _KNOWN_ERRORS:
        message = str(body.get("message", "")) or f"HTTP {status_code} ({error or 'unrecognized'})"
        return _unknown_error(status_code, message, str(body.get("tier", "")))
    reset_in = int(body.get("reset_in") or 0)
    if error in RETRYABLE_ERRORS:
        header = int(retry_after) if retry_after and retry_after.strip().isdigit() else 0
        reset_in = reset_in or header or DEFAULT_RETRY_AFTER_S
    return FunnelError(
        error=error,
        tier=str(body.get("tier", "")),
        limit=int(body.get("limit") or body.get("limit_bytes") or 0),
        size=int(body.get("size") or body.get("atoms") or body.get("bytes") or 0),
        files=int(body.get("files") or 0),
        reset_in=reset_in,
        upgrade_url=str(body.get("upgrade_url", "")),
        support_url=str(body.get("support_url", "")),
        message=str(body.get("message", "")),
        status=status_code,
    )


def _unknown_error(status_code: int, message: str, tier: str = "") -> FunnelError:
    """The catch-all error for a reply whose body names no known token; it renders the bug-report link."""
    return FunnelError(
        error="unknown_error",
        tier=tier,
        message=message or f"Diagnostics server returned HTTP {status_code}",
        status=status_code,
    )


def preflight_oversized(
    payload: dict[str, Any],
    has_api_key: bool,
) -> FunnelError | None:
    """Local check on universal absolute caps (atoms, files)."""
    presumed_tier = "pro" if has_api_key else "anonymous"
    n_atoms = len(payload.get("atoms", []))
    if n_atoms > UNIVERSAL_ATOM_CAP:
        return FunnelError(
            error="atom_cap_exceeded",
            tier=presumed_tier,
            limit=UNIVERSAL_ATOM_CAP,
            size=n_atoms,
            files=len(payload.get("files", [])),
            upgrade_url=_preflight_url("atom_cap_exceeded", presumed_tier),
        )
    n_files = len(payload.get("files", []))
    if n_files > WIRE_MAX_FILES:
        # A separate token from `payload_too_large`: the file-count cap is the same
        # for every plan, so it carries no upgrade or contact-form link.
        return FunnelError(
            error="file_cap_exceeded",
            tier=presumed_tier,
            limit=WIRE_MAX_FILES,
            size=n_files,
            files=n_files,
            upgrade_url="",
        )
    return None
