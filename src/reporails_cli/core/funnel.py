"""Funnel error parsing and CTA rendering."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

logger = logging.getLogger(__name__)


UNIVERSAL_ATOM_CAP = 10_000
BUG_REPORT_URL = "https://github.com/reporails/cli/issues"
WIRE_MAX_FILES = 500
WIRE_MAX_CLUSTERS = 2000


@dataclass(frozen=True)
class FunnelError:
    """Funnel error shape for both server 4xx bodies and local preflight failures."""

    error: str
    tier: str = ""
    limit: int = 0
    size: int = 0
    files: int = 0
    reset_in: int = 0
    upgrade_url: str = ""
    support_url: str = ""
    message: str = ""


@dataclass(frozen=True)
class LintResponse:
    """Envelope returned by AilsClient.lint()."""

    result: Any = None
    funnel_error: FunnelError | None = None


_KNOWN_ERRORS = {
    "rate_limit_exceeded",
    "payload_too_large",
    "atom_cap_exceeded",
    "project_limit_reached",
}


def parse_error_body(status_code: int, body_text: str) -> FunnelError | None:
    """Parse a 4xx body into a FunnelError. Returns None only for non-4xx."""
    if status_code < 400 or status_code >= 500:
        return None
    try:
        body = json.loads(body_text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("Could not parse %d response body as JSON: %r", status_code, body_text[:200])
        return FunnelError(
            error="unknown_error",
            message=f"HTTP {status_code} with unparseable response body",
        )
    if not isinstance(body, dict):
        return FunnelError(
            error="unknown_error",
            message=f"HTTP {status_code} with unexpected response shape",
        )
    error = body.get("error", "")
    if error not in _KNOWN_ERRORS:
        message = str(body.get("message", "")) or f"HTTP {status_code} ({error or 'unrecognized'})"
        return FunnelError(
            error="unknown_error",
            tier=str(body.get("tier", "")),
            message=message,
        )
    return FunnelError(
        error=error,
        tier=str(body.get("tier", "")),
        limit=int(body.get("limit") or body.get("limit_bytes") or 0),
        size=int(body.get("size") or body.get("atoms") or body.get("bytes") or 0),
        files=int(body.get("files") or 0),
        reset_in=int(body.get("reset_in") or 0),
        upgrade_url=str(body.get("upgrade_url", "")),
        support_url=str(body.get("support_url", "")),
        message=str(body.get("message", "")),
    )


def preflight_oversized(
    payload: dict[str, Any],
    has_api_key: bool,
) -> FunnelError | None:
    """Local check on universal absolute caps (atoms, files, clusters)."""
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
        return FunnelError(
            error="payload_too_large",
            tier=presumed_tier,
            limit=WIRE_MAX_FILES,
            size=n_files,
            files=n_files,
            upgrade_url=_preflight_url("payload_too_large", presumed_tier),
        )
    n_clusters = len(payload.get("clusters", []))
    if n_clusters > WIRE_MAX_CLUSTERS:
        return FunnelError(
            error="payload_too_large",
            tier=presumed_tier,
            limit=WIRE_MAX_CLUSTERS,
            size=n_clusters,
            upgrade_url=_preflight_url("payload_too_large", presumed_tier),
        )
    return None


_CONTACT_SUFFIXES = {
    "payload_too_large": "payload",
    "atom_cap_exceeded": "atoms",
}


def _preflight_url(error: str, tier: str) -> str:
    if tier != "pro" or error not in _CONTACT_SUFFIXES:
        return ""
    return f"https://reporails.com/contact/{_CONTACT_SUFFIXES[error]}?utm_source=cli"


def merge_utm(url: str, source: str = "cli") -> str:
    """Append utm_source to URL query string when absent."""
    if not url or not url.startswith(("http://", "https://")):
        return url
    parts = urlsplit(url)
    params = dict(parse_qsl(parts.query, keep_blank_values=True))
    if "utm_source" in params:
        return url
    params["utm_source"] = source
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(params), parts.fragment))


def format_cta(err: FunnelError) -> str:
    """Render the assessment-box CTA for a funnel error."""
    url = merge_utm(err.upgrade_url or err.support_url)
    if err.message:
        return _with_url(err.message, url)
    template = _CTA_TEMPLATES.get((err.error, err.tier)) or _CTA_TEMPLATES.get((err.error, "*"))
    if template is None:
        return _with_url(f"{err.error.replace('_', ' ').capitalize()}.", url)
    return _with_url(template.format(err=err), url)


def _with_url(text: str, url: str) -> str:
    return f"{text} → [bold]{url}[/bold]" if url else text


_CTA_TEMPLATES: dict[tuple[str, str], str] = {
    ("rate_limit_exceeded", "anonymous"): "Anonymous limit hit ({err.limit}/hr). Run `ails auth login` to raise it 40x",
    ("rate_limit_exceeded", "pro"): "Hit your hourly limit ({err.limit}/hr) — file an issue with your use case so we can raise it",
    ("payload_too_large", "anonymous"): "Project too large for anonymous (2 MB cap). Run `ails auth login` to raise it to 20 MB",
    ("payload_too_large", "pro"): "Project exceeds the per-request payload cap — let us know your use case",
    ("atom_cap_exceeded", "anonymous"): (
        "Project too dense ({err.size:,} atoms, {err.limit:,} cap). "
        "Cap doesn't move with sign-up yet — engine work in progress"
    ),
    ("atom_cap_exceeded", "pro"): "Project exceeds {err.limit:,}-atom cap — let us know your use case",
    ("project_limit_reached", "*"): "Project limit reached — file an issue with your use case so we can raise it",
    ("preflight_oversized", "*"): "Payload exceeds local cap before transmission",
}
