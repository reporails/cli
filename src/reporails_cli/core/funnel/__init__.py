"""Funnel error parsing and CTA rendering."""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

logger = logging.getLogger(__name__)


UNIVERSAL_ATOM_CAP = 10_000
BUG_REPORT_URL = "https://github.com/reporails/cli/issues"
BUG_REPORT_NEW_URL = "https://github.com/reporails/cli/issues/new"
WIRE_MAX_FILES = 500
WIRE_MAX_CLUSTERS = 2000

# Per-tier body byte caps. Mirrored locally so preflight_byte_size returns
# a FunnelError before transmission instead of a server 4xx.
WIRE_MAX_BYTES_BY_TIER = {
    "anonymous": 2 * 1024 * 1024,
    "pro": 20 * 1024 * 1024,
}


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

    @property
    def reset_phrase(self) -> str:
        """Render reset_in as a CTA fragment: 'Try again in ~N min. ' or ''."""
        if self.reset_in <= 0:
            return ""
        minutes = (self.reset_in + 59) // 60
        label = "<1 min" if minutes <= 1 else f"~{minutes} min"
        return f"Try again in {label}. "


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
        logger.debug("Non-JSON %d response body: %r", status_code, body_text[:200])
        return FunnelError(
            error="unknown_error",
            message=f"Diagnostics server returned HTTP {status_code}",
        )
    if not isinstance(body, dict):
        logger.debug("Unexpected %d response shape: %r", status_code, body_text[:200])
        return FunnelError(
            error="unknown_error",
            message=f"Diagnostics server returned HTTP {status_code}",
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


def preflight_byte_size(
    body_bytes: int,
    has_api_key: bool,
) -> FunnelError | None:
    """Reject the request when the encoded body exceeds the worker's per-tier cap.

    The backend enforces this cap before any processing. Catching it locally
    surfaces the conversion CTA in the user's terminal instead of an opaque
    server-side 413.
    """
    presumed_tier = "pro" if has_api_key else "anonymous"
    limit = WIRE_MAX_BYTES_BY_TIER.get(presumed_tier, WIRE_MAX_BYTES_BY_TIER["anonymous"])
    if body_bytes <= limit:
        return None
    return FunnelError(
        error="payload_too_large",
        tier=presumed_tier,
        limit=limit,
        size=body_bytes,
        upgrade_url=_preflight_url("payload_too_large", presumed_tier),
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


def _cli_version() -> str:
    """Return the installed CLI version, or 'unknown' if metadata is missing."""
    try:
        from importlib.metadata import version

        return version("reporails-cli")
    except Exception:  # importlib.metadata.PackageNotFoundError + defensive
        return "unknown"


def format_bug_report_url(err: FunnelError) -> str:
    """Return the GitHub-issues URL for the bug-report exit ramp.

    For ``unknown_error`` (an unrecognized 4xx body or a transport failure that
    surfaced as "actual error") we deep-link to ``/issues/new`` with the title
    and a triage-ready body prefilled, so the user lands one click + a few
    lines from a filed issue. For known funnel errors (rate limit, payload too
    large) we return the plain ``/issues`` index — those are usage signals,
    not bug reports, and a deep link would invite spurious "feature request"
    issues.
    """
    if err.error != "unknown_error" or not err.message:
        return BUG_REPORT_URL

    title = f"[CLI] {err.message}"
    body = (
        "## What happened\n\n"
        f"{err.message}\n\n"
        "## Environment\n\n"
        f"- reporails-cli: {_cli_version()}\n"
        f"- OS: {sys.platform}\n"
        f"- Python: {sys.version.split()[0]}\n\n"
        "## Steps to reproduce\n\n"
        "<please describe the command you ran and the project shape>\n"
    )
    params = urlencode({"title": title, "body": body, "labels": "bug"})
    return f"{BUG_REPORT_NEW_URL}?{params}"


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


def _short_url_label(url: str) -> str:
    """Return `netloc + path` from a URL, dropping query string and fragment.

    Used as the clickable label in OSC 8 hyperlinks so the user sees
    `github.com/reporails/cli/issues/new` instead of an 800-character
    percent-encoded prefilled form URL.
    """
    parts = urlsplit(url)
    return f"{parts.netloc}{parts.path}" if parts.netloc else url


def _with_url(text: str, url: str) -> str:
    if not url:
        return text
    label = _short_url_label(url)
    return f"{text} → [link={url}][bold]{label}[/bold][/link]"


_CTA_TEMPLATES: dict[tuple[str, str], str] = {
    (
        "rate_limit_exceeded",
        "anonymous",
    ): "Anonymous limit hit ({err.limit}/hr). {err.reset_phrase}Run `ails auth login` to raise it 40x",
    ("rate_limit_exceeded", "pro"): (
        "Hit your hourly limit ({err.limit}/hr). {err.reset_phrase}File an issue with your use case so we can raise it"
    ),
    ("payload_too_large", "anonymous"): (
        "Project too large for anonymous (2 MB cap). Run `ails auth login` to raise it to 20 MB"
    ),
    ("payload_too_large", "pro"): "Project exceeds the per-request payload cap — let us know your use case",
    ("atom_cap_exceeded", "anonymous"): (
        "Project too dense ({err.size:,} atoms, {err.limit:,} cap). "
        "Cap doesn't move with sign-up yet — engine work in progress"
    ),
    ("atom_cap_exceeded", "pro"): "Project exceeds {err.limit:,}-atom cap — let us know your use case",
    ("project_limit_reached", "*"): "Project limit reached — file an issue with your use case so we can raise it",
    ("preflight_oversized", "*"): "Payload exceeds local cap before transmission",
}
