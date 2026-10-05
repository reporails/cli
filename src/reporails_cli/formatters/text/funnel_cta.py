"""Conversion-CTA rendering for funnel errors.

Turns a `FunnelError` into the assessment-box CTA string and the bug-report
exit-ramp URL. Copy strings live here; their authoring rationale is kept out of
the shipped tarball.
"""

from __future__ import annotations

import sys
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from reporails_cli.core.platform.dto.diagnostics import DEFAULT_RETRY_AFTER_S, UNENTITLED_TIERS, FunnelError

BUG_REPORT_URL = "https://github.com/reporails/cli/issues"
BUG_REPORT_NEW_URL = "https://github.com/reporails/cli/issues/new"

# The subscribe/upgrade landing for a keyed-but-unentitled (`free`) principal —
# the account page, where the subscribe action lives.
_SUBSCRIBE_URL = "https://reporails.com/account?utm_source=cli"

# Free-tier rejections where subscribing genuinely lifts the cap, so the CTA
# carries the subscribe link. The atom cap is universal (no tier moves it), so
# it is deliberately excluded — its copy makes no subscribe promise.
_FREE_SUBSCRIBE_ERRORS = {"rate_limit_exceeded", "payload_too_large"}


# Why a refused run carries no score, by error code. Any other error means the server was
# unreachable or broken, so the score is simply unavailable.
_REFUSAL_REASONS = {
    "rate_limit_exceeded": "hourly limit reached",
    "payload_too_large": "project over your plan's size cap",
    "atom_cap_exceeded": "project over the size cap",
    "file_cap_exceeded": "project over the size cap",
    "scoring_limit_exceeded": "project too large to score",
}


def no_score_reason(err: object) -> str:
    """The few words after `n/a` on the Quality line when a run has no score."""
    if isinstance(err, FunnelError):
        return _REFUSAL_REASONS.get(err.error, "server diagnostics unavailable")
    return "server diagnostics unavailable"


def _has_key() -> bool:
    """True when this CLI holds an API key (env override or stored credentials)."""
    from reporails_cli.core.platform.adapters.api_client import has_api_key

    return has_api_key()


def _cta_tier(err: FunnelError) -> str:
    """Return the tier key for template + URL selection.

    The wire tier alone cannot pick the copy: ``anonymous`` and ``free`` carry
    identical caps, and what differs is whether the caller already holds a key.
    A keyless caller must be told to sign in first; a keyed caller must not be
    sent to a login they already completed. So an unentitled wire tier resolves
    to ``free`` when a key is held and ``anonymous`` when none is, and every
    other wire tier (``pro``) passes through.
    """
    # Unentitled tiers share identical caps; the copy that converts depends on whether the caller
    # can already act on an upgrade link.
    if err.tier in UNENTITLED_TIERS or not err.tier:
        return "free" if _has_key() else "anonymous"
    return err.tier


def _cta_upgrade_url(err: FunnelError) -> str:
    """Return the URL for the CTA arrow.

    Prefers the server-provided ``upgrade_url``. When absent, a keyed-``free``
    rate-limit or payload rejection defaults to the subscribe form; every other
    case has no default (renders without an arrow).
    """
    if err.upgrade_url:
        return err.upgrade_url
    if _cta_tier(err) == "free" and err.error in _FREE_SUBSCRIBE_ERRORS:
        return _SUBSCRIBE_URL
    return err.support_url


def _cli_version() -> str:
    """Return the installed CLI version, or 'unknown' if metadata is missing."""
    try:
        return version("reporails-cli")
    except PackageNotFoundError:
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
    """Render the assessment-box CTA for a funnel error.

    A server-supplied ``err.message`` is escaped (`rich.markup.escape`) before it enters
    the template: the server body is untrusted text, and an unescaped `[/bold]`-shaped
    fragment or bracket run raises `rich.errors.MarkupError` the moment this string is
    actually rendered — by `console.print` in the terminal CTA (`display.py::_render_funnel_cta`)
    or by `plain_cta`'s markup-strip below. Escaping here is the single point both paths
    render safely from.
    """
    from rich.markup import escape as escape_markup

    if err.retryable:
        return retry_text(err)
    url = merge_utm(_cta_upgrade_url(err))
    if err.message:
        return _with_url(escape_markup(err.message), url)
    tier = _cta_tier(err)
    template = _CTA_TEMPLATES.get((err.error, tier)) or _CTA_TEMPLATES.get((err.error, "*"))
    if template is None:
        return _with_url(f"{err.error.replace('_', ' ').capitalize()}.", url)
    return _with_url(template.format(err=err), url)


def retry_text(err: FunnelError) -> str:
    """The plain line for a busy server, a request that took too long, or the client's own timeout."""
    seconds = err.reset_in if err.reset_in > 0 else DEFAULT_RETRY_AFTER_S
    wait = f"{seconds} second{'' if seconds == 1 else 's'}"
    if err.error == "server_busy":
        return f"The diagnostics server is busy. Try again in {wait}."
    return f"The diagnostics request took too long. Try again in {wait}."


def plain_cta(err: FunnelError) -> str:
    """Render the CTA as plain text — no Rich markup, safe for machine consumers.

    Single source for `formatters/json.py::format_server_error`'s `message` field and
    `interfaces/mcp/tools.py::_attach_funnel`'s `funnel.message`, so a rate-limit /
    payload-cap / atom-cap rejection reads identically on both surfaces — neither carries
    `format_cta`'s terminal `[link=...][bold]...[/bold][/link]` tags. Disables emoji
    substitution (``emoji=False``) so a server ``message`` containing a `:name:`
    shortcode renders as the literal text, not a substituted emoji glyph, in JSON/MCP
    output.
    """
    from rich.markup import render as render_markup

    return render_markup(format_cta(err), emoji=False).plain


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
    ): (
        "Anonymous limit hit ({err.limit}/hr). {err.reset_phrase}"
        "Sign in with `ails auth login`, then upgrade to Pro to raise it to 1,200/hr"
    ),
    ("rate_limit_exceeded", "free"): (
        "Hit the free limit ({err.limit}/hr). {err.reset_phrase}Upgrade to Pro to raise it to 1,200/hr"
    ),
    ("rate_limit_exceeded", "pro"): (
        "Hit your hourly limit ({err.limit}/hr). {err.reset_phrase}File an issue with your use case so we can raise it"
    ),
    ("payload_too_large", "anonymous"): (
        "Project too large for anonymous (2 MB cap). "
        "Sign in with `ails auth login`, then upgrade to Pro to raise it to 20 MB"
    ),
    ("payload_too_large", "free"): (
        "Project too large on the free tier (2 MB cap). Upgrade to Pro to raise it to 20 MB"
    ),
    ("payload_too_large", "pro"): "Project exceeds the per-request payload cap — let us know your use case",
    ("atom_cap_exceeded", "anonymous"): (
        "Project too dense ({err.size:,} atoms, {err.limit:,} cap). The cap is the same on every plan"
    ),
    ("atom_cap_exceeded", "free"): (
        "Project too dense ({err.size:,} atoms, {err.limit:,} cap). The cap is the same on every plan"
    ),
    ("atom_cap_exceeded", "pro"): "Project exceeds {err.limit:,}-atom cap — let us know your use case",
    ("project_limit_reached", "*"): "Project limit reached — file an issue with your use case so we can raise it",
    ("file_cap_exceeded", "*"): (
        "Project has {err.files:,} files, over the {err.limit:,}-file cap — the same cap on every plan"
    ),
    ("scoring_limit_exceeded", "*"): (
        "Project too large to score in one request. "
        "Check a smaller part with `ails check <path>`, or file an issue with your use case"
    ),
    ("preflight_oversized", "*"): "Payload exceeds local cap before transmission",
}
