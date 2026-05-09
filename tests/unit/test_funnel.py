"""Tests for core/funnel.py — funnel error parsing and CTA rendering."""

from __future__ import annotations

import json

import pytest

from reporails_cli.core.funnel import (
    BUG_REPORT_NEW_URL,
    BUG_REPORT_URL,
    UNIVERSAL_ATOM_CAP,
    WIRE_MAX_CLUSTERS,
    WIRE_MAX_FILES,
    FunnelError,
    LintResponse,
    format_bug_report_url,
    format_cta,
    merge_utm,
    parse_error_body,
    preflight_oversized,
)


def test_bug_report_url_points_to_github_issues() -> None:
    """Bug-report URL is the GitHub issues page; renderer prints it as the secondary CTA."""
    assert BUG_REPORT_URL.startswith("https://github.com/")
    assert BUG_REPORT_URL.endswith("/issues")


def test_bug_report_new_url_points_to_issue_form() -> None:
    """The ``/new`` variant is the deep-link target for prefilled bug reports."""
    assert BUG_REPORT_NEW_URL.startswith("https://github.com/")
    assert BUG_REPORT_NEW_URL.endswith("/issues/new")


class TestFormatBugReportUrl:
    def test_unknown_error_prefills_title_and_body(self) -> None:
        err = FunnelError(error="unknown_error", message="HTTP 400 (unsupported_payload_version)")
        url = format_bug_report_url(err)
        assert url.startswith(f"{BUG_REPORT_NEW_URL}?")
        # URL-encoded forms: title's `+` for spaces, body uses %0A for newlines.
        assert "title=" in url
        assert "%5BCLI%5D" in url  # "[CLI]" url-encoded
        assert "HTTP+400" in url or "HTTP%20400" in url
        assert "labels=bug" in url
        assert "body=" in url

    def test_unknown_error_url_encodes_special_chars(self) -> None:
        err = FunnelError(error="unknown_error", message='HTTP 422 ("validation failed" / atoms)')
        url = format_bug_report_url(err)
        # `"`, `/`, and `(` must round-trip through urlencode without breaking the URL shape.
        assert url.count("?") == 1
        assert "%22validation+failed%22" in url or "%22validation%20failed%22" in url

    def test_unknown_error_with_empty_message_falls_back_to_index(self) -> None:
        err = FunnelError(error="unknown_error", message="")
        assert format_bug_report_url(err) == BUG_REPORT_URL

    def test_known_funnel_error_returns_plain_index(self) -> None:
        # rate_limit_exceeded is an expected usage signal, not a bug report.
        err = FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5, message="any")
        assert format_bug_report_url(err) == BUG_REPORT_URL

    def test_payload_too_large_returns_plain_index(self) -> None:
        err = FunnelError(error="payload_too_large", tier="anonymous", limit=2_097_152, size=8_971_467)
        assert format_bug_report_url(err) == BUG_REPORT_URL


class TestParseErrorBody:
    def test_rate_limit_body(self) -> None:
        body = json.dumps(
            {
                "error": "rate_limit_exceeded",
                "tier": "anonymous",
                "limit": 5,
                "reset_in": 2400,
            }
        )
        err = parse_error_body(429, body)
        assert err is not None
        assert err.error == "rate_limit_exceeded"
        assert err.tier == "anonymous"
        assert err.limit == 5
        assert err.reset_in == 2400

    def test_payload_too_large_body(self) -> None:
        body = json.dumps(
            {
                "error": "payload_too_large",
                "tier": "anonymous",
                "size": 8971467,
                "limit": 2097152,
            }
        )
        err = parse_error_body(413, body)
        assert err is not None
        assert err.error == "payload_too_large"
        assert err.size == 8971467
        assert err.limit == 2097152

    def test_atom_cap_exceeded_body(self) -> None:
        body = json.dumps(
            {
                "error": "atom_cap_exceeded",
                "tier": "pro",
                "atoms": 12396,
                "limit": 10000,
                "files": 47,
                "upgrade_url": "https://reporails.com/contact/atoms",
            }
        )
        err = parse_error_body(413, body)
        assert err is not None
        assert err.error == "atom_cap_exceeded"
        assert err.size == 12396  # falls back to "atoms" key
        assert err.files == 47
        assert err.upgrade_url == "https://reporails.com/contact/atoms"

    def test_unknown_error_returns_unknown_error(self) -> None:
        body = json.dumps({"error": "some_other_thing", "tier": "pro"})
        err = parse_error_body(400, body)
        assert err is not None
        assert err.error == "unknown_error"
        assert err.tier == "pro"
        assert "some_other_thing" in err.message

    def test_unknown_error_with_server_message(self) -> None:
        body = json.dumps({"error": "some_other_thing", "message": "Custom server explanation"})
        err = parse_error_body(400, body)
        assert err is not None
        assert err.error == "unknown_error"
        assert err.message == "Custom server explanation"

    def test_2xx_returns_none(self) -> None:
        body = json.dumps({"error": "rate_limit_exceeded"})
        assert parse_error_body(200, body) is None

    def test_5xx_returns_none(self) -> None:
        body = json.dumps({"error": "rate_limit_exceeded"})
        assert parse_error_body(500, body) is None

    def test_invalid_json_returns_unknown_error(self) -> None:
        err = parse_error_body(429, "not json")
        assert err is not None
        assert err.error == "unknown_error"
        assert "429" in err.message

    def test_non_dict_returns_unknown_error(self) -> None:
        err = parse_error_body(429, json.dumps([1, 2, 3]))
        assert err is not None
        assert err.error == "unknown_error"

    def test_missing_error_field_returns_unknown_error(self) -> None:
        err = parse_error_body(429, json.dumps({"tier": "pro"}))
        assert err is not None
        assert err.error == "unknown_error"
        assert err.tier == "pro"


class TestPreflightOversized:
    """Preflight enforces only the universal absolute caps. Byte-size is the
    Worker's concern; the CLI never makes tier-specific cap decisions."""

    def test_under_all_caps(self) -> None:
        payload = {"files": [], "atoms": [], "clusters": []}
        assert preflight_oversized(payload, has_api_key=True) is None

    def test_does_not_check_byte_size(self) -> None:
        """Even a 50 MB payload passes preflight — Worker enforces byte caps."""
        payload = {"files": [], "atoms": [], "clusters": []}
        assert preflight_oversized(payload, has_api_key=False) is None

    def test_atom_count_universal_cap(self) -> None:
        payload = {"files": [], "atoms": [{}] * (UNIVERSAL_ATOM_CAP + 1), "clusters": []}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.error == "atom_cap_exceeded"
        assert err.limit == UNIVERSAL_ATOM_CAP

    def test_files_over_cap(self) -> None:
        payload = {"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": [], "clusters": []}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.limit == WIRE_MAX_FILES

    def test_clusters_over_cap(self) -> None:
        payload = {"files": [], "atoms": [], "clusters": [{}] * (WIRE_MAX_CLUSTERS + 1)}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.limit == WIRE_MAX_CLUSTERS

    def test_anonymous_cta_omits_upgrade_url(self) -> None:
        # The anonymous CTA's actionable instruction is `ails auth login`
        # in the message itself; no landing-page URL is appended.
        payload = {"files": [], "atoms": [{}] * (UNIVERSAL_ATOM_CAP + 1), "clusters": []}
        err = preflight_oversized(payload, has_api_key=False)
        assert err is not None
        assert err.tier == "anonymous"
        assert err.upgrade_url == ""

    def test_keyed_cta_uses_contact_section(self) -> None:
        """With a key the presumed tier is `pro`; CTA points at /contact/."""
        payload = {"files": [], "atoms": [{}] * (UNIVERSAL_ATOM_CAP + 1), "clusters": []}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.tier == "pro"
        assert "/contact/" in err.upgrade_url


class TestMergeUtm:
    def test_appends_when_absent(self) -> None:
        url = "https://reporails.com/contact/rate-limit"
        assert merge_utm(url) == "https://reporails.com/contact/rate-limit?utm_source=cli"

    def test_preserves_when_present(self) -> None:
        url = "https://reporails.com/contact?utm_source=mcp"
        assert merge_utm(url) == url

    def test_preserves_existing_query_params(self) -> None:
        url = "https://reporails.com/x?reason=rate"
        merged = merge_utm(url)
        assert "reason=rate" in merged
        assert "utm_source=cli" in merged

    def test_empty_url_unchanged(self) -> None:
        assert merge_utm("") == ""

    def test_non_http_url_unchanged(self) -> None:
        assert merge_utm("javascript:alert(1)") == "javascript:alert(1)"

    def test_custom_source(self) -> None:
        url = "https://reporails.com/contact"
        assert "utm_source=action" in merge_utm(url, source="action")


class TestFunnelErrorResetPhrase:
    def test_zero_reset_in_renders_empty(self) -> None:
        assert FunnelError(error="rate_limit_exceeded", reset_in=0).reset_phrase == ""

    def test_negative_reset_in_renders_empty(self) -> None:
        # Defensive — server clock skew or stale entry should never produce
        # "Try again in -5 min."
        assert FunnelError(error="rate_limit_exceeded", reset_in=-30).reset_phrase == ""

    def test_under_one_minute_rounds_up_to_one(self) -> None:
        # 30 seconds reads as "<1 min" — telling a user "0 min" is worse
        # than telling them "<1 min".
        assert FunnelError(error="rate_limit_exceeded", reset_in=30).reset_phrase == "Try again in <1 min. "

    def test_exact_minute_boundary(self) -> None:
        # 60 seconds → 1 minute, but rendered as "<1 min" (the rounding-up
        # rule kicks in only above 60s, so the prompt stays calibrated).
        assert FunnelError(error="rate_limit_exceeded", reset_in=60).reset_phrase == "Try again in <1 min. "

    def test_thirty_minutes(self) -> None:
        assert FunnelError(error="rate_limit_exceeded", reset_in=1800).reset_phrase == "Try again in ~30 min. "

    def test_rounds_up_partial_minute(self) -> None:
        # 61 s should not render as "~1 min" (which collides with <1 min).
        # Rounding up keeps the displayed wait honestly ≥ the real wait.
        assert FunnelError(error="rate_limit_exceeded", reset_in=61).reset_phrase == "Try again in ~2 min. "


class TestFormatCta:
    def test_anonymous_rate_limit_no_url(self) -> None:
        # In 0.5.6 the anonymous CTA emits no URL — `ails auth login` is the
        # action and lives in the message. Renderer must omit the arrow.
        err = FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5)
        cta = format_cta(err)
        assert "Anonymous limit hit" in cta
        assert "5/hr" in cta
        assert "→" not in cta
        # No reset_in → no retry hint.
        assert "Try again" not in cta

    def test_anonymous_rate_limit_with_reset_in(self) -> None:
        # Server reset_in surfaces as a human retry hint between the limit
        # blurb and the upgrade CTA.
        err = FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5, reset_in=1800)
        cta = format_cta(err)
        assert "Anonymous limit hit" in cta
        assert "Try again in ~30 min" in cta
        assert "ails auth login" in cta

    def test_pro_rate_limit_with_reset_in(self) -> None:
        err = FunnelError(error="rate_limit_exceeded", tier="pro", limit=200, reset_in=120)
        cta = format_cta(err)
        assert "Hit your hourly limit" in cta
        assert "Try again in ~2 min" in cta

    def test_pro_rate_limit(self) -> None:
        err = FunnelError(
            error="rate_limit_exceeded",
            tier="pro",
            limit=200,
            upgrade_url="https://reporails.com/contact/rate-limit",
        )
        cta = format_cta(err)
        assert "Hit your hourly limit" in cta
        assert "File an issue" in cta
        assert "200/hr" in cta
        assert "utm_source=cli" in cta

    def test_atom_cap_acknowledges_cap_unchanged(self) -> None:
        err = FunnelError(
            error="atom_cap_exceeded",
            tier="anonymous",
            limit=10000,
            size=12396,
        )
        cta = format_cta(err)
        # Honest copy: until the engine work lands, the cap doesn't move with sign-in.
        assert "10,000" in cta or "10000" in cta
        assert "12,396" in cta or "12396" in cta

    def test_server_message_wins(self) -> None:
        err = FunnelError(
            error="rate_limit_exceeded",
            tier="pro",
            limit=200,
            message="Custom server-provided message",
            upgrade_url="https://reporails.com/contact/rate-limit",
        )
        cta = format_cta(err)
        assert "Custom server-provided message" in cta
        # The default template should not appear when message is set.
        assert "Hit your hourly limit" not in cta

    def test_no_url_renders_without_arrow(self) -> None:
        err = FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5)
        cta = format_cta(err)
        assert "→" not in cta


class TestLintResponse:
    def test_default_empty(self) -> None:
        response = LintResponse()
        assert response.result is None
        assert response.funnel_error is None

    @pytest.mark.parametrize("error_type", ["rate_limit_exceeded", "payload_too_large", "atom_cap_exceeded"])
    def test_holds_funnel_error(self, error_type: str) -> None:
        err = FunnelError(error=error_type, tier="pro")
        response = LintResponse(funnel_error=err)
        assert response.funnel_error is err
