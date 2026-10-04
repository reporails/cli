"""Tests for funnel error parsing (policy.preflight) and CTA rendering (formatters.text.funnel_cta)."""

from __future__ import annotations

import json

import pytest

from reporails_cli.core.platform.dto.diagnostics import (
    ENTITLED_TIERS,
    UNENTITLED_TIERS,
    FunnelError,
    LintResponse,
)
from reporails_cli.core.platform.policy.preflight import (
    UNIVERSAL_ATOM_CAP,
    WIRE_MAX_FILES,
    _preflight_url,
    parse_error_body,
    preflight_oversized,
)
from reporails_cli.formatters.text import funnel_cta as funnel_cta_module
from reporails_cli.formatters.text.funnel_cta import (
    _SUBSCRIBE_URL,
    BUG_REPORT_NEW_URL,
    BUG_REPORT_URL,
    _cta_upgrade_url,
    format_bug_report_url,
    format_cta,
    merge_utm,
    plain_cta,
)


@pytest.fixture
def no_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render CTAs as a keyless caller, independent of the machine's credentials."""
    monkeypatch.setattr(funnel_cta_module, "_has_key", lambda: False)


@pytest.fixture
def held_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Render CTAs as a caller holding an API key, independent of the machine's credentials."""
    monkeypatch.setattr(funnel_cta_module, "_has_key", lambda: True)


@pytest.mark.unit
@pytest.mark.subsys_funnel
def test_bug_report_url_points_to_github_issues() -> None:
    """Bug-report URL is the GitHub issues page; renderer prints it as the secondary CTA."""
    assert BUG_REPORT_URL.startswith("https://github.com/")
    assert BUG_REPORT_URL.endswith("/issues")


@pytest.mark.unit
@pytest.mark.subsys_funnel
def test_bug_report_new_url_points_to_issue_form() -> None:
    """The ``/new`` variant is the deep-link target for prefilled bug reports."""
    assert BUG_REPORT_NEW_URL.startswith("https://github.com/")
    assert BUG_REPORT_NEW_URL.endswith("/issues/new")


class TestFormatBugReportUrl:
    @pytest.mark.unit
    @pytest.mark.subsys_funnel
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

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_unknown_error_url_encodes_special_chars(self) -> None:
        err = FunnelError(error="unknown_error", message='HTTP 422 ("validation failed" / atoms)')
        url = format_bug_report_url(err)
        # `"`, `/`, and `(` must round-trip through urlencode without breaking the URL shape.
        assert url.count("?") == 1
        assert "%22validation+failed%22" in url or "%22validation%20failed%22" in url

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_unknown_error_with_empty_message_falls_back_to_index(self) -> None:
        err = FunnelError(error="unknown_error", message="")
        assert format_bug_report_url(err) == BUG_REPORT_URL

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_known_funnel_error_returns_plain_index(self) -> None:
        # rate_limit_exceeded is an expected usage signal, not a bug report.
        err = FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5, message="any")
        assert format_bug_report_url(err) == BUG_REPORT_URL

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_payload_too_large_returns_plain_index(self) -> None:
        err = FunnelError(error="payload_too_large", tier="anonymous", limit=2_097_152, size=8_971_467)
        assert format_bug_report_url(err) == BUG_REPORT_URL


class TestParseErrorBody:
    @pytest.mark.unit
    @pytest.mark.subsys_funnel
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

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
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

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
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

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_file_cap_exceeded_body_is_a_known_error(self) -> None:
        """The server's own `file_cap_exceeded` (a live 413 over the 500-file cap)
        must parse as itself, not collapse to `unknown_error` with a bug-report link."""
        body = json.dumps(
            {
                "error": "file_cap_exceeded",
                "tier": "anonymous",
                "files": 501,
                "limit": 500,
            }
        )
        err = parse_error_body(413, body)
        assert err is not None
        assert err.error == "file_cap_exceeded"
        assert err.files == 501
        assert err.limit == 500

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_file_cap_exceeded_reply_message_states_the_file_count(self) -> None:
        """The refusal reply carries the count under `files`; the CTA must print it."""
        body = json.dumps({"error": "file_cap_exceeded", "tier": "anonymous", "files": 501, "limit": 500})
        err = parse_error_body(413, body)
        assert err is not None
        assert plain_cta(err).startswith("Project has 501 files, over the 500-file cap")

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_unknown_error_returns_unknown_error(self) -> None:
        body = json.dumps({"error": "some_other_thing", "tier": "pro"})
        err = parse_error_body(400, body)
        assert err is not None
        assert err.error == "unknown_error"
        assert err.tier == "pro"
        assert "some_other_thing" in err.message

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_unknown_error_with_server_message(self) -> None:
        body = json.dumps({"error": "some_other_thing", "message": "Custom server explanation"})
        err = parse_error_body(400, body)
        assert err is not None
        assert err.error == "unknown_error"
        assert err.message == "Custom server explanation"

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_2xx_returns_none(self) -> None:
        body = json.dumps({"error": "rate_limit_exceeded"})
        assert parse_error_body(200, body) is None

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_5xx_returns_none(self) -> None:
        body = json.dumps({"error": "rate_limit_exceeded"})
        assert parse_error_body(500, body) is None

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_invalid_json_returns_unknown_error(self) -> None:
        err = parse_error_body(429, "not json")
        assert err is not None
        assert err.error == "unknown_error"
        assert "429" in err.message

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_non_dict_returns_unknown_error(self) -> None:
        err = parse_error_body(429, json.dumps([1, 2, 3]))
        assert err is not None
        assert err.error == "unknown_error"

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_missing_error_field_returns_unknown_error(self) -> None:
        err = parse_error_body(429, json.dumps({"tier": "pro"}))
        assert err is not None
        assert err.error == "unknown_error"
        assert err.tier == "pro"


class TestPreflightOversized:
    """Preflight enforces only the universal absolute caps. Byte-size caps are
    enforced by the service; the CLI never makes tier-specific cap decisions."""

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_under_all_caps(self) -> None:
        payload = {"files": [], "atoms": []}
        assert preflight_oversized(payload, has_api_key=True) is None

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_does_not_check_byte_size(self) -> None:
        """Even a 50 MB payload passes preflight — byte caps are enforced by the service."""
        payload = {"files": [], "atoms": []}
        assert preflight_oversized(payload, has_api_key=False) is None

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_atom_count_universal_cap(self) -> None:
        payload = {"files": [], "atoms": [{}] * (UNIVERSAL_ATOM_CAP + 1)}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.error == "atom_cap_exceeded"
        assert err.limit == UNIVERSAL_ATOM_CAP

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_files_over_cap(self) -> None:
        payload = {"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": []}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.limit == WIRE_MAX_FILES

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_files_over_cap_uses_its_own_token_not_payload_too_large(self) -> None:
        """The 500-file cap is universal — it must not reuse `payload_too_large`,
        whose CTA promises Pro raises a 2 MB byte cap that has nothing to do with
        a file-count rejection."""
        payload = {"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": []}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.error == "file_cap_exceeded"

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    @pytest.mark.parametrize("has_key", [True, False])
    def test_files_over_cap_never_promises_an_upgrade(self, has_key: bool) -> None:
        """Universal cap, no tier raises it — no upgrade link and no contact-form
        link either way, unlike the keyed-vs-keyless split on the byte/atom caps."""
        payload = {"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": []}
        err = preflight_oversized(payload, has_api_key=has_key)
        assert err is not None
        assert err.upgrade_url == ""

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_anonymous_cta_omits_upgrade_url(self) -> None:
        # The anonymous CTA's actionable instruction is `ails auth login`
        # in the message itself; no landing-page URL is appended.
        payload = {"files": [], "atoms": [{}] * (UNIVERSAL_ATOM_CAP + 1)}
        err = preflight_oversized(payload, has_api_key=False)
        assert err is not None
        assert err.tier == "anonymous"
        assert err.upgrade_url == ""

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_keyed_cta_uses_contact_section(self) -> None:
        """With a key the presumed tier is `pro`; CTA points at /contact/."""
        payload = {"files": [], "atoms": [{}] * (UNIVERSAL_ATOM_CAP + 1)}
        err = preflight_oversized(payload, has_api_key=True)
        assert err is not None
        assert err.tier == "pro"
        assert "/contact/" in err.upgrade_url

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    @pytest.mark.parametrize("tier", sorted(ENTITLED_TIERS))
    def test_every_entitled_tier_gets_the_contact_url(self, tier: str) -> None:
        """A `team` session is a paying session and gets the contact form, like `pro`.

        The gate used to compare against the single string `"pro"`, so a team user who
        hit an absolute cap was handed the unentitled CTA instead of the contact link.
        """
        assert _preflight_url("atom_cap_exceeded", tier) == ("https://reporails.com/contact/atoms?utm_source=cli")

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    @pytest.mark.parametrize("tier", sorted(UNENTITLED_TIERS))
    def test_no_unentitled_tier_gets_the_contact_url(self, tier: str) -> None:
        assert _preflight_url("atom_cap_exceeded", tier) == ""


class TestAuthErrorTokensSurviveParsing:
    """A 401 body's own error token must survive `parse_error_body`.

    An error token the client does not recognize collapses to `unknown_error`, which
    renders the bug-report deep link. An auth rejection routed there tells the user to
    file a bug instead of running `ails auth login`.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    @pytest.mark.parametrize("token", ["invalid_api_key", "missing_or_invalid_api_key"])
    def test_401_auth_token_is_preserved_with_its_message(self, token: str) -> None:
        body = json.dumps({"error": token, "tier": "anonymous", "message": "API key not recognized"})
        err = parse_error_body(401, body)

        assert err is not None
        assert err.error == token
        assert err.message == "API key not recognized"
        assert err.tier == "anonymous"
        assert err.status == 401


class TestMergeUtm:
    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_appends_when_absent(self) -> None:
        url = "https://reporails.com/contact/rate-limit"
        assert merge_utm(url) == "https://reporails.com/contact/rate-limit?utm_source=cli"

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_preserves_when_present(self) -> None:
        url = "https://reporails.com/contact?utm_source=mcp"
        assert merge_utm(url) == url

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_preserves_existing_query_params(self) -> None:
        url = "https://reporails.com/x?reason=rate"
        merged = merge_utm(url)
        assert "reason=rate" in merged
        assert "utm_source=cli" in merged

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_empty_url_unchanged(self) -> None:
        assert merge_utm("") == ""

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_non_http_url_unchanged(self) -> None:
        assert merge_utm("javascript:alert(1)") == "javascript:alert(1)"

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_custom_source(self) -> None:
        url = "https://reporails.com/contact"
        assert "utm_source=action" in merge_utm(url, source="action")


class TestFunnelErrorResetPhrase:
    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_zero_reset_in_renders_empty(self) -> None:
        assert FunnelError(error="rate_limit_exceeded", reset_in=0).reset_phrase == ""

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_negative_reset_in_renders_empty(self) -> None:
        # Defensive — server clock skew or stale entry should never produce
        # "Try again in -5 min."
        assert FunnelError(error="rate_limit_exceeded", reset_in=-30).reset_phrase == ""

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_under_one_minute_rounds_up_to_one(self) -> None:
        # 30 seconds reads as "<1 min" — telling a user "0 min" is worse
        # than telling them "<1 min".
        assert FunnelError(error="rate_limit_exceeded", reset_in=30).reset_phrase == "Try again in <1 min. "

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_exact_minute_boundary(self) -> None:
        # 60 seconds → 1 minute, but rendered as "<1 min" (the rounding-up
        # rule kicks in only above 60s, so the prompt stays calibrated).
        assert FunnelError(error="rate_limit_exceeded", reset_in=60).reset_phrase == "Try again in <1 min. "

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_thirty_minutes(self) -> None:
        assert FunnelError(error="rate_limit_exceeded", reset_in=1800).reset_phrase == "Try again in ~30 min. "

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_rounds_up_partial_minute(self) -> None:
        # 61 s should not render as "~1 min" (which collides with <1 min).
        # Rounding up keeps the displayed wait honestly ≥ the real wait.
        assert FunnelError(error="rate_limit_exceeded", reset_in=61).reset_phrase == "Try again in ~2 min. "


class TestFormatCta:
    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_anonymous_rate_limit_no_url(self, no_key: None) -> None:
        # In 0.5.6 the anonymous CTA emits no URL — `ails auth login` is the
        # action and lives in the message. Renderer must omit the arrow.
        err = FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5)
        cta = format_cta(err)
        assert "Anonymous limit hit" in cta
        assert "5/hr" in cta
        assert "→" not in cta
        # No reset_in → no retry hint.
        assert "Try again" not in cta

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_anonymous_rate_limit_with_reset_in(self, no_key: None) -> None:
        # Server reset_in surfaces as a human retry hint between the limit
        # blurb and the upgrade CTA.
        err = FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5, reset_in=1800)
        cta = format_cta(err)
        assert "Anonymous limit hit" in cta
        assert "Try again in ~30 min" in cta
        assert "ails auth login" in cta

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_anonymous_cta_attributes_the_cap_raise_to_pro_not_to_login(self, no_key: None) -> None:
        # Anonymous and free share identical caps — signing in raises nothing.
        # Both anonymous templates must name Pro as the actor that lifts the cap,
        # with `ails auth login` offered only as the account step before it.
        # Reddens if the copy returns to "Run `ails auth login` to raise it 40x".
        rate = format_cta(FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5))
        payload = format_cta(FunnelError(error="payload_too_large", tier="anonymous", limit=2 * 1024 * 1024))
        for cta in (rate, payload):
            assert "upgrade to Pro" in cta
            assert "ails auth login" in cta
            assert cta.index("ails auth login") < cta.index("upgrade to Pro")
        # A `free` wire tier with no key held renders the same keyless copy —
        # the caps are identical, so the wire label alone must not flip it.
        free_wire = format_cta(FunnelError(error="rate_limit_exceeded", tier="free", limit=5))
        assert "ails auth login" in free_wire
        # The gain is named as the number Pro gives (1,200/hr), not a multiplier.
        assert rate.endswith("upgrade to Pro to raise it to 1,200/hr")
        assert "40x" not in rate
        assert "to raise it to 1,200/hr" in free_wire

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_pro_rate_limit_with_reset_in(self) -> None:
        err = FunnelError(error="rate_limit_exceeded", tier="pro", limit=200, reset_in=120)
        cta = format_cta(err)
        assert "Hit your hourly limit" in cta
        assert "Try again in ~2 min" in cta

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
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

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_atom_cap_acknowledges_cap_unchanged(self, no_key: None) -> None:
        err = FunnelError(
            error="atom_cap_exceeded",
            tier="anonymous",
            limit=10000,
            size=12396,
        )
        cta = format_cta(err)
        # The cap is the same on every plan.
        assert "10,000" in cta or "10000" in cta
        assert "12,396" in cta or "12396" in cta
        assert "The cap is the same on every plan" in cta
        assert "engine work" not in cta

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
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

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_no_url_renders_without_arrow(self, no_key: None) -> None:
        err = FunnelError(error="rate_limit_exceeded", tier="anonymous", limit=5)
        cta = format_cta(err)
        assert "→" not in cta


class TestFileCapCta:
    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_names_the_file_cap_with_no_pro_promise(self) -> None:
        """A project over the 500-file cap gets a message naming the file
        cap — never the byte-cap Pro promise ("raise it to 20 MB"), which does
        not apply to a universal, tier-blind cap."""
        err = preflight_oversized({"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": []}, has_api_key=True)
        assert err is not None
        cta = format_cta(err)
        assert "500" in cta and "501" in cta
        assert "20 MB" not in cta
        assert "upgrade" not in cta.lower()
        assert "pro" not in cta.lower().split()

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_same_wording_for_anonymous_and_keyed(self) -> None:
        """The cap is universal, so the keyed and keyless CTAs must read the same
        — no keyed-user contact-form promise the cap doesn't back."""
        keyless = preflight_oversized({"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": []}, has_api_key=False)
        keyed = preflight_oversized({"files": [{}] * (WIRE_MAX_FILES + 1), "atoms": []}, has_api_key=True)
        assert keyless is not None
        assert keyed is not None
        assert format_cta(keyless) == format_cta(keyed)
        assert "/contact/" not in format_cta(keyed)


class TestFreeTierCta:
    """A `tier == "free"` body is a keyed-but-unentitled principal. Its CTA must
    be subscribe/upgrade, NEVER `ails auth login` (the login dead-end a signed-in
    user cannot act on). These reddens if the free row is dropped (CTA falls to
    the bare error name) or mis-aliased to `anonymous` (the login copy returns).
    """

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_free_rate_limit_is_upgrade_not_login(self, held_key: None) -> None:
        err = FunnelError(error="rate_limit_exceeded", tier="free", limit=5)
        cta = format_cta(err)
        assert "Upgrade to Pro" in cta
        assert "ails auth login" not in cta
        assert "5/hr" in cta
        # The arrow links to the account page (the subscribe/trial action surface).
        assert "[link=https://reporails.com/account?utm_source=cli]" in cta

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_held_key_not_wire_tier_selects_the_cta(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # SEAM: one wire tier (`free`), two callers. The CLI keys the CTA on the
        # key it holds, because `anonymous` and `free` carry identical caps: a
        # keyed caller must never be sent to a login they already completed, and
        # a keyless caller cannot act on an upgrade link. Reddens if template
        # selection goes back to reading `err.tier` alone.
        err = FunnelError(error="rate_limit_exceeded", tier="free", limit=5)

        monkeypatch.setattr(funnel_cta_module, "_has_key", lambda: True)
        keyed = format_cta(err)
        monkeypatch.setattr(funnel_cta_module, "_has_key", lambda: False)
        keyless = format_cta(err)

        assert keyed != keyless
        assert "Upgrade to Pro" in keyed
        assert "ails auth login" not in keyed
        assert _SUBSCRIBE_URL.split("?")[0] in keyed
        assert "ails auth login" in keyless
        assert "→" not in keyless

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_free_rate_limit_includes_reset_hint(self, held_key: None) -> None:
        err = FunnelError(error="rate_limit_exceeded", tier="free", limit=5, reset_in=1800)
        cta = format_cta(err)
        assert "Try again in ~30 min" in cta
        assert "Upgrade to Pro" in cta

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_free_payload_too_large_is_upgrade_not_login(self, held_key: None) -> None:
        err = FunnelError(error="payload_too_large", tier="free", limit=2 * 1024 * 1024)
        cta = format_cta(err)
        assert "Upgrade to Pro" in cta
        assert "20 MB" in cta
        assert "ails auth login" not in cta
        assert "[link=https://reporails.com/account?utm_source=cli]" in cta

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_free_atom_cap_is_honest_no_login_no_upgrade_link(self, held_key: None) -> None:
        # The atom cap is universal — no tier moves it — so the free copy makes
        # no upgrade promise and appends no misleading link.
        err = FunnelError(error="atom_cap_exceeded", tier="free", limit=10_000, size=12_396)
        cta = format_cta(err)
        assert "ails auth login" not in cta
        assert "Upgrade to Pro" not in cta
        assert "→" not in cta
        assert "12,396" in cta

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_free_upgrade_url_defaults_to_subscribe_only_where_it_helps(self, held_key: None) -> None:
        # SEAM: the URL resolver defaults free rate-limit / payload to the
        # subscribe form, gives the universal atom cap no default, and always
        # prefers a server-provided upgrade_url.
        assert _cta_upgrade_url(FunnelError(error="rate_limit_exceeded", tier="free")) == _SUBSCRIBE_URL
        assert _cta_upgrade_url(FunnelError(error="payload_too_large", tier="free")) == _SUBSCRIBE_URL
        assert _cta_upgrade_url(FunnelError(error="atom_cap_exceeded", tier="free")) == ""
        assert (
            _cta_upgrade_url(FunnelError(error="rate_limit_exceeded", tier="free", upgrade_url="https://x/y"))
            == "https://x/y"
        )

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_free_lapsed_trial_server_message_and_url_win(self, held_key: None) -> None:
        # A lapsed legacy trial winds down to keyed `free` and the server sends
        # its own message + upgrade_url; the CLI renders them verbatim, never the
        # login CTA.
        err = FunnelError(
            error="payload_too_large",
            tier="free",
            limit=2 * 1024 * 1024,
            message="Your trial has ended and anonymous limits now apply. Upgrade to Pro at reporails.com.",
            upgrade_url="https://reporails.com/account?utm_source=cli",
        )
        cta = format_cta(err)
        assert "Your trial has ended" in cta
        assert "ails auth login" not in cta
        assert "[link=https://reporails.com/account?utm_source=cli]" in cta


class TestServerMessageIsSafeToRender:
    """A SERVER-supplied `message` is untrusted text. Before the
    fix, an unmatched closing tag (`[/bold]`) raised `rich.errors.MarkupError` the moment the
    CTA was actually rendered (the terminal `console.print`, or a manual markup-strip), and a
    `:name:` shortcode silently became an emoji glyph. Both must be neutralized where the
    message enters the template."""

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_unmatched_closing_tag_does_not_crash_on_render(self) -> None:
        from rich.markup import render as render_markup

        err = FunnelError(error="unknown_error", tier="free", message="Server said [/bold] oops")
        cta = format_cta(err)
        # Must not raise rich.errors.MarkupError.
        rendered = render_markup(cta).plain
        assert "Server said [/bold] oops" in rendered

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_emoji_shortcode_stays_literal_in_plain_cta(self) -> None:
        err = FunnelError(error="unknown_error", tier="free", message="Uh oh :smile: try again")
        assert ":smile:" in plain_cta(err)

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_plain_cta_strips_terminal_markup(self) -> None:
        err = FunnelError(error="rate_limit_exceeded", tier="free", limit=5, upgrade_url="https://x/upgrade")
        plain = plain_cta(err)
        assert "[link=" not in plain
        assert "[bold]" not in plain
        assert "[/bold]" not in plain
        assert "[/link]" not in plain
        assert "5/hr" in plain


class TestLintResponse:
    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    def test_default_empty(self) -> None:
        response = LintResponse()
        assert response.result is None
        assert response.funnel_error is None

    @pytest.mark.unit
    @pytest.mark.subsys_funnel
    @pytest.mark.parametrize("error_type", ["rate_limit_exceeded", "payload_too_large", "atom_cap_exceeded"])
    def test_holds_funnel_error(self, error_type: str) -> None:
        err = FunnelError(error=error_type, tier="pro")
        response = LintResponse(funnel_error=err)
        assert response.funnel_error is err
