"""Mutation-killing behavioral tests for funnel-parsing/CTA survivors.

Covers the `limit`/`limit_bytes` fallback chain in `parse_error_body`
(policy.preflight) and the blank-value preservation in `merge_utm`
(formatters.text.funnel_cta). The `@dataclass(frozen=True)` on FunnelError and
LintResponse are equivalent mutants: neither is ever hashed or used as a set
member / dict key, so `frozen -> False` changes no observable behavior — left
undecorated.
"""

from __future__ import annotations

import json

import pytest

from reporails_cli.core.platform.policy.preflight import parse_error_body
from reporails_cli.formatters.text.funnel_cta import merge_utm


# --- parse_error_body: limit/limit_bytes fallback (L101) ------------------
@pytest.mark.unit
@pytest.mark.subsys_funnel
def test_parse_error_body_reads_limit_bytes_fallback() -> None:
    body = json.dumps({"error": "payload_too_large", "limit_bytes": 500})
    err = parse_error_body(413, body)
    assert err is not None
    # `or`->`and` on either operand of `limit or limit_bytes or 0` collapses the
    # limit_bytes-only body to 0 instead of picking up the 500-byte limit.
    assert err.limit == 500


# --- merge_utm: keep_blank_values (L228) ----------------------------------
@pytest.mark.unit
@pytest.mark.subsys_funnel
def test_merge_utm_preserves_blank_valued_params() -> None:
    result = merge_utm("https://example.com/p?foo=&bar=1", "cli")
    # `keep_blank_values=True -> False` would drop the blank `foo=` param when
    # re-encoding the query.
    assert "foo=" in result
    assert "utm_source=cli" in result
