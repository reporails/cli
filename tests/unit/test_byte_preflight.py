"""Unit tests for the local byte-size preflight."""

from __future__ import annotations

import pytest

from reporails_cli.core.funnel import (
    WIRE_MAX_BYTES_BY_TIER,
    FunnelError,
    preflight_byte_size,
)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_under_cap_returns_none() -> None:
    assert preflight_byte_size(1024, has_api_key=False) is None


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_anonymous_at_cap_passes() -> None:
    cap = WIRE_MAX_BYTES_BY_TIER["anonymous"]
    assert preflight_byte_size(cap, has_api_key=False) is None


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_anonymous_over_cap_returns_funnel_error() -> None:
    cap = WIRE_MAX_BYTES_BY_TIER["anonymous"]
    err = preflight_byte_size(cap + 1, has_api_key=False)
    assert isinstance(err, FunnelError)
    assert err.error == "payload_too_large"
    assert err.tier == "anonymous"
    assert err.limit == cap
    assert err.size == cap + 1


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_keyed_cap_higher_than_anonymous() -> None:
    keyed_cap = WIRE_MAX_BYTES_BY_TIER["pro"]
    anon_cap = WIRE_MAX_BYTES_BY_TIER["anonymous"]
    assert keyed_cap > anon_cap
    assert preflight_byte_size(anon_cap + 1, has_api_key=True) is None


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_keyed_over_cap_returns_funnel_error() -> None:
    keyed_cap = WIRE_MAX_BYTES_BY_TIER["pro"]
    err = preflight_byte_size(keyed_cap + 1, has_api_key=True)
    assert isinstance(err, FunnelError)
    assert err.tier == "pro"
    assert err.limit == keyed_cap
