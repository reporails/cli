"""Live-path regression for the new-user activation first hop.

Exercises `_resolve_client_id` against the real platform host. This is the
exact network hop that a Cloudflare edge challenge on `/api/auth/client-id`
would break — if the endpoint stops serving 200 JSON with a non-empty
client_id, terminal-based `ails auth login` cannot start the device flow.

Network-only and excluded from the offline CI lanes; runs in the dedicated
`test_live` lane (`pytest -m requires_network`).
"""

from __future__ import annotations

import httpx
import pytest

from reporails_cli.interfaces.cli.auth_command import (
    DEFAULT_PLATFORM_URL,
    _resolve_client_id,
)


@pytest.mark.integration
@pytest.mark.requires_network
@pytest.mark.slow
@pytest.mark.subsys_api
def test_resolve_client_id_returns_nonempty_against_live_platform() -> None:
    """The live platform serves a non-empty GitHub OAuth client id."""
    client_id = _resolve_client_id(DEFAULT_PLATFORM_URL)
    assert client_id, "live platform returned an empty client_id — activation path broken"


@pytest.mark.integration
@pytest.mark.requires_network
@pytest.mark.slow
@pytest.mark.subsys_api
def test_client_id_endpoint_serves_200_json() -> None:
    """The client-id endpoint serves 200 with a JSON body (no edge challenge)."""
    resp = httpx.get(
        f"{DEFAULT_PLATFORM_URL}/api/auth/client-id",
        timeout=10.0,
        headers={"Accept": "application/json"},
    )
    assert resp.status_code == 200, f"expected 200, got {resp.status_code}"
    assert resp.json().get("client_id"), "200 body missing a non-empty client_id"
