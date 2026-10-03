"""The smoke suite never points the client at the hosted diagnostics endpoint."""

from __future__ import annotations

from urllib.parse import urlparse

import pytest

from reporails_cli.core.platform.adapters.api_client import DEFAULT_SERVER_URL, AilsClient


@pytest.mark.e2e
@pytest.mark.subsys_api
def test_smoke_client_targets_closed_local_port() -> None:
    """With the suite's environment applied, a client targets a loopback address."""
    client = AilsClient()
    assert client.base_url != DEFAULT_SERVER_URL
    assert urlparse(client.base_url).hostname in {"127.0.0.1", "localhost", "::1"}
