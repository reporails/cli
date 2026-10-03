"""The smoke suite's environment fixture keeps clients off the hosted endpoint."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import urlparse

import pytest

from reporails_cli.core.platform.adapters.api_client import DEFAULT_SERVER_URL, AilsClient

SMOKE_CONFTEST = Path(__file__).parent.parent / "smoke" / "conftest.py"


def _fixture_body():
    spec = importlib.util.spec_from_file_location("smoke_conftest_under_test", SMOKE_CONFTEST)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fixture = module._offline_server
    return getattr(fixture, "__wrapped__", None) or fixture._get_wrapped_function()


@pytest.mark.unit
@pytest.mark.subsys_api
def test_smoke_fixture_targets_closed_local_port(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fixture sets a loopback server URL, never empty and never the default."""
    monkeypatch.delenv("AILS_SERVER_URL", raising=False)
    _fixture_body()(monkeypatch)
    client = AilsClient()
    assert client.base_url != DEFAULT_SERVER_URL
    assert urlparse(client.base_url).hostname in {"127.0.0.1", "localhost", "::1"}
