"""Tests for AilsClient's handling of an empty AILS_SERVER_URL environment value.

An input that is set-but-empty (the composite Action's undocumented default
behaviour, and the documented `server-url: ''` input) must not be read as a
deliberate "no server" choice — only an unset variable, or an explicit empty
`base_url` argument, means that.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.adapters.api_client import DEFAULT_SERVER_URL, AilsClient


class TestServerUrlEnvOverride:
    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_empty_server_url_env_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A set-but-empty AILS_SERVER_URL is treated as unset, not as "no server"."""
        monkeypatch.setenv("AILS_SERVER_URL", "")
        client = AilsClient()
        assert client.base_url == DEFAULT_SERVER_URL

    @pytest.mark.unit
    @pytest.mark.subsys_api
    def test_populated_server_url_env_is_honored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A real override still wins over the default."""
        monkeypatch.setenv("AILS_SERVER_URL", "http://localhost:8787")
        client = AilsClient()
        assert client.base_url == "http://localhost:8787"
