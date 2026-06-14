"""Idle model-release behavior for the mapper daemon and MCP server (fix A)."""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper import daemon
from reporails_cli.core.mapper.models import _UNSET, Models
from reporails_cli.interfaces.mcp import server


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_unload_resets_loaded_models() -> None:
    models = Models()
    models._st = object()  # stand in for a loaded embedder
    models._nlp = object()  # stand in for a loaded spaCy pipeline

    models.unload()

    assert models._st is None
    assert models._nlp is _UNSET


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_daemon_idle_timeout_defaults_on(monkeypatch) -> None:
    monkeypatch.delenv("AILS_DAEMON_IDLE_S", raising=False)
    assert daemon._parse_idle_timeout() == daemon._DEFAULT_IDLE_TIMEOUT_S


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_daemon_idle_timeout_env_override(monkeypatch) -> None:
    monkeypatch.setenv("AILS_DAEMON_IDLE_S", "5")
    assert daemon._parse_idle_timeout() == 5


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_daemon_idle_timeout_zero_disables(monkeypatch) -> None:
    monkeypatch.setenv("AILS_DAEMON_IDLE_S", "0")
    assert daemon._parse_idle_timeout() is None


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_mcp_idle_timeout_defaults_on(monkeypatch) -> None:
    monkeypatch.delenv("AILS_MCP_IDLE_S", raising=False)
    assert server._parse_mcp_idle_timeout() == server._DEFAULT_MCP_IDLE_S


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_mcp_idle_timeout_zero_disables(monkeypatch) -> None:
    monkeypatch.setenv("AILS_MCP_IDLE_S", "0")
    assert server._parse_mcp_idle_timeout() is None


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_mcp_idle_timeout_env_override(monkeypatch) -> None:
    monkeypatch.setenv("AILS_MCP_IDLE_S", "5")
    assert server._parse_mcp_idle_timeout() == 5


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_idle_env_blank_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setenv("AILS_DAEMON_IDLE_S", "")
    assert daemon._parse_idle_timeout() == daemon._DEFAULT_IDLE_TIMEOUT_S


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_idle_env_non_numeric_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setenv("AILS_DAEMON_IDLE_S", "30m")
    assert daemon._parse_idle_timeout() == daemon._DEFAULT_IDLE_TIMEOUT_S


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_idle_watchdog_disabled_returns_immediately(monkeypatch) -> None:
    import asyncio

    monkeypatch.setenv("AILS_MCP_IDLE_S", "0")
    asyncio.run(asyncio.wait_for(server._idle_watchdog(), timeout=1))


@pytest.mark.unit
@pytest.mark.subsys_runtime
def test_idle_watchdog_unloads_once_while_idle(monkeypatch) -> None:
    import asyncio

    monkeypatch.setenv("AILS_MCP_IDLE_S", "1")
    monkeypatch.setattr(server, "_last_activity", 0.0)
    monkeypatch.setattr(server.time, "monotonic", lambda: 10_000.0)  # always idle

    calls = {"unload": 0}

    class _FakeModels:
        def unload(self) -> None:
            calls["unload"] += 1

    monkeypatch.setattr("reporails_cli.core.mapper.models.get_models", lambda: _FakeModels())

    polls = {"n": 0}

    async def _fake_sleep(_seconds: float) -> None:
        polls["n"] += 1
        if polls["n"] >= 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(server.asyncio, "sleep", _fake_sleep)

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(server._idle_watchdog())

    assert calls["unload"] == 1  # unloaded once, not once per poll
