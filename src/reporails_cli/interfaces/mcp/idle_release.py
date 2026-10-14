"""Idle model release for the long-lived MCP server."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import TYPE_CHECKING

from reporails_cli.core.mapper.models import get_models
from reporails_cli.core.platform.config.bootstrap import parse_idle_timeout_env

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer

# Idle model release: the MCP server is long-lived and loads its models on the
# first `validate`. Without a release path they stay resident (~GBs) for the
# server's whole lifetime. After AILS_MCP_IDLE_S seconds (default 30 min; 0
# disables) with no tool call, drop them; the next call lazy-reloads.
_DEFAULT_IDLE_S = 1800
_activity = SimpleNamespace(last=time.monotonic())


def _parse_idle_timeout() -> int | None:
    return parse_idle_timeout_env("AILS_MCP_IDLE_S", _DEFAULT_IDLE_S)


async def _idle_watchdog() -> None:
    """Unload resident models once after an idle window; re-arm on new activity."""
    idle_s = _parse_idle_timeout()
    if idle_s is None:
        return

    poll = min(60, idle_s)
    unloaded = False
    while True:
        await asyncio.sleep(poll)
        is_idle = time.monotonic() - _activity.last > idle_s
        if is_idle and not unloaded:
            get_models().unload()
            unloaded = True
        elif not is_idle:
            unloaded = False


@asynccontextmanager
async def lifespan(_server: MCPServer) -> AsyncIterator[None]:
    """Run the idle-unload watchdog for the server's lifetime."""
    watchdog = asyncio.create_task(_idle_watchdog())
    try:
        yield
    finally:
        watchdog.cancel()


def touch_activity() -> None:
    """Mark a tool call for the idle watchdog. Fires on every tool invocation."""
    _activity.last = time.monotonic()
