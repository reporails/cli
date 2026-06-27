"""MCP server for reporails - exposes validation tools to Claude Code."""

# ─────────────────────────────────────────────────────────────────────
# CRITICAL: torch import blocker MUST run before any import that could
# transitively reach thinc/spacy. The MCP server is long-lived and
# serves many tool calls; skipping the ~20s torch import makes first
# validate/score calls fast. See `_torch_blocker` docstring for details.
from reporails_cli.core.platform.runtime import _torch_blocker

_torch_blocker.install()
# ─────────────────────────────────────────────────────────────────────

import asyncio  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import time  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

from mcp.server import Server  # noqa: E402
from mcp.server.stdio import stdio_server  # noqa: E402
from mcp.types import TextContent, Tool  # noqa: E402

from reporails_cli.core.discovery.agents import get_all_instruction_files  # noqa: E402
from reporails_cli.interfaces.mcp.tools import (  # noqa: E402
    explain_tool,
    preflight_tool,
    validate_tool,
)

# Create MCP server
server = Server("ails")

# Circuit breaker: content-aware loop detection.
_MAX_CALLS = 10
_MAX_UNCHANGED = 2

# Idle model release: the MCP server is long-lived and loads embedding + spaCy
# models in-process on the first `validate`. Without a release path they stay
# resident (~GBs) for the server's whole lifetime. After AILS_MCP_IDLE_S seconds
# (default 30 min; 0 disables) with no tool call, drop them; the next call
# lazy-reloads. Cross-platform (asyncio + monotonic clock, no POSIX APIs).
_DEFAULT_MCP_IDLE_S = 1800
_last_activity = time.monotonic()


def _parse_mcp_idle_timeout() -> int | None:
    from reporails_cli.core.platform.config.bootstrap import parse_idle_timeout_env

    return parse_idle_timeout_env("AILS_MCP_IDLE_S", _DEFAULT_MCP_IDLE_S)


async def _idle_watchdog() -> None:
    """Unload resident models once after an idle window; re-arm on new activity."""
    idle_s = _parse_mcp_idle_timeout()
    if idle_s is None:
        return
    from reporails_cli.core.mapper.models import get_models

    poll = min(60, idle_s)
    unloaded = False
    while True:
        await asyncio.sleep(poll)
        is_idle = time.monotonic() - _last_activity > idle_s
        if is_idle and not unloaded:
            get_models().unload()
            unloaded = True
        elif not is_idle:
            unloaded = False


@dataclass
class _CircuitState:
    call_count: int = 0
    last_mtime_hash: str = ""
    consecutive_unchanged: int = 0


_validate_states: dict[str, _CircuitState] = {}


def _compute_mtime_hash(target: Path) -> str:
    """Hash instruction file mtimes to detect changes between validate calls."""
    files = get_all_instruction_files(target)
    parts = []
    for f in sorted(files):
        try:
            parts.append(f"{f}:{f.stat().st_mtime}")
        except OSError:
            continue
    return hashlib.md5("".join(parts).encode()).hexdigest() if parts else ""


@server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_tools() -> list[Tool]:
    """List available tools.

    Surface trimmed in 0.5.11 to match the plugin's model-as-helper UX:
    `validate` for the Check loop, `preflight` for authoring-first, `explain`
    for drill-down. `score` and `heal` are derivable from validate output or
    run via the CLI's batch heal.
    """
    return [
        Tool(
            name="validate",
            description=(
                "Validate AI instruction files at `path` (directory or single file)."
                " Returns JSON with findings, per-finding fix text, compliance band,"
                " tier, per-surface category breakdown, and cross-file analysis."
                " Use when user asks to check, validate, or improve instruction files."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory or file path to validate (default: current directory)",
                        "default": ".",
                    },
                },
            },
        ),
        Tool(
            name="preflight",
            description=(
                "Return the workflow-ordered rules that govern authoring a file of the given"
                " `capability` (e.g. `skill`, `agent`, `rule`, `main`). Use BEFORE drafting"
                " a new SKILL.md / agent / rule so the draft follows the rules from the"
                " start instead of patching findings after `validate`."
                " Returns JSON with rules sorted by category in workflow order plus"
                " Pass / Fail examples."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "capability": {
                        "type": "string",
                        "description": "Capability keyword (skill, agent, rule, main, memory, ...)",
                    },
                    "agent": {
                        "type": "string",
                        "description": "Optional agent filter (claude, codex, antigravity, ...); empty = all agents",
                        "default": "",
                    },
                },
                "required": ["capability"],
            },
        ),
        Tool(
            name="explain",
            description=(
                "Get details about a specific rule by ID."
                " Returns rule title, category, type, description, checks."
                " Use full coordinate IDs (e.g., CORE:S:0005, CLAUDE:S:0005)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "Rule ID to explain (e.g., CORE:S:0005)",
                    }
                },
                "required": ["rule_id"],
            },
        ),
    ]


def _json_response(data: dict[str, Any]) -> list[TextContent]:
    """Wrap a dict as a compact JSON TextContent response."""
    return [TextContent(type="text", text=json.dumps(data, separators=(",", ":")))]


async def _handle_validate(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'validate' tool call.

    Two layers of safety:
      1. Path-existence + emptiness checks emit structured errors the slash
         command body can branch on (no bare strings).
      2. The circuit breaker (`_MAX_CALLS` total, `_MAX_UNCHANGED` consecutive
         no-op validates per path) catches the failure mode of a model that
         re-validates without applying any fixes. The mtime-tracker resets on
         any file edit, so the fix-walk sub-agent's normal Edit-validate
         cycle never trips it.
    """
    path = arguments.get("path", ".")
    target = Path(path).resolve()

    path_key = str(target)
    state = _validate_states.get(path_key, _CircuitState())
    mtime_hash = _compute_mtime_hash(target)
    if mtime_hash == state.last_mtime_hash and state.last_mtime_hash:
        state.consecutive_unchanged += 1
    else:
        state.consecutive_unchanged = 0
    state.last_mtime_hash = mtime_hash
    state.call_count += 1
    _validate_states[path_key] = state

    if state.call_count > _MAX_CALLS or state.consecutive_unchanged >= _MAX_UNCHANGED:
        return _json_response(
            {
                "error": "circuit_breaker",
                "message": (
                    "STOP — circuit breaker triggered. "
                    f"Validated this path {state.call_count} times "
                    f"({state.consecutive_unchanged} consecutive unchanged). "
                    "DO NOT call validate again for this path. Instead: "
                    "1. Report the remaining violations to the user. "
                    "2. Explain which ones you could not resolve and why. "
                    "3. Let the user decide how to proceed."
                ),
            }
        )

    if not target.exists():
        return _json_response({"error": "path_not_found", "message": f"Path not found: {target}"})

    # File and directory targets both supported (per 0.5.11 bug-1 fix).
    return _json_response(validate_tool(path))


async def _handle_preflight(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle 'preflight' — return workflow-ordered rules for authoring."""
    return _json_response(preflight_tool(arguments.get("capability", ""), arguments.get("agent", "")))


async def _handle_explain(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle 'explain' — readable text, not JSON."""
    result = explain_tool(arguments.get("rule_id", ""))
    return _json_response(result) if isinstance(result, dict) else [TextContent(type="text", text=result)]


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    global _last_activity
    _last_activity = time.monotonic()
    handlers = {
        "validate": _handle_validate,
        "preflight": _handle_preflight,
        "explain": _handle_explain,
    }
    handler = handlers.get(name)
    if handler is None:
        return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]
    return await handler(arguments)


async def run_server() -> None:
    """Run the MCP server with a background idle-unload watchdog."""
    watchdog = asyncio.create_task(_idle_watchdog())
    try:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())
    finally:
        watchdog.cancel()


def main() -> None:
    """Entry point for MCP server."""
    import asyncio

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
