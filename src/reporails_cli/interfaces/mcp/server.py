"""MCP server for reporails - exposes validation tools to Claude Code."""

# ─────────────────────────────────────────────────────────────────────
# CRITICAL: torch import blocker MUST run before any import that could
# transitively reach thinc/spacy. The MCP server is long-lived and
# serves many tool calls; skipping the ~20s torch import makes first
# validate/score calls fast. See `_torch_blocker` docstring for details.
from reporails_cli.core import _torch_blocker

_torch_blocker.install()
# ─────────────────────────────────────────────────────────────────────

import hashlib  # noqa: E402
import json  # noqa: E402
from dataclasses import dataclass  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

from mcp.server import Server  # noqa: E402
from mcp.server.stdio import stdio_server  # noqa: E402
from mcp.types import TextContent, Tool  # noqa: E402

from reporails_cli.core.agents import get_all_instruction_files  # noqa: E402
from reporails_cli.core.bootstrap import is_initialized  # noqa: E402
from reporails_cli.interfaces.mcp.tools import (  # noqa: E402
    explain_tool,
    score_tool,
    validate_tool,
)

# Create MCP server
server = Server("ails")

# Circuit breaker: content-aware loop detection.
_MAX_CALLS = 10
_MAX_UNCHANGED = 2


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
    """List available tools."""
    return [
        Tool(
            name="validate",
            description=(
                "Validate AI instruction files. Returns JSON with findings,"
                " compliance band, and cross-file analysis."
                " Use when user asks to check, validate, or improve instruction files."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to validate (default: current directory)",
                        "default": ".",
                    },
                },
            },
        ),
        Tool(
            name="score",
            description=(
                "Quick score check without violation details. Returns JSON with compliance band and violation count."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to score (default: current directory)",
                        "default": ".",
                    }
                },
            },
        ),
        Tool(
            name="explain",
            description=(
                "Get details about a specific rule by ID."
                " Returns rule title, category, type, description, checks."
                " Use full coordinate IDs (e.g., CORE:S:0005, CLAUDE:S:0011)."
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
        Tool(
            name="heal",
            description=(
                "Auto-fix instruction file issues. Applies formatting, bold→italic,"
                " constraint wrapping, and charge ordering fixes."
                " Use --dry-run to preview."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to heal (default: current directory)",
                        "default": ".",
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Preview fixes without applying",
                        "default": False,
                    },
                },
            },
        ),
    ]


def _json_response(data: dict[str, Any]) -> list[TextContent]:
    """Wrap a dict as a compact JSON TextContent response."""
    return [TextContent(type="text", text=json.dumps(data, separators=(",", ":")))]


async def _handle_validate(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'validate' tool call."""
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

    if not is_initialized():
        return _json_response({"error": "not_initialized", "message": "Run 'ails check' to auto-initialize."})
    if not target.exists():
        return _json_response({"error": "path_not_found", "message": f"Path not found: {target}"})
    if not target.is_dir():
        return _json_response({"error": "not_a_directory", "message": f"Not a directory: {target}"})

    return _json_response(validate_tool(path))


async def _handle_score(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle 'score'."""
    return _json_response(score_tool(arguments.get("path", ".")))


async def _handle_heal(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle 'heal'."""
    from reporails_cli.interfaces.mcp.tools import heal_tool

    return _json_response(heal_tool(arguments.get("path", "."), arguments.get("dry_run", False)))


async def _handle_explain(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle 'explain' — readable text, not JSON."""
    result = explain_tool(arguments.get("rule_id", ""))
    return _json_response(result) if isinstance(result, dict) else [TextContent(type="text", text=result)]


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    handlers = {
        "validate": _handle_validate,
        "explain": _handle_explain,
        "score": _handle_score,
        "heal": _handle_heal,
    }
    handler = handlers.get(name)
    if handler is None:
        return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]
    return await handler(arguments)


async def run_server() -> None:
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    """Entry point for MCP server."""
    import asyncio

    asyncio.run(run_server())


if __name__ == "__main__":
    main()
