"""MCP server for reporails - exposes validation tools to Claude Code."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from reporails_cli.core.agents import get_all_instruction_files
from reporails_cli.core.bootstrap import is_initialized
from reporails_cli.core.cache import get_previous_scan
from reporails_cli.core.engine import run_validation
from reporails_cli.core.models import ScanDelta
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.interfaces.mcp.tools import (
    explain_tool,
    heal_tool,
    judge_tool,
    score_tool,
)

# Create MCP server
server = Server("ails")

# Circuit breaker: content-aware loop detection.
# Tracks instruction file mtimes — if files changed between calls, it's a
# legitimate edit-validate cycle, not a loop.
_MAX_CALLS = 10  # Absolute ceiling per session
_MAX_UNCHANGED = 2  # Consecutive calls without file changes


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
                "Returns JSON with score (0-10), level (L1-L6), violations array,"
                " and judgment_requests for semantic rules you must evaluate."
                " Use when user asks to check, validate, or improve instruction files."
                " After evaluating judgment_requests, call judge to cache verdicts."
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
                "Quick score check without violation details or semantic rules."
                " Returns JSON with score, level, violation count, and friction."
                " Use for fast health checks or progress monitoring."
                " Use validate for full details."
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
                " Returns JSON with title, category, type, level, description, checks."
                " Accepts short IDs (S1, C6) or coordinate IDs (CORE:S:0001)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "rule_id": {
                        "type": "string",
                        "description": "Rule ID to explain (e.g., S1, C2)",
                    }
                },
                "required": ["rule_id"],
            },
        ),
        Tool(
            name="heal",
            description=(
                "Auto-fix deterministic violations (adds missing sections) then returns"
                " remaining semantic judgment_requests for you to evaluate."
                " Use when user asks to fix, heal, or improve instruction files."
                " Returns JSON with auto_fixed array and judgment_requests."
                " After evaluating judgment_requests, call judge to cache verdicts."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to heal (default: current directory)",
                        "default": ".",
                    },
                },
            },
        ),
        Tool(
            name="judge",
            description=(
                "Cache semantic rule verdicts so they persist across validation runs."
                " Call after evaluating judgment_requests from validate."
                " Verdict format: RULE_ID:FILENAME:pass|fail:reason."
                " Keep reason BRIEF (under 40 chars)."
                " Examples: 'CORE:C:0017:CLAUDE.md:pass:Repo-specific paths',"
                " 'CORE:S:0012:CLAUDE.md:fail:3 inlined procedures'."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Project root directory",
                        "default": ".",
                    },
                    "verdicts": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Verdict strings in rule_id:location:verdict:reason format",
                    },
                },
                "required": ["verdicts"],
            },
        ),
    ]


def _json_response(data: dict[str, Any], indent: int = 2) -> list[TextContent]:
    """Wrap a dict as a JSON TextContent response."""
    return [TextContent(type="text", text=json.dumps(data, indent=indent))]


async def _handle_validate(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'validate' tool call."""
    path = arguments.get("path", ".")
    target = Path(path).resolve()

    # Circuit breaker: update state, then check thresholds
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

    previous_scan = get_previous_scan(target)
    try:
        result = run_validation(target, agent="claude")
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return _json_response({"error": type(e).__name__, "message": str(e)})

    delta = ScanDelta.compute(
        current_score=result.score,
        current_level=result.level.value,
        current_violations=len(result.violations),
        previous=previous_scan,
    )
    return _json_response(mcp_formatter.format_result(result, delta=delta))


async def _handle_score(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'score' tool call."""
    return _json_response(score_tool(arguments.get("path", ".")))


async def _handle_explain(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'explain' tool call."""
    return _json_response(explain_tool(arguments.get("rule_id", "")))


async def _handle_heal(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'heal' tool call."""
    return _json_response(heal_tool(arguments.get("path", ".")))


async def _handle_judge(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'judge' tool call."""
    return _json_response(judge_tool(arguments.get("path", "."), arguments.get("verdicts", [])))


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    handlers = {
        "validate": _handle_validate,
        "explain": _handle_explain,
        "score": _handle_score,
        "heal": _handle_heal,
        "judge": _handle_judge,
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
