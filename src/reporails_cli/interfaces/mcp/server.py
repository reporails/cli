"""MCP server for reporails - exposes validation tools to Claude Code."""

from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from reporails_cli.interfaces.mcp.tools import (
    explain_tool,
    score_tool,
    validate_tool_text,
)

# Create MCP server
server = Server("ails")


@server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="validate",
            description=(
                "Validate CLAUDE.md files. Use when user asks to check, lint, "
                "validate, or diagnose their CLAUDE.md or AI context files."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to validate (default: current directory)",
                        "default": ".",
                    }
                },
            },
        ),
        Tool(
            name="score",
            description="Quick score check for CLAUDE.md files without full violation details.",
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
                "Explain a specific rule. Use when user asks about a rule ID like S1, C2, E3, etc."
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
    ]


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    import json

    if name == "validate":
        path = arguments.get("path", ".")
        text_result = await validate_tool_text(path)
        return [TextContent(type="text", text=text_result)]
    elif name == "score":
        path = arguments.get("path", ".")
        result = await score_tool(path)
    elif name == "explain":
        rule_id = arguments.get("rule_id", "")
        result = await explain_tool(rule_id)
    else:
        result = {"error": f"Unknown tool: {name}"}

    return [TextContent(type="text", text=json.dumps(result, indent=2))]


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
