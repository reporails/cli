"""MCP server for reporails - exposes validation tools to Claude Code."""

from pathlib import Path
from typing import Any

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

from reporails_cli.core.bootstrap import is_initialized
from reporails_cli.core.cache import get_previous_scan
from reporails_cli.core.engine import run_validation
from reporails_cli.core.models import ScanDelta
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.formatters import text as text_formatter
from reporails_cli.interfaces.mcp.tools import (
    explain_tool,
    score_tool,
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
                "Lint and score AI coding agent instruction files (CLAUDE.md, .cursorrules, copilot-instructions.md, etc). "
                "Returns violations, score (0-10), capability level (L1-L6), and semantic rules for you to evaluate inline. "
                "Use when user asks: 'what ails', 'check instructions', 'lint setup', 'score my config', 'validate agent files'. "
                "Prefer this over running 'ails' via bash — only this tool returns semantic candidates for your evaluation."
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
        target = Path(path).resolve()

        # Check initialization
        if not is_initialized():
            return [TextContent(type="text", text="Error: Reporails not initialized. Run 'ails init' first.")]

        if not target.exists():
            return [TextContent(type="text", text=f"Error: Path not found: {target}")]

        # Get previous scan BEFORE validation (for delta comparison)
        previous_scan = get_previous_scan(target)

        # Run validation once
        try:
            result = run_validation(target, agent="claude")
        except FileNotFoundError as e:
            return [TextContent(type="text", text=f"Error: {e}")]

        # Compute delta
        delta = ScanDelta.compute(
            current_score=result.score,
            current_level=result.level.value,
            current_violations=len(result.violations),
            previous=previous_scan,
        )

        # Format text result with delta (suppress MCP CTA since we're already in MCP)
        text_result = text_formatter.format_result(result, ascii_mode=True, delta=delta, show_mcp_cta=False)

        # Get structured data for judgment requests
        dict_result = mcp_formatter.format_result(result, delta=delta)

        # Build response with text report
        response_parts = [text_result]

        # Add judgment requests for Claude to evaluate inline
        judgment_requests = dict_result.get("judgment_requests", [])
        if judgment_requests:
            response_parts.append("\n" + "=" * 60)
            response_parts.append("ACTION REQUIRED - EVALUATE THESE SEMANTIC RULES:")
            response_parts.append("=" * 60)
            response_parts.append(
                "You MUST evaluate each rule below by reading the file content. "
                "This is not optional. Do NOT ask the user for permission. "
                "For each item: read the file, apply the criteria. "
                "Report ONLY violations (where criteria are NOT met). "
                "Do not list items that pass — just state how many passed at the end."
            )
            for i, jr in enumerate(judgment_requests, 1):
                response_parts.append(f"[{i}] Rule {jr.get('rule_id', '?')}: {jr.get('question', '')}")
                response_parts.append(f"    File: {jr.get('location', '?')}")

                # Format criteria properly (not as raw Python dict)
                criteria = jr.get("criteria")
                if criteria:
                    if isinstance(criteria, dict):
                        # Extract pass_condition or format dict nicely
                        criteria_text = criteria.get("pass_condition", str(criteria))
                    elif isinstance(criteria, list):
                        criteria_text = "; ".join(str(c) for c in criteria)
                    else:
                        criteria_text = str(criteria)
                    response_parts.append(f"    Criteria: {criteria_text}")

                if jr.get("content"):
                    # Show snippet if available
                    snippet = jr.get("content", "")[:200]
                    if len(jr.get("content", "")) > 200:
                        snippet += "..."
                    response_parts.append(f"    Context: {snippet}")
                response_parts.append("")

            # Add guidance for final score reporting
            response_parts.append(
                "After evaluating semantic rules above, report the FINAL score. "
                "If all semantic rules pass, the score remains the same but is now COMPLETE (not partial). "
                "If any semantic rules fail, add those violations and recalculate."
            )

        return [TextContent(type="text", text="\n".join(response_parts))]
    elif name == "score":
        path = arguments.get("path", ".")
        score_result = score_tool(path)
        return [TextContent(type="text", text=json.dumps(score_result, indent=2))]
    elif name == "explain":
        rule_id = arguments.get("rule_id", "")
        explain_result = explain_tool(rule_id)
        return [TextContent(type="text", text=json.dumps(explain_result, indent=2))]
    else:
        return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}, indent=2))]


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
