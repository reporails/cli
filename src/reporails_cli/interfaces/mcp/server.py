"""MCP server for reporails - exposes validation tools to Claude Code."""

import json
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
    judge_tool,
    score_tool,
)

# Create MCP server
server = Server("ails")

# Circuit breaker: track validate calls per resolved path per session.
# After threshold, inject stop signal to prevent infinite validate-fix-validate loops.
_validate_call_counts: dict[str, int] = {}
_VALIDATE_CALL_THRESHOLD = 2


@server.list_tools()  # type: ignore[no-untyped-call,untyped-decorator]
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="validate",
            description=(
                "Validate and score AI coding agent instruction files"
                " (CLAUDE.md, .cursorrules, copilot-instructions.md, etc)."
                " Returns violations, score (0-10), capability level (L1-L6),"
                " and semantic rules for you to evaluate inline."
                " Use when user asks: 'what ails', 'check instructions',"
                " 'score my config', 'validate agent files'."
                " Prefer this over running 'ails' via bash"
                " — only this tool returns semantic candidates for your evaluation."
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
            description=("Explain a specific rule. Use when user asks about a rule ID like S1, C2, E3, etc."),
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
            name="judge",
            description="Cache semantic rule verdicts so they persist across validation runs.",
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


async def _handle_validate(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'validate' tool call."""
    path = arguments.get("path", ".")
    target = Path(path).resolve()

    # Circuit breaker: prevent infinite validate-fix-validate loops
    path_key = str(target)
    _validate_call_counts[path_key] = _validate_call_counts.get(path_key, 0) + 1
    call_count = _validate_call_counts[path_key]

    if call_count > _VALIDATE_CALL_THRESHOLD:
        return [
            TextContent(
                type="text",
                text=(
                    "STOP — circuit breaker triggered.\n\n"
                    f"You have already validated this path {call_count - 1} times in this session. "
                    "Repeated validate-fix-validate cycles indicate a rule that cannot be "
                    "resolved automatically (e.g., negated checks, conflicting rules, or "
                    "rules requiring user decisions).\n\n"
                    "DO NOT call validate again for this path. Instead:\n"
                    "1. Report the remaining violations to the user\n"
                    "2. Explain which ones you could not resolve and why\n"
                    "3. Let the user decide how to proceed"
                ),
            )
        ]

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
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {type(e).__name__}: {e}")]

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
        _append_judgment_section(response_parts, judgment_requests)

    return [TextContent(type="text", text="\n".join(response_parts))]


def _append_judgment_section(response_parts: list[str], judgment_requests: list[dict[str, Any]]) -> None:
    """Append the semantic-rule evaluation section to the response."""
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
                criteria_text = criteria.get("pass_condition", str(criteria))
            elif isinstance(criteria, list):
                criteria_text = "; ".join(str(c) for c in criteria)
            else:
                criteria_text = str(criteria)
            response_parts.append(f"    Criteria: {criteria_text}")

        if jr.get("content"):
            snippet = jr.get("content", "")[:200]
            if len(jr.get("content", "")) > 200:
                snippet += "..."
            response_parts.append(f"    Context: {snippet}")
        response_parts.append("")

    response_parts.append(
        "After evaluating semantic rules above, report the FINAL score. "
        "If all semantic rules pass, the score remains the same but is now COMPLETE (not partial). "
        "If any semantic rules fail, add those violations and recalculate.\n\n"
        "IMPORTANT: Cache your verdicts using the judge tool so they persist across runs.\n"
        "Format each verdict as: rule_id:location:verdict:reason\n"
        'Example: judge(verdicts=["C6:CLAUDE.md:pass:Criteria met", '
        '"M2:.claude/rules/foo.md:fail:Contradictions found"])'
    )


async def _handle_score(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'score' tool call."""
    path = arguments.get("path", ".")
    score_result = score_tool(path)
    return [TextContent(type="text", text=json.dumps(score_result, indent=2))]


async def _handle_explain(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'explain' tool call."""
    rule_id = arguments.get("rule_id", "")
    explain_result = explain_tool(rule_id)
    return [TextContent(type="text", text=json.dumps(explain_result, indent=2))]


async def _handle_judge(arguments: dict[str, Any]) -> list[TextContent]:
    """Handle the 'judge' tool call."""
    path = arguments.get("path", ".")
    verdicts = arguments.get("verdicts", [])
    judge_result = judge_tool(path, verdicts)
    return [TextContent(type="text", text=json.dumps(judge_result, indent=2))]


@server.call_tool()  # type: ignore[untyped-decorator]
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""
    handlers = {
        "validate": _handle_validate,
        "explain": _handle_explain,
        "score": _handle_score,
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
