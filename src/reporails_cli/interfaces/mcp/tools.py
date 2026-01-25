"""MCP tool implementations for reporails."""

from pathlib import Path
from typing import Any

from reporails_cli.core.bootstrap import is_initialized
from reporails_cli.core.engine import run_validation
from reporails_cli.core.registry import load_rules
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.formatters import text as text_formatter


async def validate_tool(path: str = ".") -> dict[str, Any]:
    """
    Validate CLAUDE.md files at path.

    Returns violations, score, level, and JudgmentRequests for semantic rules.

    Args:
        path: Directory to validate (default: current directory)

    Returns:
        Validation result dict
    """
    if not is_initialized():
        return {"error": "Reporails not initialized. Run 'ails init' first."}

    target = Path(path).resolve()

    if not target.exists():
        return {"error": f"Path not found: {target}"}

    try:
        result = await run_validation(target)
        return mcp_formatter.format_result(result)
    except FileNotFoundError as e:
        return {"error": str(e)}


async def validate_tool_text(path: str = ".") -> str:
    """
    Validate CLAUDE.md files at path, returning text format.

    Returns human-readable text report with score, violations, and friction.

    Args:
        path: Directory to validate (default: current directory)

    Returns:
        Text-formatted validation report
    """
    if not is_initialized():
        return "Error: Reporails not initialized. Run 'ails init' first."

    target = Path(path).resolve()

    if not target.exists():
        return f"Error: Path not found: {target}"

    try:
        result = await run_validation(target)
        return text_formatter.format_result(result, ascii_mode=True)
    except FileNotFoundError as e:
        return f"Error: {e}"


async def score_tool(path: str = ".") -> dict[str, Any]:
    """
    Quick score check for CLAUDE.md files.

    Args:
        path: Directory to score (default: current directory)

    Returns:
        Score summary dict
    """
    if not is_initialized():
        return {"error": "Reporails not initialized. Run 'ails init' first."}

    target = Path(path).resolve()

    if not target.exists():
        return {"error": f"Path not found: {target}"}

    try:
        result = await run_validation(target)
        return mcp_formatter.format_score(result)
    except FileNotFoundError as e:
        return {"error": str(e)}


async def explain_tool(rule_id: str) -> dict[str, Any]:
    """
    Get detailed info about a specific rule.

    Args:
        rule_id: Rule identifier (e.g., S1, C2)

    Returns:
        Rule details dict
    """
    rules = load_rules()

    # Normalize rule ID
    rule_id_upper = rule_id.upper()

    if rule_id_upper not in rules:
        return {
            "error": f"Unknown rule: {rule_id}",
            "available_rules": sorted(rules.keys()),
        }

    rule = rules[rule_id_upper]
    rule_data = {
        "title": rule.title,
        "category": rule.category.value,
        "type": rule.type.value,
        "level": rule.level,
        "scoring": rule.scoring,
        "detection": rule.detection,
        "checks": [
            {"id": c.id, "name": c.name, "severity": c.severity.value}
            for c in rule.checks
        ],
        "see_also": rule.see_also,
    }

    # Read description from markdown file if available
    if rule.md_path and rule.md_path.exists():
        content = rule.md_path.read_text(encoding="utf-8")
        # Extract content after frontmatter
        parts = content.split("---", 2)
        if len(parts) >= 3:
            rule_data["description"] = parts[2].strip()[:500]

    return mcp_formatter.format_rule(rule_id_upper, rule_data)
