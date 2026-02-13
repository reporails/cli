"""MCP tool implementations for reporails."""

from pathlib import Path
from typing import Any

from reporails_cli.core.bootstrap import is_initialized
from reporails_cli.core.engine import run_validation
from reporails_cli.core.registry import load_rules
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.formatters import text as text_formatter


def _resolve_recommended_rules_paths(target: Path) -> list[Path] | None:
    """Build rules_paths including recommended package if enabled for target project."""
    import logging

    from reporails_cli.core.bootstrap import get_project_config, get_recommended_package_path
    from reporails_cli.core.init import download_recommended, is_recommended_installed
    from reporails_cli.core.registry import get_rules_dir

    logger = logging.getLogger("reporails")

    project_config = get_project_config(target)
    if not project_config.recommended:
        return None

    if not is_recommended_installed():
        try:
            download_recommended()
        except Exception as e:
            logger.warning("Failed to download recommended rules: %s: %s", type(e).__name__, e)
            return None

    rec_path = get_recommended_package_path()
    if rec_path.is_dir():
        return [get_rules_dir(), rec_path]
    return None


def validate_tool(path: str = ".") -> dict[str, Any]:
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
    if not target.is_dir():
        return {"error": f"Path is not a directory: {target}"}

    try:
        rules_paths = _resolve_recommended_rules_paths(target)
        result = run_validation(target, agent="claude", rules_paths=rules_paths)
        return mcp_formatter.format_result(result)
    except FileNotFoundError as e:
        return {"error": str(e)}


def validate_tool_text(path: str = ".") -> str:
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
    if not target.is_dir():
        return f"Error: Path is not a directory: {target}"

    try:
        rules_paths = _resolve_recommended_rules_paths(target)
        result = run_validation(target, agent="claude", rules_paths=rules_paths)
        return text_formatter.format_result(result, ascii_mode=True)
    except FileNotFoundError as e:
        return f"Error: {e}"


def score_tool(path: str = ".") -> dict[str, Any]:
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
    if not target.is_dir():
        return {"error": f"Path is not a directory: {target}"}

    try:
        rules_paths = _resolve_recommended_rules_paths(target)
        result = run_validation(target, agent="claude", rules_paths=rules_paths)
        return mcp_formatter.format_score(result)
    except FileNotFoundError as e:
        return {"error": str(e)}


def judge_tool(path: str = ".", verdicts: list[str] | None = None) -> dict[str, Any]:
    """
    Cache semantic judgment verdicts so they persist across validation runs.

    Args:
        path: Project root directory (default: current directory)
        verdicts: Verdict strings in rule_id:location:verdict:reason format

    Returns:
        Dict with recorded count or error
    """
    if not verdicts:
        return {"error": "No verdicts provided"}

    target = Path(path).resolve()
    if not target.exists():
        return {"error": f"Path not found: {target}"}
    if not target.is_dir():
        return {"error": f"Path is not a directory: {target}"}

    try:
        recorded, failed = cache_judgments_with_errors(target, verdicts)
        result: dict[str, Any] = {"recorded": recorded}
        if failed:
            result["failed"] = failed
        return result
    except (ValueError, OSError) as e:
        return {"error": str(e)}


def cache_judgments_with_errors(target: Path, verdicts: list[str]) -> tuple[int, list[str]]:
    """Cache judgments and return (recorded_count, failed_reasons)."""
    from reporails_cli.core.cache import _parse_verdict_string, cache_judgments

    # Pre-validate verdicts to report failures
    failed: list[str] = []
    valid_verdicts: list[str] = []
    for v in verdicts:
        rule_id, location, verdict, _reason = _parse_verdict_string(v)
        if not rule_id or not location:
            failed.append(f"Invalid format (need RULE:FILE:verdict:reason): {v}")
            continue
        if verdict not in ("pass", "fail"):
            failed.append(f"Invalid verdict value (need pass/fail): {v}")
            continue
        file_path = location.rsplit(":", 1)[0] if ":" in location else location
        full_path = (target / file_path).resolve()
        if not full_path.exists():
            failed.append(f"File not found: {file_path}")
            continue
        valid_verdicts.append(v)

    recorded = cache_judgments(target, valid_verdicts) if valid_verdicts else 0
    return recorded, failed


def explain_tool(rule_id: str, rules_paths: list[Path] | None = None) -> dict[str, Any]:
    """
    Get detailed info about a specific rule.

    Args:
        rule_id: Rule identifier (e.g., S1, C2)
        rules_paths: Optional rules directories (for CLI/testing; MCP auto-resolves)

    Returns:
        Rule details dict
    """
    if rules_paths is None:
        from reporails_cli.core.bootstrap import get_recommended_package_path
        from reporails_cli.core.registry import get_rules_dir

        # Auto-resolve: include recommended if available
        rec_path = get_recommended_package_path()
        if rec_path.is_dir():
            rules_paths = [get_rules_dir(), rec_path]

    # include_experimental=True so any rule can be explained
    rules = load_rules(rules_paths, include_experimental=True)

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
        "slug": rule.slug,
        "targets": rule.targets,
        "checks": [{"id": c.id, "type": c.type, "severity": c.severity.value} for c in rule.checks],
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
