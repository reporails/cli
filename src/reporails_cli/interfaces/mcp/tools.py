"""MCP tool implementations for reporails."""

from pathlib import Path
from typing import Any

from reporails_cli.core.bootstrap import is_initialized
from reporails_cli.core.models import FileMatch
from reporails_cli.core.registry import infer_agent_from_rule_id, load_rules
from reporails_cli.formatters import mcp as mcp_formatter


def _serialize_match(match: FileMatch | None) -> dict[str, object]:
    """Serialize FileMatch to dict, including all non-None properties."""
    if match is None:
        return {}
    result: dict[str, object] = {}
    if match.type is not None:
        result["type"] = match.type
    for prop in ("format", "scope", "cardinality", "lifecycle", "maintainer", "vcs", "loading", "precedence"):
        val = getattr(match, prop)
        if val is not None:
            result[prop] = val
    return result


def _run_pipeline(target: Path) -> dict[str, Any]:
    """Run the full check pipeline and return CombinedResult as dict."""
    from reporails_cli.core.agents import detect_agents, get_all_instruction_files, resolve_agent
    from reporails_cli.core.api_client import AilsClient
    from reporails_cli.core.client_checks import run_client_checks
    from reporails_cli.core.config import get_project_config
    from reporails_cli.core.merger import merge_results
    from reporails_cli.core.rule_runner import run_content_quality_checks, run_m_probes
    from reporails_cli.formatters import json as json_formatter

    config = get_project_config(target)
    detected = detect_agents(target)
    effective_agent, _, _ = resolve_agent(config.default_agent, detected)
    instruction_files = get_all_instruction_files(target, agents=detected)
    if not instruction_files:
        return {"error": "No instruction files found"}

    # Build map first
    ruleset_map = None
    try:
        from reporails_cli.core.mapper import map_ruleset

        cache_dir = target / ".ails" / ".cache"
        ruleset_map = map_ruleset(list(instruction_files), cache_dir=cache_dir)
    except (ImportError, RuntimeError):
        pass

    # M probes (mechanical + deterministic)
    m_findings = run_m_probes(target, instruction_files, agent=effective_agent)

    # Content quality + client checks on map
    content_findings = (
        run_content_quality_checks(ruleset_map, target, instruction_files, agent=effective_agent) if ruleset_map else []
    )
    client_findings = run_client_checks(ruleset_map) if ruleset_map else []

    lint_result = AilsClient().lint(ruleset_map) if ruleset_map else None
    server_report = lint_result.report if lint_result else None
    hints = lint_result.hints if lint_result else ()
    result = merge_results(
        m_findings, content_findings + client_findings, server_report, hints=hints, project_root=target
    )
    return json_formatter.format_combined_result(result)


def validate_tool(path: str = ".") -> dict[str, Any]:
    """Validate AI instruction files at path."""
    if not is_initialized():
        return {"error": "Reporails not initialized. Run 'ails install' first."}
    target = Path(path).resolve()
    if not target.exists():
        return {"error": f"Path not found: {target}"}
    if not target.is_dir():
        return {"error": f"Path is not a directory: {target}"}
    try:
        return _run_pipeline(target)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return {"error": str(e)}


def score_tool(path: str = ".") -> dict[str, Any]:
    """Quick score check for AI instruction files."""
    if not is_initialized():
        return {"error": "Reporails not initialized. Run 'ails install' first."}
    target = Path(path).resolve()
    if not target.exists():
        return {"error": f"Path not found: {target}"}
    if not target.is_dir():
        return {"error": f"Path is not a directory: {target}"}
    try:
        result = _run_pipeline(target)
        if "error" in result:
            return result
        stats = result.get("stats", {})
        return {
            "compliance_band": result.get("compliance_band", "offline"),
            "total_findings": stats.get("total_findings", 0),
            "errors": stats.get("errors", 0),
            "warnings": stats.get("warnings", 0),
            "offline": result.get("offline", True),
        }
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return {"error": str(e)}


def heal_tool(path: str = ".", dry_run: bool = False) -> dict[str, Any]:
    """Auto-fix instruction file issues at path."""
    if not is_initialized():
        return {"error": "Reporails not initialized. Run 'ails install' first."}
    target = Path(path).resolve()
    if not target.exists():
        return {"error": f"Path not found: {target}"}
    if not target.is_dir():
        return {"error": f"Path is not a directory: {target}"}
    try:
        from reporails_cli.core.agents import detect_agents, get_all_instruction_files, resolve_agent
        from reporails_cli.core.config import get_project_config

        config = get_project_config(target)
        detected = detect_agents(target)
        _agent, _, _ = resolve_agent(config.default_agent, detected)
        instruction_files = get_all_instruction_files(target, agents=detected)
        if not instruction_files:
            return {"auto_fixed": [], "summary": {"auto_fixed_count": 0}}

        ruleset_map = None
        try:
            from reporails_cli.core.mapper import map_ruleset

            cache_dir = target / ".ails" / ".cache"
            ruleset_map = map_ruleset(list(instruction_files), cache_dir=cache_dir)
        except (ImportError, RuntimeError):
            pass

        fixes: list[dict[str, str]] = []
        if ruleset_map is not None:
            from reporails_cli.core.mechanical_fixers import apply_mechanical_fixes

            mech = apply_mechanical_fixes(ruleset_map, target, dry_run=dry_run)
            fixes.extend({"rule_id": m.fix_type, "file_path": m.file_path, "description": m.description} for m in mech)

        return {"auto_fixed": fixes, "summary": {"auto_fixed_count": len(fixes), "dry_run": dry_run}}
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return {"error": str(e)}


def explain_tool(rule_id: str, rules_paths: list[Path] | None = None) -> str | dict[str, Any]:
    """Get detailed info about a specific rule."""
    if rules_paths is None:
        from reporails_cli.core.bootstrap import get_recommended_package_path
        from reporails_cli.core.registry import get_rules_dir

        rec_path = get_recommended_package_path()
        if rec_path.is_dir():
            rules_paths = [get_rules_dir(), rec_path]

    rule_id_upper = rule_id.upper()
    agent = infer_agent_from_rule_id(rule_id_upper)
    rules = load_rules(rules_paths, agent=agent)

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
        "slug": rule.slug,
        "match": _serialize_match(rule.match),
        "severity": rule.severity.value,
        "checks": [{"id": c.id, "type": c.type} for c in rule.checks],
        "see_also": rule.see_also,
    }

    if rule.md_path and rule.md_path.exists():
        try:
            content = rule.md_path.read_text(encoding="utf-8")
            parts = content.split("---", 2)
            if len(parts) >= 3:
                rule_data["description"] = parts[2].strip()[:500]
        except (OSError, ValueError):
            pass

    return mcp_formatter.format_rule(rule_id_upper, rule_data)
