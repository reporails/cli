"""MCP tool implementations for reporails.

Trimmed surface (post-0.5.11): `validate`, `preflight`, `explain`. `score` and
`heal` removed — the slash command derives score from `validate.stats` /
`surface_health` and runs the heal-via-Edit fix-walk in its own SKILL.md body.
CLI `ails check --heal` continues to serve batch deterministic use.
"""

import logging
from pathlib import Path
from typing import Any

from reporails_cli.core.platform.adapters.registry import infer_agent_from_rule_id, load_rules
from reporails_cli.core.platform.config.bootstrap import is_initialized
from reporails_cli.core.platform.dto.models import FileMatch
from reporails_cli.formatters import mcp as mcp_formatter

logger = logging.getLogger(__name__)


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


def _discover_files(target: Path, single_file: Path | None = None) -> tuple[list[Any], str, list[Any]] | None:
    """Detect agents and discover instruction files. Returns (detected, agent, files) or None.

    `target` is the discovery root (a directory). When `single_file` is given the
    validated set is narrowed to that one file while agents resolve against `target`.
    """
    from reporails_cli.core.discovery.agents import detect_agents, get_all_instruction_files, resolve_agent
    from reporails_cli.core.platform.config.config import get_project_config

    config = get_project_config(target)
    detected = detect_agents(target)
    effective_agent, _, _ = resolve_agent(config.default_agent, detected)
    if single_file is not None:
        return detected, effective_agent, [single_file.resolve()]
    instruction_files = get_all_instruction_files(target, agents=detected)
    if not instruction_files:
        return None
    return detected, effective_agent, instruction_files


def _build_map(target: Path, instruction_files: list[Any]) -> Any:  # noqa: ARG001
    """Build ruleset map, returning None on failure."""
    try:
        from reporails_cli.core.mapper import map_ruleset
        from reporails_cli.core.platform.config.bootstrap import get_global_cache_dir

        return map_ruleset(list(instruction_files), cache_dir=get_global_cache_dir())
    except (ImportError, RuntimeError) as exc:
        logger.warning("Mapper unavailable in MCP: %s", exc)
        return None


def _merge_with_server(
    m_findings: list[Any],
    client_findings: list[Any],
    ruleset_map: Any,
    target: Path,
    agent: str = "",
) -> Any:
    """Merge local findings with server diagnostics, returning CombinedResult.

    `agent` must match the agent the findings were produced under, so agent-superseded
    structural rules resolve to the same id the findings carry (see `structural_rule_ids`).
    """
    from reporails_cli.core.platform.adapters.api_client import AilsClient
    from reporails_cli.core.platform.adapters.registry import structural_rule_ids
    from reporails_cli.core.platform.policy.completeness import structural_gaps_by_path
    from reporails_cli.core.platform.runtime.merger import merge_results

    structural_ids = structural_rule_ids(agent)
    local_findings = structural_gaps_by_path(list(m_findings) + list(client_findings), structural_ids)
    response = AilsClient().lint(ruleset_map, local_findings, len(structural_ids)) if ruleset_map else None
    lint_result = response.result if response else None
    return merge_results(
        m_findings,
        client_findings,
        lint_result.report if lint_result else None,
        hints=lint_result.hints if lint_result else (),
        cross_file_coordinates=lint_result.cross_file_coordinates if lint_result else (),
        project_root=target,
        tier=lint_result.tier if lint_result else "",
    )


def _resolve_scan_target(target: Path) -> tuple[Path, Path | None]:
    """Map a target to `(scan_root, single_file)`. A file roots at its project dir."""
    from reporails_cli.core.discovery.agent_discovery import resolve_project_root

    single_file = target if target.is_file() else None
    return resolve_project_root(target), single_file


def _run_pipeline(target: Path) -> dict[str, Any]:
    """Run the full check pipeline and return CombinedResult as dict.

    A file `target` narrows discovery to its project root and the validated set
    to that single file, mirroring the CLI single-path mode.
    """
    scan_root, single_file = _resolve_scan_target(target)
    discovery = _discover_files(scan_root, single_file=single_file)
    if discovery is None:
        return {"error": "No instruction files found"}
    _detected, effective_agent, instruction_files = discovery
    return _lint_discovered(scan_root, effective_agent, instruction_files)


def _lint_discovered(scan_root: Path, effective_agent: str, instruction_files: list[Any]) -> dict[str, Any]:
    """Run M-probes + content/client checks over discovered files, formatted as a dict.

    Regime + surface health key against `scan_root` (the validated path), not the
    server cwd — otherwise regime drops out and surface scores misroute for MCP.
    """
    from reporails_cli.core.lint.client_checks import run_client_checks
    from reporails_cli.core.lint.rule_runner import run_content_quality_checks, run_m_probes
    from reporails_cli.formatters import json as json_formatter

    ruleset_map = _build_map(scan_root, instruction_files)
    m_findings = run_m_probes(scan_root, instruction_files, agent=effective_agent)
    content_findings = (
        run_content_quality_checks(ruleset_map, scan_root, instruction_files, agent=effective_agent)
        if ruleset_map
        else []
    )
    client_findings = run_client_checks(ruleset_map) if ruleset_map else []

    result = _merge_with_server(
        m_findings, content_findings + client_findings, ruleset_map, scan_root, agent=effective_agent
    )
    # Honor inline `ails-disable-line` directives on this surface too — the CLI `check`
    # path drops them before display, so the agent-facing MCP surface must match or it
    # re-flags a finding the author already dismissed.
    from reporails_cli.core.lint.suppression import apply_suppressions
    from reporails_cli.formatters.text.display_constants import rule_aliases

    result = apply_suppressions(result, project_root=scan_root, alias_fn=rule_aliases)
    return json_formatter.format_combined_result(result, ruleset_map=ruleset_map, project_root=scan_root)


def validate_tool(path: str = ".") -> dict[str, Any]:
    """Validate AI instruction files at `path` (directory OR single file).

    The slash-command body consumes the response per its Check loop — opens
    with one paragraph naming the worst surface + dominant category, then
    spawns the fix-walk sub-agent. Returns a structured `needs_install`
    response (not a bare error) when framework rules are absent, so the
    slash-command body can surface an actionable next step.
    """
    if not is_initialized():
        return {
            "needs_install": True,
            "message": "Reporails framework not installed. Run `ails install` to download the rules pack.",
            "command": "ails install",
        }
    target = Path(path).resolve()
    if not target.exists():
        return {"error": f"Path not found: {target}"}
    # When `path` is an existing file, the pipeline narrows discovery to the
    # file's project root and the validated set to that single file.
    try:
        return _run_pipeline(target)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return {"error": str(e)}


def preflight_tool(capability: str, agent: str = "") -> dict[str, Any]:
    """Return workflow-ordered rules for authoring a file of `capability`.

    Backs `/reporails:ails preflight <capability>` in the plugin. Returns the
    same data the CLI's `ails rules list --capability=<capability> -f json` emits — rules
    sorted by category in workflow order (structure → direction → coherence
    → efficiency → maintenance → governance), severity tiebreaker, with
    Pass / Fail example blocks attached.

    The SKILL.md body presents the rule list and offers to draft; the
    structured shape lets the model walk rules category-by-category without
    parsing markdown.
    """
    from reporails_cli.core.platform.adapters.rules_query import rules_for_capability

    if not is_initialized():
        return {
            "needs_install": True,
            "message": "Reporails framework not installed. Run `ails install` to download the rules pack.",
            "command": "ails install",
        }
    if not capability:
        return {"error": "capability argument is required (e.g. 'skill', 'agent', 'rule', 'main')"}

    agents = [agent] if agent else None
    rules = rules_for_capability(capability, agents=agents)

    return {
        "capability": capability,
        "agent": agent,
        "rules": [_serialize_preflight_rule(r) for r in rules],
        "count": len(rules),
    }


def _serialize_preflight_rule(rule: Any) -> dict[str, Any]:
    """Shape one rule for the preflight response payload."""
    from reporails_cli.core.platform.adapters.rules_query import load_rule_examples

    examples = load_rule_examples(rule)
    payload: dict[str, Any] = {
        "id": rule.id,
        "title": rule.title,
        "category": rule.category.value,
        "severity": rule.severity.value,
        "slug": rule.slug,
        "match": _serialize_match(rule.match),
    }
    if examples.get("pass"):
        payload["pass_example"] = examples["pass"]
    if examples.get("fail"):
        payload["fail_example"] = examples["fail"]
    return payload


def explain_tool(rule_id: str, rules_paths: list[Path] | None = None) -> str | dict[str, Any]:
    """Get detailed info about a specific rule."""
    rule_id_upper = rule_id.upper()
    agent = infer_agent_from_rule_id(rule_id_upper)
    rules = load_rules(rules_paths, agent=agent)

    if rule_id_upper not in rules:
        return {
            "error": f"Unknown rule: {rule_id}",
            "available_rules": sorted(rules.keys()),
        }

    rule = rules[rule_id_upper]
    rule_data: dict[str, Any] = {
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

    # Pass / Fail examples — same extractor `ails explain` / `ails rules -f md` use,
    # so the MCP explain surface agrees with the CLI on example presence.
    from reporails_cli.core.platform.adapters.rules_query import load_rule_examples

    rule_data["examples"] = load_rule_examples(rule)

    return mcp_formatter.format_rule(rule_id_upper, rule_data)
