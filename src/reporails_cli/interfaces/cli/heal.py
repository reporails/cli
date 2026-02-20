"""Autoheal command — ails heal.

Silently applies all auto-fixes and reports results.
Non-fixable violations are listed for the coding agent to handle.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

from reporails_cli.core.engine import run_validation_sync
from reporails_cli.core.fixers import apply_auto_fixes, partition_violations
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters.text.heal import format_heal_summary
from reporails_cli.interfaces.cli.helpers import (
    _resolve_recommended_rules,
    _resolve_rules_paths,
    _validate_agent,
    app,
    console,
)

if TYPE_CHECKING:
    from reporails_cli.core.fixers import FixResult
    from reporails_cli.core.models import JudgmentRequest, Violation

VALID_HEAL_FORMATS = {"text", "json"}


def _serialize_heal_json(
    fixes: list[FixResult],
    non_fixable: list[Violation],
    requests: list[JudgmentRequest],
    target: Path,
) -> dict[str, Any]:
    """Serialize heal results to JSON-compatible dict."""
    auto_fixed_data = [
        {
            "rule_id": fix.rule_id,
            "file_path": str(Path(fix.file_path).relative_to(target))
            if Path(fix.file_path).is_relative_to(target)
            else fix.file_path,
            "description": fix.description,
        }
        for fix in fixes
    ]

    violation_data = [
        {
            "rule_id": v.rule_id,
            "rule_title": v.rule_title,
            "location": v.location,
            "message": v.message,
            "severity": v.severity.value,
        }
        for v in non_fixable
    ]

    judgment_data = [
        {
            "rule_id": jr.rule_id,
            "rule_title": jr.rule_title,
            "question": jr.question,
            "content": jr.content,
            "location": jr.location,
            "criteria": jr.criteria,
            "examples": jr.examples,
            "choices": jr.choices,
            "pass_value": jr.pass_value,
        }
        for jr in requests
    ]

    return json_formatter.format_heal_result(
        auto_fixed_data,
        judgment_data,
        violations=violation_data,
    )


@app.command(rich_help_panel="Commands")
def heal(  # pylint: disable=too-many-locals
    path: str = typer.Argument(".", help="Project root to heal"),
    rules: list[str] = typer.Option(  # noqa: B008
        None,
        "--rules",
        "-r",
        help="Directory containing rules (repeatable).",
    ),
    exclude_dir: list[str] = typer.Option(  # noqa: B008
        None,
        "--exclude-dir",
        "-x",
        help="Directory name to exclude from scanning (repeatable).",
    ),
    refresh: bool = typer.Option(
        False,
        "--refresh",
        help="Refresh file map cache (re-scan for instruction files)",
    ),
    ascii: bool = typer.Option(
        False,
        "--ascii",
        "-a",
        help="Use ASCII characters only (no Unicode)",
    ),
    agent: str = typer.Option(
        "",
        "--agent",
        help="Agent type for rule overrides and template vars (e.g., claude, cursor, codex)",
    ),
    experimental: bool = typer.Option(
        False,
        "--experimental",
        help="Include experimental rules",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text or json",
    ),
) -> None:
    """Apply all auto-fixes and report remaining violations."""
    # Validate format
    if format not in VALID_HEAL_FORMATS:
        console.print(f"[red]Error:[/red] Unknown format: {format}")
        console.print(f"Valid formats: {', '.join(sorted(VALID_HEAL_FORMATS))}")
        raise typer.Exit(2)

    # Normalize and validate agent
    agent = _validate_agent(agent, console)

    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(2)

    # Resolve rules paths
    rules_paths = _resolve_rules_paths(rules, console)

    # Load project config
    from reporails_cli.core.bootstrap import get_project_config

    project_config = get_project_config(target)

    # Resolve effective agent: CLI flag > config default_agent > engine defaults to generic
    if not agent and project_config.default_agent:
        agent = _validate_agent(project_config.default_agent, console)

    # Merge exclude_dirs
    merged_excludes: list[str] | None = None
    all_excludes = set(project_config.exclude_dirs) | set(exclude_dir or [])
    if all_excludes:
        merged_excludes = sorted(all_excludes)

    rules_paths = _resolve_recommended_rules(rules_paths, project_config, format, console)

    # Run validation
    result = run_validation_sync(
        target,
        rules_paths=rules_paths,
        use_cache=not refresh,
        agent=agent,
        include_experimental=experimental,
        exclude_dirs=merged_excludes,
        record_analytics=False,
    )

    # Partition violations and apply fixes
    fixable, non_fixable = partition_violations(list(result.violations))
    requests = list(result.judgment_requests)
    fixes = apply_auto_fixes(fixable, target)

    # Output
    if format == "json":
        output = _serialize_heal_json(fixes, non_fixable, requests, target)
        print(json.dumps(output, indent=2))
    else:
        summary = format_heal_summary(fixes, non_fixable, requests, ascii_mode=ascii)
        console.print(summary)
        if fixes or non_fixable or requests:
            console.print("\n[dim]Run 'ails check' to see your updated score.[/dim]")
