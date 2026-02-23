# pylint: disable=too-many-lines
"""Typer CLI for reporails - validate and score AI instruction files."""

from __future__ import annotations

import sys
import time
from contextlib import nullcontext
from pathlib import Path

import typer

from reporails_cli.core.agents import get_all_instruction_files
from reporails_cli.core.cache import get_previous_scan
from reporails_cli.core.engine import run_validation_sync
from reporails_cli.core.models import ScanDelta
from reporails_cli.core.registry import infer_agent_from_rule_id, load_rules
from reporails_cli.formatters import text as text_formatter
from reporails_cli.interfaces.cli.helpers import (
    _default_format,
    _format_output,
    _handle_no_instruction_files,
    _print_unknown_rule,
    _print_verbose,
    _resolve_recommended_rules,
    _resolve_rules_paths,
    _show_agent_auto_detect_hint,
    _validate_agent,
    _validate_format,
    app,
    console,
)


def _explain_rules_paths(rules: list[str] | None) -> list[Path] | None:
    """Resolve rules paths for explain command, auto-including recommended."""
    if rules:
        return [Path(r).resolve() for r in rules]
    from reporails_cli.core.bootstrap import get_recommended_package_path
    from reporails_cli.core.registry import get_rules_dir

    rec_path = get_recommended_package_path()
    return [get_rules_dir(), rec_path] if rec_path.is_dir() else None


@app.command(rich_help_panel="Commands")
def check(  # pylint: disable=too-many-arguments,too-many-locals,too-many-statements
    path: str = typer.Argument(".", help="File or directory to validate"),
    format: str = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json, github (auto-detects: text for terminal, json for pipes/CI)",
    ),
    rules: list[str] = typer.Option(  # noqa: B008
        None,
        "--rules",
        "-r",
        help="Directory containing rules (repeatable). First = primary framework. Defaults to ~/.reporails/rules/.",
    ),
    exclude_dir: list[str] = typer.Option(  # noqa: B008
        None,
        "--exclude-dir",
        "-x",
        help="Directory name to exclude from scanning (repeatable). Merges with config exclude_dirs.",
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
        help="Use ASCII characters only (no Unicode box drawing)",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Exit with code 1 if violations found (for CI pipelines)",
    ),
    quiet_semantic: bool = typer.Option(
        False,
        "--quiet-semantic",
        "-q",
        help="Suppress 'semantic rules skipped' message (for agent/MCP contexts)",
    ),
    legend: bool = typer.Option(
        False,
        "--legend",
        "-l",
        help="Show severity legend only",
    ),
    agent: str = typer.Option(
        "",
        "--agent",
        help="Agent type for rule overrides and template vars (e.g., claude, cursor, codex)",
    ),
    experimental: bool = typer.Option(
        False,
        "--experimental",
        help="Include experimental rules (methodology-backed, lower confidence)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show rule sources, file count, and scan details",
    ),
    no_update_check: bool = typer.Option(
        False,
        "--no-update-check",
        help="Skip pre-run update check prompt",
    ),
) -> None:
    """Validate AI instruction files against reporails rules."""
    if legend:
        legend_text = text_formatter.format_legend(ascii_mode=ascii)
        print(f"Severity Legend: {legend_text}")
        return

    agent = _validate_agent(agent, console)
    _validate_format(format, console)
    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        console.print("Run 'ails check .' to validate the current directory.")
        raise typer.Exit(2)

    # Resolve --rules paths
    rules_paths = _resolve_rules_paths(rules, console)

    # Load project config for exclude_dirs and recommended opt-out
    from reporails_cli.core.bootstrap import get_project_config

    project_config = get_project_config(target)

    # Resolve effective agent: CLI flag > config default_agent > engine defaults to generic
    if not agent and project_config.default_agent:
        agent = _validate_agent(project_config.default_agent, console)

    # Merge exclude_dirs: config + CLI flags
    all_excludes = set(project_config.exclude_dirs) | set(exclude_dir or [])
    merged_excludes: list[str] | None = sorted(all_excludes) if all_excludes else None

    # Auto-include recommended rules if needed
    rules_paths = _resolve_recommended_rules(rules_paths, project_config, format, console)

    # Pre-run update check (interactive TTY only, text format)
    if format not in ("json", "brief", "compact", "github"):
        from reporails_cli.core.update_check import prompt_for_updates

        prompt_for_updates(console, no_update_check=no_update_check)

    # Early check for missing instruction files
    output_format = format if format else _default_format()
    from reporails_cli.core.agents import (
        detect_agents,
        filter_agents_by_exclude_dirs,
        filter_agents_by_id,
        resolve_agent,
    )

    all_detected_agents = detect_agents(target)

    # Resolution chain: CLI flag > config > auto-detect > generic
    agent, assumed, mixed_signals = resolve_agent(agent, all_detected_agents)
    effective_agent = agent if agent else "generic"
    filtered_agents = filter_agents_by_id(all_detected_agents, effective_agent)
    filtered_agents = filter_agents_by_exclude_dirs(filtered_agents, target, merged_excludes)
    instruction_files = get_all_instruction_files(target, agents=filtered_agents)
    if not instruction_files:
        _handle_no_instruction_files(effective_agent, output_format, console)
        return

    # Get previous scan BEFORE running validation (for delta comparison)
    previous_scan = get_previous_scan(target)

    # Run validation with timing
    show_spinner = sys.stdout.isatty() and format not in ("json", "brief", "compact", "github")
    if show_spinner:
        spinner = console.status("[bold]Loading rules...[/bold]")
        progress_cb = lambda phase, _c, _t: spinner.update(f"[bold]{phase}...[/bold]")  # noqa: E731
    else:
        spinner, progress_cb = nullcontext(), None  # type: ignore[assignment]
    start_time = time.perf_counter()
    try:
        with spinner:
            result = run_validation_sync(
                target,
                rules_paths=rules_paths,
                use_cache=not refresh,
                agent=agent,
                include_experimental=experimental,
                exclude_dirs=merged_excludes,
                on_progress=progress_cb,
            )
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] File not found during validation: {e.filename or e}")
        raise typer.Exit(2) from None
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # Compute delta from previous scan
    delta = ScanDelta.compute(
        current_score=result.score,
        current_level=result.level.value,
        current_violations=len(result.violations),
        previous=previous_scan,
    )

    # Build surface summary from agent detection for display
    from reporails_cli.formatters.text.components import build_surface_summary

    surface = build_surface_summary(filtered_agents, target) | {
        "detected_agents": [a.agent_type.id for a in all_detected_agents],
        "effective_agent": effective_agent,
        "assumed": assumed,
    }

    # Format output
    _format_output(
        result,
        delta,
        output_format,
        ascii,
        quiet_semantic,
        elapsed_ms,
        console,
        surface=surface,
    )

    # Agent auto-detect messaging
    _show_agent_auto_detect_hint(effective_agent, output_format, assumed, mixed_signals, all_detected_agents)

    # Verbose diagnostics (text formats only)
    if verbose and output_format not in ("json", "brief"):
        _print_verbose(rules_paths, instruction_files, result, agent, elapsed_ms, target, experimental, console)

    # Exit with error only in strict mode
    if strict and result.violations:
        raise typer.Exit(1)


@app.command(rich_help_panel="Commands")
def explain(
    rule_id: str = typer.Argument(..., help="Rule ID (e.g., S1, C2)"),
    rules: list[str] = typer.Option(  # noqa: B008
        None,
        "--rules",
        "-r",
        help="Directory containing rules (repeatable). Same semantics as check --rules.",
    ),
) -> None:
    """Show rule details."""
    rules_paths = _explain_rules_paths(rules)
    rule_id_upper = rule_id.upper()
    agent = infer_agent_from_rule_id(rule_id_upper)  # auto-load agent-namespaced rules
    loaded_rules = load_rules(rules_paths, agent=agent)

    if rule_id_upper not in loaded_rules:
        _print_unknown_rule(rule_id, loaded_rules)
        raise typer.Exit(2)

    rule = loaded_rules[rule_id_upper]
    rule_data = {
        "title": rule.title,
        "category": rule.category.value,
        "type": rule.type.value,
        "level": rule.level,
        "slug": rule.slug,
        "targets": rule.targets,
        "checks": [
            {"id": c.id, "type": c.type, "name": c.name, "check": c.check, "severity": c.severity.value}
            for c in rule.checks
        ],
        "see_also": rule.see_also,
    }

    # Read description from markdown file if available
    if rule.md_path and rule.md_path.exists():
        content = rule.md_path.read_text(encoding="utf-8")
        parts = content.split("---", 2)
        if len(parts) >= 3:
            rule_data["description"] = parts[2].strip()[:500]

    output = text_formatter.format_rule(rule_id_upper, rule_data)
    console.print(output)


def main() -> None:
    """Entry point for CLI."""
    app()


import reporails_cli.interfaces.cli.commands  # noqa: E402  # Register commands
import reporails_cli.interfaces.cli.heal  # noqa: E402  # Register heal command
import reporails_cli.interfaces.cli.install  # noqa: E402  # Register install command
import reporails_cli.interfaces.cli.test_command  # noqa: F401, E402  # Register test command
from reporails_cli.interfaces.cli.config_command import config_app  # noqa: E402

app.add_typer(config_app, rich_help_panel="Configuration")

if __name__ == "__main__":
    main()
