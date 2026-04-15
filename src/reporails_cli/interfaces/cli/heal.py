"""Heal command — apply auto-fixes to instruction file issues.

Combines additive fixers (missing sections) with mechanical fixers
(formatting, bold, italic, ordering) that operate on atom-level data.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

import typer

from reporails_cli.interfaces.cli.main import app  # type: ignore[attr-defined]


@app.command(rich_help_panel="Commands")
def heal(  # noqa: C901
    path: str = typer.Argument(".", help="Project root to heal"),
    format: str = typer.Option(None, "--format", "-f", help="Output format: text, json"),
    agent: str = typer.Option("", "--agent", help="Agent type"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show fixes without applying"),
    exclude_dirs: list[str] = typer.Option(None, "--exclude-dirs", help="Directories to exclude"),  # noqa: B008
) -> None:
    """Auto-fix instruction file issues.

    Applies formatting fixes (backticks, bold→italic, constraint wrapping,
    charge ordering) and structural fixes (missing sections). Use --dry-run
    to preview changes without writing.
    """
    from rich.console import Console

    from reporails_cli.core.agents import detect_agents, get_all_instruction_files
    from reporails_cli.core.config import get_project_config
    from reporails_cli.core.fixers import apply_auto_fixes as _apply_auto_fixes
    from reporails_cli.core.models import Severity, Violation
    from reporails_cli.core.rule_runner import run_m_probes
    from reporails_cli.interfaces.cli.helpers import _default_format, _handle_no_instruction_files
    from reporails_cli.interfaces.cli.main import _suppress_ml_noise

    console = Console(stderr=True)
    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(2)

    output_format = format or _default_format()

    # 1. Detect agents and discover files
    detected = detect_agents(target)
    config = get_project_config(target)
    agent_arg = agent or config.default_agent
    excl = exclude_dirs if exclude_dirs is not None else config.exclude_dirs
    from reporails_cli.interfaces.cli.helpers import _resolve_agent_filters, _validate_agent

    if agent_arg:
        _validate_agent(agent_arg, console)
    effective_agent, _assumed, _mixed, filtered = _resolve_agent_filters(agent_arg, detected, target, excl)
    instruction_files = get_all_instruction_files(target, agents=filtered)
    if not instruction_files:
        _handle_no_instruction_files(effective_agent, output_format, console)
        return

    show_progress = sys.stdout.isatty() and output_format != "json"
    start_time = time.perf_counter()

    # 2. Run mapper for mechanical fixes
    _suppress_ml_noise()
    ruleset_map = None
    cache_dir = target / ".ails" / ".cache"

    if show_progress:
        console.print("[bold]Mapping instruction files...[/bold]")

    try:
        from reporails_cli.core.mapper.daemon_client import ensure_daemon, map_ruleset_via_daemon

        ensure_daemon(cache_dir)
        ruleset_map = map_ruleset_via_daemon(list(instruction_files), target, cache_dir)
        if ruleset_map is None:
            from reporails_cli.interfaces.cli.main import _map_in_process

            ruleset_map = _map_in_process(instruction_files, cache_dir)
    except ImportError:
        if show_progress:
            console.print("[dim]Mapper unavailable — mechanical fixes skipped.[/dim]")

    # 3. Apply mechanical fixes (atom-level)
    mechanical_results: list[dict[str, Any]] = []
    if ruleset_map is not None:
        if show_progress:
            console.print("[bold]Applying mechanical fixes...[/bold]")
        from reporails_cli.core.mechanical_fixers import apply_mechanical_fixes

        mech_fixes = apply_mechanical_fixes(ruleset_map, target, dry_run=dry_run)
        mechanical_results.extend(
            {"rule_id": mf.fix_type, "file_path": mf.file_path, "line": mf.line, "description": mf.description}
            for mf in mech_fixes
        )

    # 4. Run M probes for additive fixes
    if show_progress:
        console.print("[bold]Running structural checks...[/bold]")
    m_findings = run_m_probes(target, instruction_files, agent=effective_agent)

    # Convert findings to Violations for additive fixers
    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
    violations = [
        Violation(
            rule_id=f.rule,
            rule_title="",
            severity=sev_map.get(f.severity, Severity.MEDIUM),
            message=f.message,
            location=f"{f.file}:{f.line}" if f.line else f.file,
        )
        for f in m_findings
    ]

    # 5. Apply additive fixes (missing sections)
    additive_results: list[dict[str, Any]] = []
    if not dry_run:
        add_fixes = _apply_auto_fixes(violations, target)
        additive_results.extend(
            {"rule_id": af.rule_id, "file_path": af.file_path, "description": af.description} for af in add_fixes
        )

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 1)
    all_fixes = mechanical_results + additive_results

    # 6. Output
    if output_format == "json":
        data = {
            "auto_fixed": all_fixes,
            "summary": {
                "auto_fixed_count": len(all_fixes),
                "mechanical_count": len(mechanical_results),
                "additive_count": len(additive_results),
                "dry_run": dry_run,
                "elapsed_ms": elapsed_ms,
            },
        }
        print(json.dumps(data, indent=2))
    else:
        _print_text_result(all_fixes, dry_run, elapsed_ms, console)


def _print_text_result(
    fixes: list[dict[str, Any]],
    dry_run: bool,
    elapsed_ms: float,
    console: Any,
) -> None:
    """Print human-readable heal results."""
    prefix = "[dim]would fix[/dim]" if dry_run else "[green]fixed[/green]"

    if not fixes:
        console.print("[green]No fixable issues found.[/green]")
        console.print(f"[dim]{elapsed_ms:.0f}ms[/dim]")
        return

    # Group by file
    by_file: dict[str, list[dict[str, Any]]] = {}
    for f in fixes:
        by_file.setdefault(f.get("file_path", "?"), []).append(f)

    for filepath, file_fixes in sorted(by_file.items()):
        console.print(f"\n[bold]{filepath}[/bold]")
        for fix in file_fixes:
            line = fix.get("line", "")
            line_str = f"L{line} " if line else ""
            console.print(f"  {prefix} {line_str}{fix['description']}")

    console.print(
        f"\n[bold]{len(fixes)}[/bold] fix{'es' if len(fixes) != 1 else ''} "
        + ("(dry run)" if dry_run else "applied")
        + f" in {elapsed_ms:.0f}ms"
    )
