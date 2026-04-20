"""Heal command — apply auto-fixes to instruction file issues.

Combines additive fixers (missing sections) with mechanical fixers
(formatting, bold, italic, ordering) that operate on atom-level data.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path
from typing import Any

import typer

from reporails_cli.interfaces.cli.main import app  # type: ignore[attr-defined]

logger = logging.getLogger(__name__)


def _build_ruleset_map(
    instruction_files: list[Path],
    target: Path,
    show_progress: bool,
    console: Any,
) -> Any:
    """Build ruleset map via daemon or in-process fallback."""
    from reporails_cli.interfaces.cli.main import _suppress_ml_noise

    _suppress_ml_noise()

    if show_progress:
        console.print("[bold]Mapping instruction files...[/bold]")

    try:
        from reporails_cli.core.mapper.daemon_client import ensure_daemon, map_ruleset_via_daemon

        ensure_daemon()
        ruleset_map = map_ruleset_via_daemon(list(instruction_files), target)
        if ruleset_map is None:
            from reporails_cli.interfaces.cli.main import _map_in_process

            ruleset_map = _map_in_process(instruction_files)
        return ruleset_map
    except (ImportError, RuntimeError) as exc:
        logger.warning("Mapper unavailable in heal: %s", exc)
        if show_progress:
            console.print("[dim]Mapper unavailable — mechanical fixes skipped.[/dim]")
        return None


def _apply_mechanical_fixes(
    ruleset_map: Any,
    target: Path,
    dry_run: bool,
    show_progress: bool,
    console: Any,
) -> list[dict[str, Any]]:
    """Apply atom-level mechanical fixes. Returns list of fix dicts."""
    if ruleset_map is None:
        return []
    if show_progress:
        console.print("[bold]Applying mechanical fixes...[/bold]")
    from reporails_cli.core.mechanical_fixers import apply_mechanical_fixes

    mech_fixes = apply_mechanical_fixes(ruleset_map, target, dry_run=dry_run)
    return [
        {"rule_id": mf.fix_type, "file_path": mf.file_path, "line": mf.line, "description": mf.description}
        for mf in mech_fixes
    ]


def _apply_additive_fixes(
    target: Path,
    instruction_files: list[Path],
    effective_agent: str,
    dry_run: bool,
    show_progress: bool,
    console: Any,
) -> list[dict[str, Any]]:
    """Run M probes and apply additive fixes (missing sections)."""
    from reporails_cli.core.fixers import apply_auto_fixes as _apply_auto_fixes
    from reporails_cli.core.models import Severity, Violation
    from reporails_cli.core.rule_runner import run_m_probes

    if show_progress:
        console.print("[bold]Running structural checks...[/bold]")
    m_findings = run_m_probes(target, instruction_files, agent=effective_agent)

    if dry_run:
        return []

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
    add_fixes = _apply_auto_fixes(violations, target)
    return [{"rule_id": af.rule_id, "file_path": af.file_path, "description": af.description} for af in add_fixes]


def _discover_heal_targets(
    target: Path,
    agent: str,
    exclude_dirs: list[str] | None,
    output_format: str,
    console: Any,
) -> tuple[str, list[Path]] | None:
    """Discover instruction files for healing. Returns (agent, files) or None."""
    from reporails_cli.core import agents as _agents
    from reporails_cli.core.config import get_project_config
    from reporails_cli.interfaces.cli import helpers as _helpers

    config = get_project_config(target)
    agent_arg = agent or config.default_agent
    excl = exclude_dirs if exclude_dirs is not None else config.exclude_dirs

    if agent_arg:
        _helpers._validate_agent(agent_arg, console)
    detected = _agents.detect_agents(target)
    effective_agent, _, _, filtered = _helpers._resolve_agent_filters(agent_arg, detected, target, excl)
    files = _agents.get_all_instruction_files(target, agents=filtered)
    if not files:
        _helpers._handle_no_instruction_files(effective_agent, output_format, console)
        return None
    return effective_agent, files


def _output_heal_results(
    all_fixes: list[dict[str, Any]],
    mechanical_results: list[dict[str, Any]],
    additive_results: list[dict[str, Any]],
    dry_run: bool,
    elapsed_ms: float,
    output_format: str,
    console: Any,
) -> None:
    """Output heal results in the requested format."""
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


def _heal_validate_path(path: str) -> tuple[Path, Any]:
    """Validate heal target path and create console. Raises typer.Exit on error."""
    from rich.console import Console

    console = Console(stderr=True)
    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(2)
    return target, console


@app.command(rich_help_panel="Commands")
def heal(
    path: str = typer.Argument(".", help="Project root to heal"),
    format: str = typer.Option(None, "--format", "-f", help="Output format: text, json"),
    agent: str = typer.Option("", "--agent", help="Agent type"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show fixes without applying"),
    exclude_dirs: list[str] = typer.Option(None, "--exclude-dirs", help="Directories to exclude"),  # noqa: B008
) -> None:
    """Auto-fix instruction file issues.

    Applies formatting fixes (backticks, bold->italic, constraint wrapping,
    charge ordering) and structural fixes (missing sections). Use --dry-run
    to preview changes without writing.
    """
    target, console = _heal_validate_path(path)
    fmt = _resolve_heal_format(format)
    discovery = _discover_heal_targets(target, agent, exclude_dirs, fmt, console)
    if discovery is None:
        return
    _run_heal_pipeline(target, discovery, dry_run, fmt, console)


def _resolve_heal_format(format_arg: str | None) -> str:
    """Resolve output format with default fallback."""
    from reporails_cli.interfaces.cli.helpers import _default_format

    return format_arg or _default_format()


def _run_heal_pipeline(
    target: Path,
    discovery: tuple[str, list[Path]],
    dry_run: bool,
    fmt: str,
    console: Any,
) -> None:
    """Execute the heal pipeline: map, mechanical fixes, additive fixes, output."""
    show = sys.stdout.isatty() and fmt != "json"
    start = time.perf_counter()
    effective_agent, instruction_files = discovery

    mech = _apply_mechanical_fixes(
        _build_ruleset_map(instruction_files, target, show, console),
        target,
        dry_run,
        show,
        console,
    )
    additive = _apply_additive_fixes(target, instruction_files, effective_agent, dry_run, show, console)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
    _output_heal_results(mech + additive, mech, additive, dry_run, elapsed_ms, fmt, console)


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
