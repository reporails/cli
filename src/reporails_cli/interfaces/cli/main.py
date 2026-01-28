"""Typer CLI for reporails - lint and score AI instruction files."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import typer
from rich.console import Console

from reporails_cli.core.agents import get_all_instruction_files
from reporails_cli.core.cache import get_previous_scan, record_scan
from reporails_cli.core.discover import generate_backbone_yaml, run_discovery, save_backbone
from reporails_cli.core.engine import run_validation_sync
from reporails_cli.core.models import ScanDelta
from reporails_cli.core.opengrep import set_debug_timing
from reporails_cli.core.registry import load_rules
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters import text as text_formatter

app = typer.Typer(
    name="ails",
    help="Lint and score CLAUDE.md files - what ails your repo?",
    no_args_is_help=True,
)
console = Console()


def _is_ci() -> bool:
    """Check if running in CI environment."""
    ci_vars = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI")
    return any(os.environ.get(var) for var in ci_vars)


def _default_format() -> str:
    """Return default format based on environment detection."""
    if _is_ci():
        return "json"
    if not sys.stdout.isatty():
        return "compact"
    return "text"


@app.command()
def check(
    path: str = typer.Argument(".", help="Directory to validate"),
    format: str = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json (auto-detects: text for terminal, json for pipes/CI)",
    ),
    rules_dir: str = typer.Option(
        None,
        "--rules-dir",
        "-r",
        help="Directory containing rules (defaults to ~/.reporails/rules/)",
    ),
    refresh: bool = typer.Option(
        False,
        "--refresh",
        help="Refresh file map cache (re-scan for CLAUDE.md files)",
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
        "claude",
        "--agent",
        help="Agent identifier for template vars (claude, cursor, etc.)",
    ),
    debug: bool = typer.Option(
        False,
        "--debug",
        help="Show timing info for performance debugging",
    ),
) -> None:
    """Validate CLAUDE.md files against reporails rules."""
    # Enable debug timing if requested
    if debug:
        set_debug_timing(True)

    # Show legend only mode
    if legend:
        legend_text = text_formatter.format_legend(ascii_mode=ascii)
        print(f"Severity Legend: {legend_text}")
        return

    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    # Resolve rules directory
    rules_path = Path(rules_dir).resolve() if rules_dir else None

    # Early check for missing instruction files
    instruction_files = get_all_instruction_files(target)
    if not instruction_files:
        console.print("No instruction files found.")
        console.print("Level: L1 (Absent)")
        console.print()
        console.print("[dim]Create a CLAUDE.md to get started.[/dim]")
        return

    # Get previous scan BEFORE running validation (for delta comparison)
    previous_scan = get_previous_scan(target)

    # Determine if we should show spinner (TTY + not explicitly JSON)
    show_spinner = sys.stdout.isatty() and format not in ("json", "brief", "compact")

    # Run validation with timing
    start_time = time.perf_counter()
    try:
        if show_spinner:
            with console.status("[bold]Scanning instruction files...[/bold]"):
                result = run_validation_sync(target, rules_dir=rules_path, use_cache=not refresh, agent=agent)
        else:
            result = run_validation_sync(target, rules_dir=rules_path, use_cache=not refresh, agent=agent)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from None
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # Compute delta from previous scan
    delta = ScanDelta.compute(
        current_score=result.score,
        current_level=result.level.value,
        current_violations=len(result.violations),
        previous=previous_scan,
    )

    # Auto-detect format if not specified
    output_format = format if format else _default_format()

    # Format output
    if output_format == "json":
        data = json_formatter.format_result(result, delta)
        data["elapsed_ms"] = round(elapsed_ms, 1)
        print(json.dumps(data, indent=2))
    elif output_format == "compact":
        output = text_formatter.format_compact(result, ascii_mode=ascii, delta=delta)
        print(output)
    elif output_format == "brief":
        data = json_formatter.format_result(result, delta)
        score = data.get("score", 0)
        level = data.get("level", "?")
        violations = len(data.get("violations", []))
        check_mark = "ok" if ascii else "✓"
        cross_mark = "x" if ascii else "✗"
        status = check_mark if violations == 0 else f"{cross_mark} {violations} violations"
        print(f"ails: {score:.1f}/10 ({level}) {status}")
    else:
        output = text_formatter.format_result(result, ascii_mode=ascii, quiet_semantic=quiet_semantic, delta=delta)
        console.print(output)
        console.print(f"\n[dim]Completed in {elapsed_ms:.0f}ms[/dim]")

    # Record scan in analytics (after display, so previous_scan was accurate)
    record_scan(
        target=target,
        score=result.score,
        level=result.level.value,
        violations_count=len(result.violations),
        rules_checked=result.rules_checked,
        elapsed_ms=elapsed_ms,
        instruction_files=result.rules_checked,  # Approximation
    )

    # Exit with error only in strict mode
    if strict and result.violations:
        raise typer.Exit(1)


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Rule ID (e.g., S1, C2)"),
    rules_dir: str = typer.Option(
        None,
        "--rules-dir",
        "-r",
        help="Directory containing rules (defaults to ~/.reporails/rules/)",
    ),
) -> None:
    """Show detailed information about a specific rule."""
    rules_path = Path(rules_dir).resolve() if rules_dir else None
    rules = load_rules(rules_path)

    rule_id_upper = rule_id.upper()

    if rule_id_upper not in rules:
        console.print(f"[red]Error:[/red] Unknown rule: {rule_id}")
        console.print(f"Available rules: {', '.join(sorted(rules.keys()))}")
        raise typer.Exit(1)

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
        parts = content.split("---", 2)
        if len(parts) >= 3:
            rule_data["description"] = parts[2].strip()[:500]

    output = text_formatter.format_rule(rule_id_upper, rule_data)
    console.print(output)


@app.command()
def map(
    path: str = typer.Argument(".", help="Project root to analyze"),
    output: str = typer.Option(
        "text",
        "--output",
        "-o",
        help="Output format: text, yaml, json",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        "-s",
        help="Save backbone.yml to .reporails/ directory",
    ),
) -> None:
    """Map project structure - find instruction files and components."""
    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    start_time = time.perf_counter()
    result = run_discovery(target)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    backbone_yaml = generate_backbone_yaml(result)

    if output == "yaml":
        console.print(backbone_yaml)
    elif output == "json":
        import yaml as yaml_lib
        data = yaml_lib.safe_load(backbone_yaml)
        console.print(json.dumps(data, indent=2))
    else:
        console.print(f"[bold]Discovery Results[/bold] - {target.name}")
        console.print("=" * 60)
        console.print()

        console.print(f"[bold]Agents detected:[/bold] {len(result.agents)}")
        for agent in result.agents:
            console.print(
                f"  - {agent.agent_type.name}: {len(agent.instruction_files)} instruction file(s)"
            )

        console.print()

        console.print(f"[bold]Components:[/bold] {len(result.components)}")
        for comp_id, comp in sorted(result.components.items()):
            indent = "  " * comp_id.count(".")
            files = len(comp.instruction_files)
            imports = len(comp.imports)
            console.print(f"  {indent}{comp_id}: {files} file(s), {imports} import(s)")

        console.print()

        if result.shared_files:
            console.print(f"[bold]Shared files:[/bold] {len(result.shared_files)}")
            for sf in result.shared_files[:10]:
                console.print(f"  - {sf}")
            if len(result.shared_files) > 10:
                console.print(f"  ... and {len(result.shared_files) - 10} more")

        console.print()
        console.print(f"[dim]Total instruction files: {result.total_instruction_files}[/dim]")
        console.print(f"[dim]Total references: {result.total_references}[/dim]")
        console.print(f"[dim]Completed in {elapsed_ms:.0f}ms[/dim]")

    if save:
        backbone_path = save_backbone(target, backbone_yaml)
        console.print()
        console.print(f"[green]Saved:[/green] {backbone_path}")


@app.command()
def sync(
    rules_dir: str = typer.Argument(
        "checks",
        help="Local rules directory to sync .md files to",
    ),
) -> None:
    """Sync rule definitions from framework repo (dev command)."""
    from reporails_cli.core.init import sync_rules_to_local

    target = Path(rules_dir).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Directory not found: {target}")
        raise typer.Exit(1)

    console.print(f"Syncing .md files from framework repo to {target}...")

    try:
        count = sync_rules_to_local(target)
        console.print(f"[green]Synced {count} rule definition(s)[/green]")
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from None


@app.command()
def update(
    version: str = typer.Option(
        None,
        "--version",
        "-v",
        help="Target version (e.g., v0.1.1). Defaults to latest.",
    ),
    force: bool = typer.Option(
        False,
        "--force",
        "-f",
        help="Force update even if already at target version",
    ),
    check: bool = typer.Option(
        False,
        "--check",
        "-c",
        help="Check for updates without installing",
    ),
) -> None:
    """Update rules framework to latest or specified version."""
    from reporails_cli.core.bootstrap import get_installed_version
    from reporails_cli.core.init import get_latest_version, update_rules

    if check:
        # Check-only mode
        current = get_installed_version()
        with console.status("[bold]Checking for updates...[/bold]"):
            latest = get_latest_version()

        if not latest:
            console.print("[yellow]Warning:[/yellow] Could not fetch latest version from GitHub.")
            raise typer.Exit(1)

        console.print(f"Installed: {current or 'not installed'}")
        console.print(f"Latest:    {latest}")

        if current == latest:
            console.print("[green]You are up to date.[/green]")
        else:
            console.print(f"\n[cyan]Run 'ails update' to update to {latest}[/cyan]")
        return

    # Perform update
    with console.status("[bold]Updating rules framework...[/bold]"):
        result = update_rules(version=version, force=force)

    if result.updated:
        console.print(f"[green]Updated:[/green] {result.previous_version or 'none'} → {result.new_version}")
        console.print(f"[dim]{result.rule_count} files installed[/dim]")
    else:
        console.print(result.message)


@app.command("version")
def show_version() -> None:
    """Show CLI and framework versions."""
    from reporails_cli import __version__ as cli_version
    from reporails_cli.core.bootstrap import get_installed_version
    from reporails_cli.core.init import OPENGREP_VERSION, RULES_VERSION

    installed = get_installed_version()

    console.print(f"CLI:       {cli_version}")
    console.print(f"Framework: {installed or 'not installed'} (bundled: {RULES_VERSION})")
    console.print(f"OpenGrep:  {OPENGREP_VERSION}")


def main() -> None:
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
