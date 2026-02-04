"""Typer CLI for reporails - validate and score AI instruction files."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import typer
from rich.console import Console

from reporails_cli.core.agents import detect_agents, get_all_instruction_files
from reporails_cli.core.cache import (
    ProjectCache,
    cache_judgments,
    content_hash,
    get_previous_scan,
    record_scan,
)
from reporails_cli.core.discover import generate_backbone_yaml, save_backbone
from reporails_cli.core.engine import run_validation_sync
from reporails_cli.core.models import ScanDelta
from reporails_cli.core.opengrep import set_debug_timing
from reporails_cli.core.registry import load_rules
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters import text as text_formatter

app = typer.Typer(
    name="ails",
    help="Validate and score CLAUDE.md files - what ails your repo?",
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
    with_recommended: bool = typer.Option(
        False,
        "--with-recommended",
        help="Include recommended rules package (auto-downloads if needed)",
    ),
    experimental: bool = typer.Option(
        False,
        "--experimental",
        help="Include experimental rules (methodology-backed, lower confidence)",
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

    # Handle --with-recommended: auto-download and inject into project packages
    if with_recommended:
        from reporails_cli.core.init import download_recommended, is_recommended_installed

        if not is_recommended_installed():
            try:
                if sys.stdout.isatty() and format not in ("json", "brief", "compact"):
                    with console.status("[bold]Downloading recommended rules...[/bold]"):
                        download_recommended()
                else:
                    download_recommended()
            except Exception as e:
                console.print(f"[yellow]Warning:[/yellow] Could not download recommended rules: {e}")

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

    # Build extra packages list from flags
    extra_packages = ["recommended"] if with_recommended else None

    # Run validation with timing
    start_time = time.perf_counter()
    try:
        if show_spinner:
            with console.status("[bold]Scanning instruction files...[/bold]"):
                result = run_validation_sync(
                    target, rules_dir=rules_path, use_cache=not refresh,
                    agent=agent, include_experimental=experimental,
                    extra_packages=extra_packages,
                )
        else:
            result = run_validation_sync(
                target, rules_dir=rules_path, use_cache=not refresh,
                agent=agent, include_experimental=experimental,
                extra_packages=extra_packages,
            )
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

    # Update check (non-blocking, swallows errors)
    if output_format not in ("json", "compact", "brief"):
        from reporails_cli.core.bootstrap import get_global_config
        from reporails_cli.core.update_check import check_for_updates, format_update_message

        config = get_global_config()
        if config.auto_update_check:
            notification = check_for_updates()
            if notification:
                console.print(format_update_message(notification))

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
    """Map project structure - detect agents and project layout."""
    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    start_time = time.perf_counter()
    agents = detect_agents(target)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    backbone_yaml = generate_backbone_yaml(target, agents)

    if output == "yaml":
        console.print(backbone_yaml)
    elif output == "json":
        import yaml as yaml_lib
        data = yaml_lib.safe_load(backbone_yaml)
        console.print(json.dumps(data, indent=2))
    else:
        console.print(f"[bold]Project Map[/bold] - {target.name}")
        console.print("=" * 50)
        console.print()

        # Agents
        for agent in agents:
            root_files = [f for f in agent.instruction_files if f.parent == target]
            main_file = str(root_files[0].relative_to(target)) if root_files else "?"
            console.print(f"[bold]{agent.agent_type.name}[/bold]")
            console.print(f"  main: {main_file}")
            for label, dir_path in agent.detected_directories.items():
                console.print(f"  {label}: {dir_path}")
            if agent.config_files:
                console.print(f"  config: {agent.config_files[0].relative_to(target)}")
            console.print()

        # Structure
        from reporails_cli.core.discover import detect_project_structure

        structure = detect_project_structure(target)
        if structure:
            console.print("[bold]Structure:[/bold]")
            for key, value in structure.items():
                if isinstance(value, list):
                    console.print(f"  {key}: {', '.join(value)}")
                else:
                    console.print(f"  {key}: {value}")
            console.print()

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
    recommended: bool = typer.Option(
        False,
        "--recommended",
        help="Re-fetch recommended rules package",
    ),
    cli: bool = typer.Option(
        False,
        "--cli",
        help="Upgrade the CLI package itself (not just rules)",
    ),
    check: bool = typer.Option(
        False,
        "--check",
        "-c",
        help="Check for updates without installing",
    ),
) -> None:
    """Update rules framework (or CLI with --cli) to latest or specified version."""
    from reporails_cli.core.bootstrap import get_installed_version
    from reporails_cli.core.init import get_latest_version, update_rules

    # Handle --recommended: re-fetch recommended package
    if recommended:
        from reporails_cli.core.init import download_recommended

        try:
            with console.status("[bold]Downloading recommended rules...[/bold]"):
                pkg_path = download_recommended()
            console.print(f"[green]Updated:[/green] recommended rules at {pkg_path}")
        except Exception as e:
            console.print(f"[red]Error:[/red] Could not download recommended rules: {e}")
            raise typer.Exit(1) from None
        return

    if cli:
        from reporails_cli.core.self_update import upgrade_cli

        with console.status("[bold]Upgrading CLI...[/bold]"):
            cli_result = upgrade_cli(target_version=version)

        if cli_result.updated:
            console.print(f"[green]CLI upgraded:[/green] {cli_result.previous_version} → {cli_result.new_version}")
            console.print(f"[dim]Method: {cli_result.method.value}[/dim]")
        else:
            console.print(cli_result.message)
        return

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


@app.command()
def dismiss(
    rule_id: str = typer.Argument(..., help="Rule ID to dismiss (e.g., C6, M4)"),
    file: str = typer.Argument(None, help="Specific file to dismiss for (default: all instruction files)"),
    path: str = typer.Option(".", help="Project root"),
) -> None:
    """Dismiss a semantic rule finding (mark as pass/false-positive).

    Writes a pass verdict to the judgment cache for the given rule+file.
    Uses current content hash, so the dismissal auto-invalidates when the file changes.
    """
    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    rule_id_upper = rule_id.upper()
    cache = ProjectCache(target)

    if file:
        # Dismiss for a specific file
        files = [Path(file)]
    else:
        # Dismiss for all instruction files
        files = [f.relative_to(target) for f in get_all_instruction_files(target)]

    if not files:
        console.print("[yellow]No instruction files found.[/yellow]")
        raise typer.Exit(1)

    dismissed = 0
    for f in files:
        full_path = target / f if not f.is_absolute() else f
        if not full_path.exists():
            console.print(f"[yellow]Skipping:[/yellow] {f} (not found)")
            continue

        file_path = str(f)
        try:
            file_hash = content_hash(full_path)
        except OSError:
            console.print(f"[yellow]Skipping:[/yellow] {f} (could not read)")
            continue

        existing = cache.get_cached_judgment(file_path, file_hash) or {}
        existing[rule_id_upper] = {
            "verdict": "pass",
            "reason": "Dismissed via ails dismiss",
        }
        cache.set_cached_judgment(file_path, file_hash, existing)
        dismissed += 1

    console.print(f"[green]Dismissed[/green] {rule_id_upper} for {dismissed} file(s)")


@app.command()
def judge(
    path: str = typer.Argument(".", help="Project root"),
    verdicts: list[str] = typer.Argument(None, help="Verdict strings: rule_id:location:verdict:reason"),  # noqa: B008
) -> None:
    """Cache semantic rule verdicts (batch).

    Accepts one or more verdict strings in rule_id:location:verdict:reason format.

    Example:
        ails judge . "C6:CLAUDE.md:pass:Criteria met" "M2:.claude/rules/foo.md:fail:Contradictions found"
    """
    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    if not verdicts:
        console.print("[yellow]No verdicts provided.[/yellow]")
        raise typer.Exit(1)

    recorded = cache_judgments(target, verdicts)
    print(json.dumps({"recorded": recorded}))


@app.command("version")
def show_version() -> None:
    """Show CLI and framework versions."""
    from reporails_cli import __version__ as cli_version
    from reporails_cli.core.bootstrap import get_installed_version
    from reporails_cli.core.init import OPENGREP_VERSION, RULES_VERSION

    installed = get_installed_version()

    from reporails_cli.core.self_update import detect_install_method

    console.print(f"CLI:       {cli_version}")
    console.print(f"Framework: {installed or 'not installed'} (bundled: {RULES_VERSION})")
    console.print(f"OpenGrep:  {OPENGREP_VERSION}")
    console.print(f"Install:   {detect_install_method().value}")


def main() -> None:
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
