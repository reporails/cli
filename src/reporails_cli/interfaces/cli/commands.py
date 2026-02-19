"""CLI commands — map, sync, update, dismiss, judge, version."""

from __future__ import annotations

import json
import time
from pathlib import Path

import typer

from reporails_cli.core.agents import detect_agents, get_all_instruction_files
from reporails_cli.core.cache import ProjectCache, cache_judgments, content_hash
from reporails_cli.core.discover import generate_backbone_yaml, save_backbone
from reporails_cli.interfaces.cli.helpers import _handle_update_check, app, console


@app.command()
def map(  # pylint: disable=too-many-locals
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
    """Detect agents and project layout."""
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
        console.print(f"[red]Error:[/red] Failed to sync rules: {e}")
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
        help="Update recommended rules only (skips framework)",
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
    """Update rules framework (or CLI with --cli)."""
    from reporails_cli.core.init import update_rules

    # Handle --recommended: re-fetch recommended package only
    if recommended:
        from reporails_cli.core.init import update_recommended

        with console.status("[bold]Updating recommended rules...[/bold]"):
            rec_result = update_recommended(force=force)

        if rec_result.updated:
            prev = rec_result.previous_version or "none"
            console.print(f"[green]Updated:[/green] recommended {prev} -> {rec_result.new_version}")
        else:
            console.print(rec_result.message)
        return

    if cli:
        from reporails_cli.core.self_update import upgrade_cli

        with console.status("[bold]Upgrading CLI...[/bold]"):
            cli_result = upgrade_cli(target_version=version)

        if cli_result.updated:
            console.print(f"[green]CLI upgraded:[/green] {cli_result.previous_version} -> {cli_result.new_version}")
            console.print(f"[dim]Method: {cli_result.method.value}[/dim]")
            console.print("[dim]Run 'ails setup' to update your MCP server config.[/dim]")
        else:
            console.print(cli_result.message)
        return

    if check:
        _handle_update_check(console)
        return

    # Perform update (rules + recommended)
    from reporails_cli.core.init import update_recommended as _update_rec

    with console.status("[bold]Updating rules framework...[/bold]"):
        result = update_rules(version=version, force=force)

    if result.updated:
        console.print(f"[green]Updated:[/green] framework {result.previous_version or 'none'} -> {result.new_version}")
        console.print(f"[dim]{result.rule_count} files installed[/dim]")
    else:
        console.print(result.message)

    # Also update recommended (unless --version was specified, which targets rules only)
    if not version:
        with console.status("[bold]Updating recommended rules...[/bold]"):
            rec_result = _update_rec(force=force)

        if rec_result.updated:
            prev = rec_result.previous_version or "none"
            console.print(f"[green]Updated:[/green] recommended {prev} -> {rec_result.new_version}")
        elif rec_result.message and rec_result.new_version != "unknown":
            console.print(f"[dim]{rec_result.message}[/dim]")


@app.command()
def dismiss(
    rule_id: str = typer.Argument(..., help="Rule ID to dismiss (e.g., C6, M4)"),
    file: str = typer.Argument(None, help="Specific file to dismiss for (default: all instruction files)"),
    path: str = typer.Option(".", help="Project root"),
) -> None:
    """Dismiss a semantic rule finding (mark as pass in judgment cache)."""
    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    rule_id_upper = rule_id.upper()

    from reporails_cli.core.engine import _find_project_root

    project_root = _find_project_root(target)
    cache = ProjectCache(project_root)

    files = [Path(file)] if file else [f.relative_to(target) for f in get_all_instruction_files(target)]

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
    verdicts: list[str] = typer.Argument(  # noqa: B008
        None,
        help="Verdict strings: RULE:FILE:verdict:reason (e.g., 'C6:CLAUDE.md:pass:Criteria met')",
    ),
) -> None:
    """Cache semantic rule verdicts (batch, rule_id:location:verdict:reason format)."""
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
    from reporails_cli.core.bootstrap import (
        get_installed_recommended_version,
        get_installed_version,
    )
    from reporails_cli.core.init import RECOMMENDED_VERSION, RULES_VERSION

    installed = get_installed_version()
    installed_rec = get_installed_recommended_version()

    from reporails_cli.core.self_update import detect_install_method

    console.print(f"CLI:         {cli_version}")
    console.print(f"Framework:   {installed or 'not installed'} (bundled: {RULES_VERSION})")
    console.print(f"Recommended: {installed_rec or 'not installed'} (bundled: {RECOMMENDED_VERSION})")
    console.print(f"Install:     {detect_install_method().value}")
