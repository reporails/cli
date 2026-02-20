"""CLI command — install."""

from __future__ import annotations

from pathlib import Path

import typer

from reporails_cli.interfaces.cli.helpers import app, console


@app.command()
def install(
    path: str = typer.Argument(".", help="Project root"),
) -> None:
    """Install the reporails MCP server for detected agents."""
    from reporails_cli.core.mcp_install import detect_mcp_targets, write_mcp_config

    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    targets = detect_mcp_targets(target)

    if not targets:
        console.print("[yellow]No supported agents detected.[/yellow]")
        console.print("[dim]Create an instruction file to get started.[/dim]")
        raise typer.Exit(1)

    for agent_id, config_path in targets:
        write_mcp_config(config_path)
        try:
            rel = config_path.relative_to(target)
        except ValueError:
            rel = config_path
        console.print(f"  {agent_id}: {rel}")

    console.print("\n[green]Restart your editor to activate.[/green]")


@app.command(hidden=True)
def setup(
    path: str = typer.Argument(".", help="Project root"),
) -> None:
    """Alias for install (deprecated)."""
    install(path)
