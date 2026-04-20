"""CLI command — install."""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

import typer

from reporails_cli.interfaces.cli.helpers import app, console

logger = logging.getLogger(__name__)


def _install_to_path() -> bool:
    """Install ails to PATH via uv tool install. Returns True on success."""
    # Already on PATH as a real install (not uvx one-shot)?
    ails_path = shutil.which("ails")
    if ails_path and "/.cache/uv/" not in (ails_path or ""):
        console.print(f"  [dim]ails already on PATH: {ails_path}[/dim]")
        return True

    uv = shutil.which("uv")
    if not uv:
        console.print("  [yellow]uv not found — skipping PATH install.[/yellow]")
        console.print("  [dim]Install uv (https://docs.astral.sh/uv/) then run: uv tool install reporails-cli[/dim]")
        return False

    console.print("  Installing ails to PATH...")
    try:
        result = subprocess.run(
            [uv, "tool", "install", "reporails-cli", "--force"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            console.print("  [green]ails installed to PATH[/green]")
            return True
        logger.warning("uv tool install failed: %s", result.stderr.strip())
        console.print(f"  [yellow]PATH install failed: {result.stderr.strip()}[/yellow]")
        console.print("  [dim]You can still use: npx @reporails/cli check[/dim]")
        return False
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("uv tool install error: %s", exc)
        console.print("  [yellow]PATH install failed — use npx @reporails/cli instead[/yellow]")
        return False


@app.command(rich_help_panel="Commands")
def install(
    path: str = typer.Argument(".", help="Project root"),
) -> None:
    """Install the reporails MCP server and ails command."""
    from reporails_cli.core.mcp_install import detect_mcp_targets, write_mcp_config

    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    # 1. Install ails to PATH
    console.print("[bold]Installing CLI...[/bold]")
    _install_to_path()

    # 2. Install MCP server for detected agents
    console.print("\n[bold]Configuring MCP server...[/bold]")
    targets = detect_mcp_targets(target)

    if not targets:
        console.print("  [yellow]No supported agents detected.[/yellow]")
        console.print("  [dim]Create an instruction file to get started.[/dim]")
    else:
        for agent_id, config_path in targets:
            write_mcp_config(config_path)
            try:
                rel = config_path.relative_to(target)
            except ValueError:
                rel = config_path
            console.print(f"  {agent_id}: {rel}")

    console.print("\n[green]Done.[/green] Restart your editor to activate MCP.")
    console.print("[dim]Run 'ails check' to validate your instruction files.[/dim]")


@app.command(hidden=True)
def setup(
    path: str = typer.Argument(".", help="Project root"),
) -> None:
    """Alias for install (deprecated)."""
    install(path)
