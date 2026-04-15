"""CLI subcommand: ails daemon start|stop|status."""

from __future__ import annotations

from pathlib import Path

import typer

from reporails_cli.interfaces.cli.helpers import console

daemon_app = typer.Typer(name="daemon", help="Manage the mapper daemon.")


@daemon_app.command()
def start(
    path: str = typer.Argument(".", help="Project root"),
) -> None:
    """Start the mapper daemon (keeps models loaded in background)."""
    from reporails_cli.core.mapper.daemon import is_daemon_running, start_daemon

    cache_dir = Path(path).resolve() / ".ails" / ".cache"

    if is_daemon_running(cache_dir):
        console.print("[dim]Daemon already running.[/dim]")
        return

    console.print("Starting mapper daemon...")
    pid = start_daemon(cache_dir)
    if is_daemon_running(cache_dir):
        console.print(f"[green]Daemon started[/green] (PID {pid})")
    else:
        console.print("[red]Failed to start daemon.[/red]")
        raise typer.Exit(1)


@daemon_app.command()
def stop(
    path: str = typer.Argument(".", help="Project root"),
) -> None:
    """Stop the mapper daemon."""
    from reporails_cli.core.mapper.daemon import stop_daemon

    cache_dir = Path(path).resolve() / ".ails" / ".cache"
    if stop_daemon(cache_dir):
        console.print("[green]Daemon stopped.[/green]")
    else:
        console.print("[dim]Daemon not running.[/dim]")


@daemon_app.command()
def status(
    path: str = typer.Argument(".", help="Project root"),
) -> None:
    """Show daemon status."""
    from reporails_cli.core.mapper.daemon import is_daemon_running
    from reporails_cli.core.mapper.daemon_client import ping

    cache_dir = Path(path).resolve() / ".ails" / ".cache"

    if not is_daemon_running(cache_dir):
        console.print("Daemon: [dim]not running[/dim]")
        return

    resp = ping(cache_dir)
    if resp and resp.get("ok"):
        console.print(f"Daemon: [green]running[/green] (PID {resp.get('pid', '?')})")
    else:
        console.print("Daemon: [yellow]PID file exists but unresponsive[/yellow]")
