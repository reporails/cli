"""CLI subcommand: ails daemon start|stop|status."""

from __future__ import annotations

import typer

from reporails_cli.interfaces.cli.helpers import console

daemon_app = typer.Typer(name="daemon", help="Manage the global mapper daemon.")


@daemon_app.command()
def start(
    path: str | None = typer.Argument(None, help="[Deprecated] Ignored — daemon is global.", hidden=True),
) -> None:
    """Start the mapper daemon (keeps models loaded in background)."""
    from reporails_cli.core.mapper.daemon import is_daemon_running, start_daemon

    if path is not None and path != ".":
        console.print("[yellow]Note: path argument is deprecated. The daemon is now global.[/yellow]")

    if is_daemon_running():
        console.print("[dim]Daemon already running.[/dim]")
        return

    console.print("Starting mapper daemon...")
    pid = start_daemon()
    if is_daemon_running():
        console.print(f"[green]Daemon started[/green] (PID {pid})")
    else:
        console.print("[red]Failed to start daemon.[/red]")
        raise typer.Exit(1)


@daemon_app.command()
def stop(
    path: str | None = typer.Argument(None, help="[Deprecated] Ignored.", hidden=True),
) -> None:
    """Stop the mapper daemon."""
    from reporails_cli.core.mapper.daemon import stop_daemon

    if path is not None and path != ".":
        console.print("[yellow]Note: path argument is deprecated. The daemon is now global.[/yellow]")

    if stop_daemon():
        console.print("[green]Daemon stopped.[/green]")
    else:
        console.print("[dim]Daemon not running.[/dim]")


@daemon_app.command()
def status(
    path: str | None = typer.Argument(None, help="[Deprecated] Ignored.", hidden=True),
) -> None:
    """Show daemon status."""
    from reporails_cli.core.mapper.daemon import is_daemon_running
    from reporails_cli.core.mapper.daemon_client import ping

    if path is not None and path != ".":
        console.print("[yellow]Note: path argument is deprecated. The daemon is now global.[/yellow]")

    if not is_daemon_running():
        console.print("Daemon: [dim]not running[/dim]")
        return

    resp = ping()
    if resp and resp.get("ok"):
        console.print(f"Daemon: [green]running[/green] (PID {resp.get('pid', '?')})")
    else:
        console.print("Daemon: [yellow]PID file exists but unresponsive[/yellow]")
