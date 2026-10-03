"""CLI subcommand: ails daemon start|stop|status."""

from __future__ import annotations

import typer

from reporails_cli.interfaces.cli.helpers import console

daemon_app = typer.Typer(
    name="daemon",
    help="Manage the background analysis daemon.",
    context_settings={"help_option_names": ["-h", "--help"]},
)


@daemon_app.command()
def start() -> None:
    """Start the analysis daemon (keeps models loaded in background)."""
    from reporails_cli.core.mapper.daemon import is_daemon_running, retire_daemon, start_daemon
    from reporails_cli.core.mapper.daemon_client import ping, runs_newer_code, runs_older_code, serves_this_code

    if is_daemon_running():
        pong = ping()
        if pong is None or serves_this_code(pong):
            console.print("[dim]Daemon already running.[/dim]")
            return
        if not runs_older_code(pong):
            whose = "A newer version's" if runs_newer_code(pong) else "An unrecognized version's"
            console.print(f"[dim]{whose} daemon is running; this version checks without it.[/dim]")
            return
        if not retire_daemon(pong.get("pid")):
            console.print("[yellow]A daemon from an older version of ails is busy; try again when it is idle.[/yellow]")
            raise typer.Exit(1)
        console.print("Stopped the daemon left by an older version of ails.")

    console.print("Starting analysis daemon...")
    try:
        pid = start_daemon()
    except OSError as exc:
        console.print(f"[red]{exc}[/red]")
        console.print("[dim]Use 'ails check' directly — it falls back to in-process mapping.[/dim]")
        raise typer.Exit(1) from None
    if is_daemon_running():
        console.print(f"[green]Daemon started[/green] (PID {pid})")
    else:
        console.print("[red]Failed to start daemon.[/red]")
        raise typer.Exit(1)


@daemon_app.command()
def stop() -> None:
    """Stop the analysis daemon."""
    from reporails_cli.core.mapper.daemon import stop_daemon

    if stop_daemon():
        console.print("[green]Daemon stopped.[/green]")
    else:
        console.print("[dim]Daemon not running.[/dim]")


@daemon_app.command()
def status() -> None:
    """Show daemon status."""
    from reporails_cli.core.mapper.daemon import is_daemon_running
    from reporails_cli.core.mapper.daemon_client import ping, runs_newer_code, runs_older_code, serves_this_code

    if not is_daemon_running():
        console.print("Daemon: [dim]not running[/dim]")
        return

    resp = ping()
    if not (resp and resp.get("ok")):
        console.print("Daemon: [yellow]PID file exists but unresponsive[/yellow]")
        return
    code = resp.get("code")
    details = [f"PID {resp.get('pid', '?')}"]
    if isinstance(code, str):
        details.append(f"version {code.rpartition('+map')[0] or code}")
    if runs_older_code(resp):
        details.append("left by an older version of ails; the next check replaces it")
    elif runs_newer_code(resp):
        details.append("a newer version's daemon; this version checks without it")
    elif not serves_this_code(resp):
        details.append("an unrecognized version's daemon; this version checks without it")
    console.print(f"Daemon: [green]running[/green] ({', '.join(details)})")
