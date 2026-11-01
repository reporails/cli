"""CLI command: ails xray — a local page showing one Claude Code session's context window."""

from __future__ import annotations

from pathlib import Path

import typer

from reporails_cli.interfaces.cli.typer_app import app


@app.command("xray")
def xray_command(
    session: str | None = typer.Option(None, "--session", "-s", help="Session id (default: the newest session)"),
    no_open: bool = typer.Option(False, "--no-open", help="Print the address without opening a browser"),
) -> None:
    """Open a local page showing how a Claude Code session handed work between agents: each agent on a timeline,
    what it was handed, what came back, and which instruction files, MCP servers and hooks reached its context.
    Serves on 127.0.0.1 until Ctrl-C."""
    from reporails_cli.core.eventbus.transcript import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        newest_session,
        session_transcript,
    )
    from reporails_cli.interfaces.cli.xray_server import (  # pylint: disable=import-outside-toplevel  # startup: the web server loads when the command runs
        serve,
    )

    root = Path.cwd().resolve()
    transcript = session_transcript(root, session) if session else newest_session(root)
    if transcript is None or not transcript.is_file():
        typer.echo(f"Error: no Claude Code session found for {root}", err=True)
        raise typer.Exit(2)
    serve(root, transcript, open_page=not no_open)
