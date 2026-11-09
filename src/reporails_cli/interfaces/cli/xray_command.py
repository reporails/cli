"""CLI command: ails xray — a local page showing one Claude Code session's context window."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import typer

from reporails_cli.interfaces.cli.typer_app import app

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.xray import SessionPick


def _show_in_background(root: Path, session_id: str, picked: SessionPick, *, open_page: bool) -> None:
    """Start or reuse the project's page, print the address of `session_id` on it and return."""
    from reporails_cli.core.platform.adapters.programs import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        open_in_browser,
    )
    from reporails_cli.core.platform.contract.errors import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        XrayPageError,
    )
    from reporails_cli.core.xray.pages import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        page_url,
        start_page,
    )
    from reporails_cli.interfaces.cli.xray_line import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        xray_line,
    )

    try:
        page, _reused = start_page(root, session_id)
    except XrayPageError as err:
        typer.echo(f"Error: {err}", err=True)
        raise typer.Exit(1) from err
    url = page_url(page, session_id, picked)
    typer.echo(xray_line(session_id, url, picked))
    if open_page:
        open_in_browser(url)


@app.command("xray")
def xray_command(
    session: str | None = typer.Option(None, "--session", "-s", help="Session id (default: the newest session)"),
    current: bool = typer.Option(
        False, "--current", help="The session of the agent that runs this command (the newest when it does not say)"
    ),
    background: bool = typer.Option(
        False, "--background", help="Start the page detached, or reuse the running one, print its address and return"
    ),
    no_open: bool = typer.Option(False, "--no-open", help="Print the address without opening a browser"),
    launch: str | None = typer.Option(None, "--launch", hidden=True, help="The id the page records for its start"),
) -> None:
    """Open a local page showing how a Claude Code session handed work between agents: each agent on a timeline,
    what it was handed, what came back, and which instruction files, MCP servers and hooks reached its context.
    Serves on 127.0.0.1 until Ctrl-C, or with --background starts the page and returns."""
    from reporails_cli.core.xray.sessions import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        pick_session,
    )

    here = Path.cwd().resolve()
    if session is not None and current:
        typer.echo("Error: --session and --current name the session twice; use one of them", err=True)
        raise typer.Exit(2)
    picked = pick_session(here, session, current=current)
    if picked is None:
        missing = "no Claude Code session found" if session is None else f"no session {session}"
        typer.echo(
            f"Error: {missing} for {here}; run it in the folder Claude Code was started in",
            err=True,
        )
        raise typer.Exit(2)
    if background:
        _show_in_background(picked.root, picked.transcript.stem, picked.picked, open_page=not no_open)
        return
    from reporails_cli.interfaces.cli.xray_server import (  # pylint: disable=import-outside-toplevel  # startup: the web server loads when the command runs
        serve,
    )

    serve(picked.root, picked.transcript, picked.picked, open_page=not no_open, launch=launch)
