"""CLI command: ails events — the event records of one agent session."""

from __future__ import annotations

import typer

from reporails_cli.interfaces.cli.output_formats import EVENTS_FORMATS
from reporails_cli.interfaces.cli.typer_app import app


@app.command("events", hidden=True)
def events_command(
    session: str = typer.Option(..., "--session", "-s", help="Session id"),
    after: int = typer.Option(0, "--after", min=0, help="Read from this byte offset; pass the printed `next` to continue"),
    output_format: str = typer.Option("json", "--format", "-f", help="Output format (json)"),
) -> None:
    """Print, as one JSON object, the records of SESSION appended after byte offset AFTER, in order."""
    from reporails_cli.core.eventbus.query import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        read_events,
    )
    from reporails_cli.core.platform.utils.utils import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        compact_json,
    )

    if output_format not in EVENTS_FORMATS:
        typer.echo(f"Error: --format must be one of: {', '.join(EVENTS_FORMATS)}", err=True)
        raise typer.Exit(2)
    records, next_offset = read_events(session, after)
    typer.echo(compact_json({"session": session, "next": next_offset, "records": [r.to_json() for r in records]}))
