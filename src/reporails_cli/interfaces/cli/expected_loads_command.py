"""CLI command: ails expected-loads — the instruction files an agent loads for a session in a folder."""

from __future__ import annotations

from pathlib import Path

import typer

from reporails_cli.interfaces.cli.typer_app import app


@app.command("expected-loads", hidden=True)
def expected_loads_command(
    path: str = typer.Argument(".", help="Project folder"),  # typer declares the default
    agent: str = typer.Option("claude", "--agent", "-a", help="Agent (claude)"),
) -> None:
    """Print, as one JSON object, the files the agent loads for a session in PATH and the AGENTS.md files it skips."""
    from reporails_cli.core.pipeline.expected_loads import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        AGENT,
        expected_loads,
    )
    from reporails_cli.core.platform.utils.utils import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        compact_json,
    )

    if agent != AGENT:
        typer.echo(f"Error: only --agent {AGENT} is supported", err=True)
        raise typer.Exit(2)
    typer.echo(compact_json(expected_loads(Path(path).resolve())))
