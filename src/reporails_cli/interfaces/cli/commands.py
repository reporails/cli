"""CLI commands — version, update, root --version/-V flag."""

from __future__ import annotations

import shutil

import typer

from reporails_cli.core.install.self_update import detect_install_method
from reporails_cli.core.platform.utils.version import installed_version
from reporails_cli.interfaces.cli.helpers import console, run_uv_tool
from reporails_cli.interfaces.cli.typer_app import app


def _print_version_and_exit(value: bool) -> None:
    if value:
        print(installed_version())
        raise typer.Exit()


@app.callback()
def _root(
    _version: bool = typer.Option(
        False,
        "--version",
        "-V",
        is_eager=True,
        callback=_print_version_and_exit,
        help="Show version and exit.",
    ),
) -> None:
    """Root callback — handles --version/-V short form."""


@app.command("version", rich_help_panel="Maintenance")
def show_version() -> None:
    """Show the version and install method."""
    console.print(f"CLI:     {installed_version()}")
    console.print(f"Install: {detect_install_method().value}")


def _update_engine() -> bool:
    """Upgrade the engine with uv; True when it is current or was installed."""
    uv = shutil.which("uv")
    if not uv:
        console.print("[red]uv not found.[/red] Install it: https://docs.astral.sh/uv/")
        console.print("[dim]Then run: uv tool install reporails-cli[/dim]")
        return False

    console.print(f"Current version: {installed_version()}")
    console.print("Upgrading...")

    result = run_uv_tool(uv, "upgrade", "reporails-cli")

    if result.returncode == 0:
        output = result.stdout.strip() or result.stderr.strip()
        if "already up to date" in output.lower() or "nothing to upgrade" in output.lower():
            console.print("[green]Already up to date.[/green]")
        else:
            console.print(f"[green]Updated.[/green] {output}")
        return True

    # Maybe not installed as a tool yet — install instead
    result2 = run_uv_tool(uv, "install", "reporails-cli", "--force")
    if result2.returncode == 0:
        console.print("[green]Installed latest version.[/green]")
        return True
    console.print(f"[red]Update failed:[/red] {result2.stderr.strip()}")
    return False


@app.command("update", rich_help_panel="Maintenance")
def update() -> None:
    """Update ails to the latest version and refresh the reporails plugin in your agents."""
    from reporails_cli.interfaces.cli.install import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        refresh_agent_plugins,
    )

    ok = _update_engine()
    console.print("\n[bold]Refreshing the reporails plugin...[/bold]")
    refresh_agent_plugins()
    if not ok:
        raise typer.Exit(1)
