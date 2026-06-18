"""CLI commands — version, update, root --version/-V flag."""

from __future__ import annotations

import typer

from reporails_cli.interfaces.cli.helpers import app, console


def _print_version_and_exit(value: bool) -> None:
    if value:
        from reporails_cli import __version__ as cli_version

        print(cli_version)
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
    from reporails_cli import __version__ as cli_version
    from reporails_cli.core.install.self_update import detect_install_method

    console.print(f"CLI:     {cli_version}")
    console.print(f"Install: {detect_install_method().value}")


@app.command("update", rich_help_panel="Maintenance")
def update() -> None:
    """Update ails to the latest version."""
    import shutil
    import subprocess

    from reporails_cli import __version__ as current_version

    uv = shutil.which("uv")
    if not uv:
        console.print("[red]uv not found.[/red] Install it: https://docs.astral.sh/uv/")
        console.print("[dim]Then run: uv tool install reporails-cli[/dim]")
        raise typer.Exit(1)

    console.print(f"Current version: {current_version}")
    console.print("Upgrading...")

    result = subprocess.run(
        [uv, "tool", "upgrade", "reporails-cli"],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.returncode == 0:
        # Parse new version from output
        output = result.stdout.strip() or result.stderr.strip()
        if "already up to date" in output.lower() or "nothing to upgrade" in output.lower():
            console.print("[green]Already up to date.[/green]")
        else:
            console.print(f"[green]Updated.[/green] {output}")
    else:
        # Maybe not installed as a tool yet — install instead
        result2 = subprocess.run(
            [uv, "tool", "install", "reporails-cli", "--force"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result2.returncode == 0:
            console.print("[green]Installed latest version.[/green]")
        else:
            console.print(f"[red]Update failed:[/red] {result2.stderr.strip()}")
            raise typer.Exit(1)
