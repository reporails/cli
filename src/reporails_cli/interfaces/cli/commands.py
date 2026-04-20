"""CLI commands — map, version."""

from __future__ import annotations

import json
import time
from pathlib import Path

import typer

from reporails_cli.core.agents import detect_agents
from reporails_cli.core.discover import generate_backbone_yaml, save_backbone
from reporails_cli.interfaces.cli.helpers import app, console


@app.command(hidden=True)
def map(
    path: str = typer.Argument(".", help="Project root to analyze"),
    output: str = typer.Option(
        "text",
        "--output",
        "-o",
        help="Output format: text, yaml, json",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        "-s",
        help="Save backbone.yml to .ails/ directory",
    ),
) -> None:
    """Detect agents and project layout."""
    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    start_time = time.perf_counter()
    agents = detect_agents(target)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    backbone_yaml = generate_backbone_yaml(target, agents)

    if output == "yaml":
        print(backbone_yaml, end="")
    elif output == "json":
        import yaml as yaml_lib

        data = yaml_lib.safe_load(backbone_yaml)
        print(json.dumps(data, indent=2))
    else:
        from reporails_cli.interfaces.cli.helpers import _print_map_text

        _print_map_text(target, agents, elapsed_ms)

    if save:
        backbone_path = save_backbone(target, backbone_yaml)
        console.print()
        console.print(f"[green]Saved:[/green] {backbone_path}")


@app.command("version", rich_help_panel="Configuration")
def show_version() -> None:
    """Show CLI version and install method."""
    from reporails_cli import __version__ as cli_version
    from reporails_cli.core.self_update import detect_install_method

    console.print(f"CLI:     {cli_version}")
    console.print(f"Install: {detect_install_method().value}")


@app.command("update", rich_help_panel="Commands")
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
