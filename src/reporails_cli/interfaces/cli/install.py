"""CLI command — install."""

from __future__ import annotations

import logging
import shutil
import subprocess

from reporails_cli.interfaces.cli.helpers import app, console

logger = logging.getLogger(__name__)

_PLUGIN_REPO = "reporails/plugin"
_PLUGIN_CLONE = "git clone https://github.com/reporails/plugin"

# The reporails plugin is a portable Agent Plugins package that carries the
# `ails` skill and the `reporails` MCP server. Each agent installs it natively;
# installing it registers the MCP server and loads the skill in one step. The
# CLI's only job is to ensure the engine binary is present and point the operator
# at the per-agent install.
_PLUGIN_INSTALL: list[tuple[str, str]] = [
    ("Claude Code", f"/plugin marketplace add {_PLUGIN_REPO}  then  /plugin install reporails@reporails"),
    ("Codex", f"codex plugin marketplace add {_PLUGIN_REPO}  then  codex plugin add reporails@reporails"),
    ("Cursor", "copy plugin/plugins/reporails/ into ~/.cursor/plugins/local/reporails/, then restart Cursor"),
    ("GitHub Copilot", "VS Code -> 'Install Plugin From Source' -> the plugin/plugins/reporails/ folder"),
    ("Antigravity", "agy plugin install plugin/plugins/reporails"),
]


def _install_to_path() -> bool:
    """Install ails to PATH via uv tool install. Returns True on success."""
    # Already on PATH as a real install (not uvx one-shot)?
    ails_path = shutil.which("ails")
    if ails_path and "/.cache/uv/" not in (ails_path or ""):
        console.print(f"  [dim]ails already on PATH: {ails_path}[/dim]")
        return True

    uv = shutil.which("uv")
    if not uv:
        console.print("  [yellow]uv not found — skipping PATH install.[/yellow]")
        console.print("  [dim]Install uv (https://docs.astral.sh/uv/) then run: uv tool install reporails-cli[/dim]")
        return False

    from reporails_cli import __version__

    # A floor (>=), not an exact pin (==): `uv tool upgrade` keeps an `==` pin
    # forever, so a floor is what lets a later `ails update` / `uv tool
    # upgrade` move the engine past this version.
    spec = f"reporails-cli>={__version__}"
    console.print("  Installing ails to PATH...")
    try:
        result = subprocess.run(
            [uv, "tool", "install", spec, "--force"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            console.print("  [green]ails installed to PATH[/green]")
            return True
        logger.warning("uv tool install failed: %s", result.stderr.strip())
        console.print(f"  [yellow]PATH install failed: {result.stderr.strip()}[/yellow]")
        console.print("  [dim]You can still use: npx @reporails/cli check[/dim]")
        return False
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("uv tool install error: %s", exc)
        console.print("  [yellow]PATH install failed — use npx @reporails/cli instead[/yellow]")
        return False


@app.command(rich_help_panel="Maintenance")
def install() -> None:
    """Put the reporails engine on PATH, then print how to connect it to your agent."""
    # 1. Ensure the ails CLI + reporails-mcp engine are on PATH.
    console.print("[bold]Installing the reporails engine (CLI + MCP server)...[/bold]")
    _install_to_path()

    # 2. Point the operator at the per-agent plugin install. The plugin bundles
    #    the MCP server and the `ails` skill, so installing it registers both.
    console.print("\n[bold]Add the reporails plugin to your agent:[/bold]")
    console.print(
        "[dim]The plugin carries the MCP server and the `ails` skill — installing it registers both. "
        "It needs uv on the machine; its first start downloads the CLI and the model files.[/dim]"
    )
    for agent, command in _PLUGIN_INSTALL:
        console.print(f"  [cyan]{agent}[/cyan]: {command}")
    console.print(f"[dim]Cursor, GitHub Copilot and Antigravity install from a local copy: {_PLUGIN_CLONE}[/dim]")
    console.print(
        "\n[green]Done.[/green] After the plugin installs, ask your agent to check and fix your "
        "instruction files, or run 'ails check' in the terminal."
    )
