"""CLI command — install."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess

import typer

from reporails_cli.interfaces.cli.helpers import app, console

logger = logging.getLogger(__name__)

_PLUGIN_REPO = "reporails/plugin"
_PLUGIN_CLONE = "git clone https://github.com/reporails/plugin"
_PLUGIN_SOURCE_ENV = "AILS_PLUGIN_SOURCE"
_PLUGIN_ID = "reporails@reporails"
_MARKETPLACE = "reporails"
_STEP_TIMEOUT = 120
_WARM_TIMEOUT = 300

# The reporails plugin is a portable Agent Plugins package that carries the
# `ails` skill and the `reporails` MCP server. Claude Code and Codex install it
# through their own plugin commands, which `ails install` runs; the other agents
# install it by hand, from the steps below.
_PLUGIN_INSTALL: list[tuple[str, str]] = [
    ("Claude Code", f"/plugin marketplace add {_PLUGIN_REPO}  then  /plugin install {_PLUGIN_ID}"),
    ("Codex", f"codex plugin marketplace add {_PLUGIN_REPO}  then  codex plugin add {_PLUGIN_ID}"),
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


def _plugin_source() -> str:
    """Marketplace source for the plugin: `AILS_PLUGIN_SOURCE`, else the public repo."""
    return os.environ.get(_PLUGIN_SOURCE_ENV, "").strip() or _PLUGIN_REPO


def _engine_spec(version: str) -> str:
    """The engine pin the plugin starts with: this release line, e.g. `>=0.6.0,<0.7`."""
    match = re.match(r"(\d+)\.(\d+)", version)
    if not match:
        return "reporails-cli"
    major, minor = int(match.group(1)), int(match.group(2))
    return f"reporails-cli>={major}.{minor}.0,<{major}.{minor + 1}"


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Run one command; None on OSError or timeout."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=_STEP_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("%s failed: %s", cmd[0], exc)
        return None


def _lists(cmd: list[str], name: str) -> bool:
    """True when `cmd` succeeds and its output names `name`."""
    result = _run(cmd)
    return bool(result and result.returncode == 0 and name in (result.stdout or ""))


def _claude_scopes(exe: str) -> set[str]:
    """Scopes in which `claude plugin list` shows the reporails plugin ("" when no scope is printed)."""
    result = _run([exe, "plugin", "list"])
    if not result or result.returncode != 0:
        return set()
    scopes: set[str] = set()
    current = ""
    for raw in (result.stdout or "").splitlines():
        line = raw.strip().lstrip("\u276f").strip()
        if line.endswith(_PLUGIN_ID):
            current = _PLUGIN_ID
            scopes.add("")
        elif "@" in line and " " not in line:
            current = line
        elif current == _PLUGIN_ID and line.lower().startswith("scope:"):
            scopes.add(line.split(":", 1)[1].strip())
    return scopes


def _plugin_installed(agent: str, exe: str, scope: str | None = None) -> bool:
    """True when the reporails plugin is installed in `agent` (in `scope`, for Claude Code)."""
    if agent == "claude":
        scopes = _claude_scopes(exe)
        return bool(scopes) if scope is None else scope in scopes
    result = _run([exe, "plugin", "list"])
    out = (result.stdout or "") if result and result.returncode == 0 else ""
    return re.search(rf"{re.escape(_PLUGIN_ID)}\s+installed", out) is not None


def _agent_steps(agent: str, exe: str, source: str, scope: str | None = None) -> list[tuple[list[str], bool]]:
    """Plugin commands for one agent as (command, required) pairs.

    A marketplace or plugin already present is refreshed instead of re-added,
    so a re-run leaves the current plugin installed. Refresh steps marked not
    required may fail without counting against the install. `scope` applies to
    Claude Code only.
    """
    plugin = [exe, "plugin"]
    market = [*plugin, "marketplace"]
    flag = ["--scope", scope] if scope and agent == "claude" else []
    market_present = _lists([*market, "list"], _MARKETPLACE) and not flag
    if agent == "claude":
        plugin_present = _plugin_installed(agent, exe, scope)
        steps: list[tuple[list[str], bool]] = (
            [([*market, "update", _MARKETPLACE], True)] if market_present else [([*market, "add", source, *flag], True)]
        )
        steps.append(([*plugin, "update" if plugin_present else "install", _PLUGIN_ID, *flag], True))
        return steps
    steps = [([*market, "upgrade", _MARKETPLACE], False)] if market_present else [([*market, "add", source], True)]
    steps.append(([*plugin, "add", _PLUGIN_ID], True))
    return steps


def _run_steps(label: str, steps: list[tuple[list[str], bool]], manual: str, verb: str) -> bool:
    """Run the plugin steps; print `manual` and return False when a required one fails."""
    for cmd, required in steps:
        result = _run(cmd)
        if result is not None and result.returncode == 0:
            continue
        if not required:
            continue
        detail = ((result.stderr or result.stdout).strip().splitlines() or [""])[-1] if result else "no answer"
        console.print(f"  [yellow]{label} plugin {verb} did not finish ({detail}).[/yellow]")
        console.print(f"  [dim]Run by hand: {manual}[/dim]")
        return False
    return True


def _install_agent_plugin(label: str, agent: str, manual: str, project: bool = False) -> None:
    """Install the plugin into one agent through its own CLI; print `manual` on any failure."""
    exe = shutil.which(agent)
    if not exe:
        return
    scope = "project" if project and agent == "claude" else None
    where = " for this project" if scope else ""
    console.print(f"  Installing the plugin into {label}{where}...")
    if _run_steps(label, _agent_steps(agent, exe, _plugin_source(), scope), manual, "install"):
        console.print(f"  [green]{label} plugin installed{where}[/green]")


def refresh_agent_plugins() -> None:
    """Refresh the reporails plugin in each agent that has it; one line per agent."""
    for label, agent in (("Claude Code", "claude"), ("Codex", "codex")):
        exe = shutil.which(agent)
        if not exe:
            continue
        if not _plugin_installed(agent, exe):
            console.print(f"  {label}: plugin not installed — run [bold]ails install[/bold]")
            continue
        steps = _agent_steps(agent, exe, _plugin_source())
        if _run_steps(label, steps, dict(_PLUGIN_INSTALL)[label], "refresh"):
            console.print(f"  [green]{label} plugin refreshed[/green]")


def _warm_engine() -> None:
    """Fetch the plugin's engine now so the agent's first MCP start is fast."""
    uvx = shutil.which("uvx")
    if not uvx:
        return
    from reporails_cli import __version__

    spec = _engine_spec(__version__)
    console.print("  Preparing the plugin's engine...")
    try:
        result = subprocess.run(
            [uvx, "--from", spec, "ails", "--version"],
            capture_output=True,
            text=True,
            timeout=_WARM_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("engine warm-up failed: %s", exc)
        return
    if result.returncode != 0:
        logger.warning("engine warm-up failed: %s", result.stderr.strip())


@app.command(rich_help_panel="Maintenance")
def install(
    project: bool = typer.Option(
        False,
        "--project",
        help="Install the plugin for this repository only, shared with collaborators (Claude Code).",
    ),
) -> None:
    """Put the reporails engine on PATH and add the plugin to Claude Code and Codex.

    With --project the plugin is installed for this repository only and shared
    with collaborators through the project's Claude Code settings; Codex
    installs for your user.
    """
    from reporails_cli.core.platform.adapters.api_client import has_api_key

    console.print("[bold]Installing the reporails engine (CLI + MCP server)...[/bold]")
    _install_to_path()

    console.print("\n[bold]Adding the reporails plugin to your agent...[/bold]")
    for label, agent in (("Claude Code", "claude"), ("Codex", "codex")):
        manual = dict(_PLUGIN_INSTALL)[label]
        _install_agent_plugin(label, agent, manual, project)
    if project and shutil.which("codex"):
        console.print("  [dim]Codex installs the plugin for your user, not per project.[/dim]")
    _warm_engine()

    console.print(
        "\n[dim]Cursor, GitHub Copilot and Antigravity install the plugin by hand, and heal has so far "
        "been run on Claude Code only:[/dim]"
    )
    for agent, command in _PLUGIN_INSTALL[2:]:
        console.print(f"  [cyan]{agent}[/cyan]: {command}")
    console.print(f"[dim]These steps use a local copy: {_PLUGIN_CLONE}[/dim]")

    if not has_api_key():
        console.print("\nSign in with [bold]ails auth login[/bold] to use heal (Pro).")
    console.print(
        "\n[green]Done.[/green] In Claude Code, run [bold]/reporails:ails heal[/bold]. In a Claude Code session that "
        "was already open, run [bold]/reload-plugins[/bold] first or start a new session."
    )
