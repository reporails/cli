"""CLI command — install."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

import typer

from reporails_cli.core.platform.config.credentials import effective_tier
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
_AUTO_AGENTS: dict[str, tuple[str, str]] = {
    "claude": ("Claude Code", f"/plugin marketplace add {_PLUGIN_REPO}  then  /plugin install {_PLUGIN_ID}"),
    "codex": ("Codex", f"codex plugin marketplace add {_PLUGIN_REPO}  then  codex plugin add {_PLUGIN_ID}"),
}
_MANUAL_AGENTS: dict[str, str] = {
    "Cursor": "copy plugin/plugins/reporails/ into ~/.cursor/plugins/local/reporails/, then restart Cursor",
    "GitHub Copilot": "VS Code -> 'Install Plugin From Source' -> the plugin/plugins/reporails/ folder",
    "Antigravity": "agy plugin install plugin/plugins/reporails",
}

# Variables an agent sets for its own session; a child agent command that
# inherits them can mistake itself for a nested session.
_SESSION_ENV = (
    "CLAUDECODE",
    "CLAUDE_CODE_SESSION_ID",
    "CLAUDE_CODE_ENTRYPOINT",
    "CLAUDE_CODE_CHILD_SESSION",
    "CLAUDE_CODE_EXECPATH",
    "AI_AGENT",
)


def _uv_cache_dir(uv: str) -> str | None:
    """uv's cache folder as uv reports it; None when uv cannot say."""
    try:
        result = subprocess.run([uv, "cache", "dir"], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout.strip() or None if result.returncode == 0 else None


def _is_temporary_ails(ails_path: str, uv: str | None) -> bool:
    """True when `ails_path` sits in uv's cache, i.e. a one-shot `uvx` environment."""
    cache = _uv_cache_dir(uv) if uv else None
    if cache:
        return Path(os.path.realpath(ails_path)).is_relative_to(os.path.realpath(cache))
    return "/.cache/uv/" in ails_path


def _install_to_path() -> bool:
    """Install ails to PATH via uv tool install. Returns True on success."""
    uv = shutil.which("uv")
    # Already on PATH as a real install (not uvx one-shot)?
    ails_path = shutil.which("ails")
    if ails_path and not _is_temporary_ails(ails_path, uv):
        console.print(f"  [dim]ails already on PATH: {ails_path}[/dim]")
        return True

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
    """Marketplace source for the plugin: `AILS_PLUGIN_SOURCE`, else the public repo.

    A path is made absolute so every command resolves it to the same folder.
    """
    value = os.environ.get(_PLUGIN_SOURCE_ENV, "").strip() or _PLUGIN_REPO
    if value.startswith(("/", "~", ".")):
        return os.path.abspath(os.path.expanduser(value))
    return value


def _git_root(start: Path) -> Path:
    """Nearest ancestor of `start` (itself included) with a `.git` entry, below home; `start` when none."""
    try:
        home: Path | None = Path.home().resolve()
    except (RuntimeError, OSError):
        home = None
    for candidate in (start, *start.parents):
        # The home folder, or a folder above it, is never a project root.
        if home and (candidate == home or home.is_relative_to(candidate)):
            break
        if (candidate / ".git").exists():
            return candidate
    return start


def _codex_home() -> Path:
    return Path(os.environ.get("CODEX_HOME") or "~/.codex").expanduser().resolve()


def _engine_spec(version: str) -> str:
    """The engine pin the plugin starts with: this release or newer within its line, e.g. `>=0.6.1,<0.7`.

    A suffix (`rc1`, `.dev3+g…`) is dropped; a bare `X.Y` counts as `X.Y.0`.
    """
    match = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version)
    if not match:
        return "reporails-cli"
    major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3) or 0)
    return f"reporails-cli>={major}.{minor}.{patch},<{major}.{minor + 1}"


def _run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str] | None:
    """Run one agent command without the agent-session variables; None on OSError or timeout."""
    env = {k: v for k, v in os.environ.items() if k not in _SESSION_ENV}
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=_STEP_TIMEOUT, check=False, env=env, cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("%s failed: %s", cmd[0], exc)
        return None


def _normalize_source(value: str) -> str:
    """Comparable form of a marketplace source: a real path, or `owner/repo` for a GitHub URL."""
    value = value.strip().rstrip("/")
    if value.startswith(("/", "~", ".")):
        return os.path.realpath(os.path.expanduser(value))
    value = re.sub(r"^(https://|git@)github\.com[/:]", "", value)
    return value.removesuffix(".git")


def _same_source(found: str, intended: str) -> bool:
    return _normalize_source(found) == _normalize_source(intended)


def _claude_marketplaces(text: str) -> dict[str, str]:
    """Marketplace name -> source from `claude plugin marketplace list` output."""
    found: dict[str, str] = {}
    current = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("\u276f"):
            current = line.lstrip("\u276f").strip()
            found[current] = ""
        elif current and line.lower().startswith("source:"):
            detail = line.split(":", 1)[1].strip()
            match = re.search(r"\((.*)\)\s*$", detail)
            found[current] = match.group(1) if match else detail
    return found


def _codex_marketplaces(text: str) -> dict[str, str]:
    """Marketplace name -> root from `codex plugin marketplace list` output."""
    found: dict[str, str] = {}
    for raw in text.splitlines():
        parts = raw.split(None, 1)
        if len(parts) == 2 and parts[0] != "MARKETPLACE" and not raw.startswith(("WARNING", " ")):
            found[parts[0]] = parts[1].strip()
    return found


def _claude_scopes(text: str) -> set[str]:
    """Scopes in which `claude plugin list` output shows the reporails plugin ("" when no scope is printed)."""
    scopes: set[str] = set()
    current = ""
    for raw in text.splitlines():
        line = raw.strip().lstrip("\u276f").strip()
        if line.endswith(_PLUGIN_ID):
            current = _PLUGIN_ID
            scopes.add("")
        elif "@" in line and " " not in line:
            current = line
        elif current == _PLUGIN_ID and line.lower().startswith("scope:"):
            scopes.add(line.split(":", 1)[1].strip())
    if len(scopes) > 1:
        scopes.discard("")
    return scopes


def _project_marketplace(root: Path, source: str) -> str:
    """State of the reporails marketplace declared in `root`'s project settings."""
    try:
        data = json.loads((root / ".claude" / "settings.json").read_text(encoding="utf-8"))
        declared = data["extraKnownMarketplaces"][_MARKETPLACE]["source"]
    except (OSError, ValueError, KeyError, TypeError):
        return "absent"
    if not isinstance(declared, dict):
        return "absent"
    found = str(declared.get("path") or declared.get("repo") or declared.get("url") or "")
    return "current" if _same_source(found, source) else "stale"


def _inspect(agent: str, exe: str, source: str, root: Path | None) -> tuple[str, set[str]]:
    """(marketplace state, scopes holding the plugin); lists each thing once.

    The marketplace state is "absent", "current", "stale" (another source) or
    "broken" (Codex cannot list it). A project install reads the project's own
    settings for the marketplace, and lists to confirm this machine has it.
    """
    market = "absent"
    if agent == "claude" and root is not None:
        market = _project_marketplace(root, source)
        if market == "current":
            # Declared in the committed settings; this machine may not have added it yet.
            listed = _run([exe, "plugin", "marketplace", "list"], root)
            names = _claude_marketplaces(listed.stdout or "") if listed and listed.returncode == 0 else {}
            if _MARKETPLACE not in names:
                market = "absent"
    else:
        listed = _run([exe, "plugin", "marketplace", "list"], root)
        if agent == "codex" and not (listed and listed.returncode == 0):
            market = "broken"
        elif listed and listed.returncode == 0:
            found = (_claude_marketplaces if agent == "claude" else _codex_marketplaces)(listed.stdout or "")
            if _MARKETPLACE in found:
                is_path = source.startswith(("/", "~", "."))
                if agent == "claude" or is_path:
                    same = _same_source(found[_MARKETPLACE], source)
                else:
                    # Codex lists a Git marketplace by its snapshot folder under the Codex home;
                    # a root elsewhere is a local folder.
                    same = Path(os.path.realpath(found[_MARKETPLACE])).is_relative_to(_codex_home())
                market = "current" if same else "stale"
    plugins = _run([exe, "plugin", "list"], root)
    out = (plugins.stdout or "") if plugins and plugins.returncode == 0 else ""
    if agent == "claude":
        return market, _claude_scopes(out)
    installed = re.search(rf"{re.escape(_PLUGIN_ID)}\s+installed", out) is not None
    return market, {""} if installed else set()


def _agent_steps(
    agent: str,
    exe: str,
    source: str,
    state: tuple[str, set[str]],
    scope: str | None = None,
    refresh: bool = False,
) -> list[tuple[list[str], bool]]:
    """Plugin commands for one agent as (command, required) pairs.

    A marketplace or plugin already present is refreshed instead of re-added,
    so a re-run leaves the current plugin installed; a marketplace of another
    source is removed and added again. Steps marked not required may fail
    without counting against the install. `scope` applies to Claude Code only;
    `refresh` updates the plugin in every scope it is installed in.
    """
    if agent == "claude":
        return _claude_steps(exe, source, state, scope, refresh)
    return _codex_steps(exe, source, state[0])


def _claude_steps(
    exe: str, source: str, state: tuple[str, set[str]], scope: str | None, refresh: bool
) -> list[tuple[list[str], bool]]:
    """Claude Code's marketplace and plugin commands, scoped when `scope` is set."""
    market_state, scopes = state
    plugin = [exe, "plugin"]
    market = [*plugin, "marketplace"]
    replaced = market_state in ("stale", "broken")
    steps: list[tuple[list[str], bool]] = []
    if replaced:
        steps.append(([*market, "remove", _MARKETPLACE, "--scope", scope or "user"], False))
    if market_state == "current":
        steps.append(([*market, "update", _MARKETPLACE], True))
    else:
        steps.append(([*market, "add", source, *(["--scope", scope] if scope else [])], True))
    for target in sorted(scopes) if refresh else [scope or ""]:
        # An unscoped install targets the user scope.
        present = bool(scopes & {"user", ""}) if not target and not refresh else target in scopes
        verb = "update" if present and not replaced else "install"
        steps.append(([*plugin, verb, _PLUGIN_ID, *(["--scope", target] if target else [])], True))
    return steps


def _codex_steps(exe: str, source: str, market_state: str) -> list[tuple[list[str], bool]]:
    """Codex's marketplace and plugin commands; Codex installs for the user only."""
    plugin = [exe, "plugin"]
    market = [*plugin, "marketplace"]
    steps: list[tuple[list[str], bool]] = []
    if market_state in ("stale", "broken"):
        steps.append(([*market, "remove", _MARKETPLACE], False))
    if market_state == "current":
        steps.append(([*market, "upgrade", _MARKETPLACE], False))
    else:
        steps.append(([*market, "add", source], True))
    steps.append(([*plugin, "add", _PLUGIN_ID], True))
    return steps


def _run_steps(
    label: str, steps: list[tuple[list[str], bool]], manual: str, verb: str, cwd: Path | None = None
) -> bool:
    """Run the plugin steps; print `manual` and return False when a required one fails."""
    for cmd, required in steps:
        result = _run(cmd, cwd)
        if result is not None and result.returncode == 0:
            continue
        if not required:
            continue
        detail = ((result.stderr or result.stdout).strip().splitlines() or [""])[-1] if result else "no answer"
        console.print(f"  [yellow]{label} plugin {verb} did not finish ({detail}).[/yellow]")
        console.print(f"  [dim]Run by hand: {manual}[/dim]")
        return False
    return True


def _note_replaced(label: str, source: str, market_state: str) -> None:
    if market_state in ("stale", "broken"):
        console.print(f"  [dim]Replacing the {label} reporails marketplace's old source with {source}.[/dim]")


def _install_agent_plugin(agent: str, project: bool = False) -> bool:
    """Install the plugin into one agent through its own CLI; True when it is in place.

    Prints the manual command when the agent is not on PATH or a step fails.
    """
    label, manual = _AUTO_AGENTS[agent]
    exe = shutil.which(agent)
    if not exe:
        console.print(f"  [yellow]{label}: `{agent}` not found on PATH.[/yellow]")
        console.print(f"  [dim]Run by hand: {manual}[/dim]")
        return False
    scoped = project and agent == "claude"
    root = _git_root(Path.cwd()) if scoped else None
    where = f" for this project ({root})" if root else ""
    console.print(f"  Installing the plugin into {label}{where}...")
    source = _plugin_source()
    state = _inspect(agent, exe, source, root)
    _note_replaced(label, source, state[0])
    steps = _agent_steps(agent, exe, source, state, "project" if scoped else None)
    if not _run_steps(label, steps, manual, "install", root):
        return False
    console.print(f"  [green]{label} plugin installed{where}[/green]")
    return True


def refresh_agent_plugins() -> None:
    """Refresh the reporails plugin in each agent that has it; one line per agent."""
    for agent, (label, manual) in _AUTO_AGENTS.items():
        exe = shutil.which(agent)
        if not exe:
            continue
        source = _plugin_source()
        state = _inspect(agent, exe, source, None)
        if not state[1]:
            console.print(f"  {label}: plugin not installed — run [bold]ails install[/bold]")
            continue
        _note_replaced(label, source, state[0])
        steps = _agent_steps(agent, exe, source, state, refresh=True)
        if _run_steps(label, steps, manual, "refresh"):
            console.print(f"  [green]{label} plugin refreshed[/green]")
    names = ", ".join(_MANUAL_AGENTS)
    console.print(
        f"  [dim]{names} install the plugin by hand: to update them, run git pull in the plugin clone,"
        " then install again as `ails install` shows.[/dim]"
    )


def _warm_engine() -> None:
    """Fetch the plugin's engine now so the agent's first MCP start is fast."""
    uvx = shutil.which("uvx")
    if not uvx:
        console.print("  [yellow]The plugin's server needs uv (https://docs.astral.sh/uv/).[/yellow]")
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
    in_place = {agent: _install_agent_plugin(agent, project) for agent in _AUTO_AGENTS}
    if project and shutil.which("codex"):
        console.print("  [dim]Codex installs the plugin for your user, not per project.[/dim]")
    if any(in_place.values()):
        _warm_engine()

    console.print(
        "\n[dim]Cursor, GitHub Copilot and Antigravity install the plugin by hand, and heal has so far "
        "been run on Claude Code only:[/dim]"
    )
    for agent, command in _MANUAL_AGENTS.items():
        console.print(f"  [cyan]{agent}[/cyan]: {command}")
    console.print(f"[dim]These steps use a local copy: {_PLUGIN_CLONE}[/dim]")

    signed_in = has_api_key()
    if not signed_in:
        console.print("\nSign in with [bold]ails login[/bold] to use heal (Pro).")
    if not in_place["claude"]:
        console.print("\n[green]Done.[/green] Claude Code's plugin steps are printed above.")
        return
    from reporails_cli.core.platform.dto.diagnostics import UNENTITLED_TIERS

    # A tier of neither kind is unknown, which reads as entitled.
    tier = effective_tier() if signed_in else ""
    entitled = bool(tier) and tier not in UNENTITLED_TIERS
    heal = "[bold]/reporails:ails heal[/bold]" + ("" if entitled else " (Pro)")
    console.print(
        f"\n[green]Done.[/green] In Claude Code, run {heal}. In a Claude Code session that "
        "was already open, run [bold]/reload-plugins[/bold] first or start a new session."
    )
