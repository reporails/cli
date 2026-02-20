"""CLI config command — ails config get/set/list."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import typer
import yaml

from reporails_cli.interfaces.cli.helpers import console

config_app = typer.Typer(
    name="config",
    help="Get and set project configuration (.reporails/config.yml).",
    no_args_is_help=True,
)

# Keys that map to ProjectConfig fields
KNOWN_KEYS = {
    "default_agent": str,
    "exclude_dirs": list,
    "disabled_rules": list,
    "experimental": bool,
    "recommended": bool,
    "framework_version": str,
}

# Subset of keys allowed in global config (~/.reporails/config.yml)
GLOBAL_KEYS = {"default_agent", "recommended"}


def _project_config_path(path: Path) -> Path:
    return path / ".reporails" / "config.yml"


def _global_config_path() -> Path:
    from reporails_cli.core.bootstrap import get_global_config_path

    return get_global_config_path()


def _load_config(path: Path) -> dict[str, Any]:
    cp = _project_config_path(path)
    if not cp.exists():
        return {}
    try:
        return yaml.safe_load(cp.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return {}


def _load_global_config() -> dict[str, Any]:
    cp = _global_config_path()
    if not cp.exists():
        return {}
    try:
        return yaml.safe_load(cp.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError):
        return {}


def _save_config(path: Path, data: dict[str, Any]) -> None:
    cp = _project_config_path(path)
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=True), encoding="utf-8")


def _save_global_config(data: dict[str, Any]) -> None:
    cp = _global_config_path()
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=True), encoding="utf-8")


def _parse_value(key: str, raw: str) -> object:
    """Parse a string value into the appropriate type for the given key."""
    expected = KNOWN_KEYS.get(key)
    if expected is bool:
        return raw.lower() in ("true", "1", "yes")
    if expected is list:
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw


@config_app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key (e.g., default_agent, exclude_dirs)"),
    value: str = typer.Argument(..., help="Value to set (comma-separated for lists)"),
    path: str = typer.Option(".", help="Project root"),
    global_: bool = typer.Option(False, "--global", help="Use global config (~/.reporails/config.yml)"),
) -> None:
    """Set a config value."""
    if key not in KNOWN_KEYS:
        console.print(f"[red]Error:[/red] Unknown config key: {key}")
        console.print(f"Known keys: {', '.join(sorted(KNOWN_KEYS))}")
        raise typer.Exit(2)

    if global_:
        if key not in GLOBAL_KEYS:
            console.print(f"[red]Error:[/red] Key '{key}' is not supported in global config.")
            console.print(f"Global keys: {', '.join(sorted(GLOBAL_KEYS))}")
            raise typer.Exit(2)
        data = _load_global_config()
        data[key] = _parse_value(key, value)
        _save_global_config(data)
        console.print(f"Set {key} = {data[key]} (global)")
        return

    target = Path(path).resolve()
    data = _load_config(target)
    data[key] = _parse_value(key, value)
    _save_config(target, data)
    console.print(f"Set {key} = {data[key]}")


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key to read"),
    path: str = typer.Option(".", help="Project root"),
    global_: bool = typer.Option(False, "--global", help="Use global config (~/.reporails/config.yml)"),
) -> None:
    """Get a config value."""
    if global_:
        if key not in KNOWN_KEYS:
            console.print(f"[red]Error:[/red] Unknown config key: {key}")
            raise typer.Exit(2)
        data = _load_global_config()
        if key not in data:
            console.print(f"{key}: [dim](not set)[/dim]")
        else:
            console.print(f"{key}: {data[key]}")
        return

    target = Path(path).resolve()
    data = _load_config(target)

    if key not in data:
        if key in KNOWN_KEYS:
            console.print(f"{key}: [dim](not set)[/dim]")
        else:
            console.print(f"[red]Error:[/red] Unknown config key: {key}")
            raise typer.Exit(2)
        return

    console.print(f"{key}: {data[key]}")


@config_app.command("list")
def config_list(
    path: str = typer.Option(".", help="Project root"),
    global_: bool = typer.Option(False, "--global", help="Use global config (~/.reporails/config.yml)"),
) -> None:
    """Show all config values."""
    if global_:
        data = _load_global_config()
        if not data:
            console.print("[dim]No global configuration set. Config file: ~/.reporails/config.yml[/dim]")
            return
        for key, val in sorted(data.items()):
            console.print(f"{key}: {val}")
        return

    target = Path(path).resolve()
    project_data = _load_config(target)
    global_data = _load_global_config()

    # Merge: show project values, annotate global fallbacks
    merged: dict[str, tuple[Any, str]] = {}
    for key, val in project_data.items():
        merged[key] = (val, "")
    for key in GLOBAL_KEYS:
        if key not in merged and key in global_data:
            merged[key] = (global_data[key], " (global)")

    if not merged:
        console.print("[dim]No configuration set. Config file: .reporails/config.yml[/dim]")
        return

    for key, (val, source) in sorted(merged.items()):
        console.print(f"{key}: {val}{source}")
