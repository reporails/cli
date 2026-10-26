"""CLI config command — ails config get/set/list."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import get_type_hints

import typer
import yaml
from rich.markup import escape

from reporails_cli.core.platform.config.bootstrap import get_global_config_path, get_project_config_path
from reporails_cli.core.platform.config.config import (
    TEXT_LIST_KEYS,
    read_config_file,
    setting_value_problem,
)
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.results import GlobalConfig, ProjectConfig
from reporails_cli.core.platform.utils.utils import forget_yaml_file
from reporails_cli.interfaces.cli.helpers import console
from reporails_cli.interfaces.cli.typer_app import HELP_CONTEXT_SETTINGS

config_app = typer.Typer(
    name="config",
    help="Get and set project configuration.",
    no_args_is_help=True,
    context_settings=HELP_CONTEXT_SETTINGS,
)


def _key_types(config_cls: type) -> dict[str, type | None]:
    """Every field of a config dataclass with the type `config set` parses its value into.

    A field the config reader holds as a list of names maps to `list`; a string or a bool
    (optionally unset) to `str` or `bool`; any other field maps to None and is read-only here.
    """
    kinds: dict[str, type | None] = {}
    for name, hint in get_type_hints(config_cls).items():
        if name in TEXT_LIST_KEYS:
            kinds[name] = list
        elif hint in (str, str | None):
            kinds[name] = str
        elif hint in (bool, bool | None):
            kinds[name] = bool
        else:
            kinds[name] = None
    return kinds


# The keys `config set` writes: every settable project field in the project file; in the
# global file only those the global config also carries, as it is read for no other.
_PROJECT_SETTABLE: dict[str, type] = {
    name: kind for name, kind in _key_types(ProjectConfig).items() if kind is not None
}
_GLOBAL_SETTABLE: dict[str, type] = {
    name: kind for name, kind in _PROJECT_SETTABLE.items() if name in _key_types(GlobalConfig)
}


def _settable(global_: bool) -> dict[str, type]:
    return _GLOBAL_SETTABLE if global_ else _PROJECT_SETTABLE


def _load_config(path: Path, check_items: bool = True) -> JsonObject:
    return read_config_file(get_project_config_path(path), check_items)


def _load_global_config(check_items: bool = True) -> JsonObject:
    return read_config_file(get_global_config_path(), check_items)


def _save_config(path: Path, data: JsonObject) -> None:
    cp = get_project_config_path(path)
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=True), encoding="utf-8")
    forget_yaml_file(cp)
    _ensure_ails_gitignore(cp.parent)


# .gitignore content for .ails/ — ignores itself plus the layered local config.
# The .gitignore is per-machine scaffolding (recreated when `ails config set` runs);
# it does not need to be tracked in version control.
_AILS_GITIGNORE_LINES = (".gitignore", "config.local.yml")


def _ensure_ails_gitignore(ails_dir: Path) -> None:
    """Ensure `.ails/.gitignore` exists and lists `.gitignore` + `config.local.yml`.

    Idempotent: if the file already lists both entries, no change. If it
    exists but is missing entries, append the missing ones.
    """
    gitignore = ails_dir / ".gitignore"
    if gitignore.exists():
        try:
            existing = gitignore.read_text(encoding="utf-8")
        except OSError:
            return
        existing_lines = {line.strip() for line in existing.splitlines()}
        missing = [entry for entry in _AILS_GITIGNORE_LINES if entry not in existing_lines]
        if not missing:
            return
        suffix = "" if existing.endswith("\n") else "\n"
        with contextlib.suppress(OSError):
            gitignore.write_text(existing + suffix + "\n".join(missing) + "\n", encoding="utf-8")
        return
    body = "# Personal/CI overrides — see docs/configuration.md\n"
    body += "\n".join(_AILS_GITIGNORE_LINES) + "\n"
    with contextlib.suppress(OSError):
        gitignore.write_text(body, encoding="utf-8")


def _save_global_config(data: JsonObject) -> None:
    cp = get_global_config_path()
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=True), encoding="utf-8")
    forget_yaml_file(cp)


def _parse_value(expected: type, raw: str) -> JsonValue:
    """Parse a string value into the type its key takes."""
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
    settable = _settable(global_)
    if key not in settable:
        console.print(f"[red]Error:[/red] Unknown config key: {key}")
        console.print(f"Settable keys: {', '.join(sorted(settable))}")
        raise typer.Exit(2)
    parsed = _parse_value(settable[key], value)
    problem = setting_value_problem(key, parsed)
    if problem is not None:
        console.print(f"[red]Error:[/red] {escape(problem)}", soft_wrap=True)
        raise typer.Exit(2)

    if global_:
        data = _load_global_config(check_items=False)
        data[key] = parsed
        _save_global_config(data)
        console.print(f"Set {key} = {data[key]} (global)")
        return

    target = Path(path).resolve()
    data = _load_config(target, check_items=False)
    data[key] = parsed
    _save_config(target, data)
    console.print(f"Set {key} = {data[key]}")


@config_app.command("get")
def config_get(
    key: str = typer.Argument(..., help="Config key to read"),
    path: str = typer.Option(".", help="Project root"),
    global_: bool = typer.Option(False, "--global", help="Use global config (~/.reporails/config.yml)"),
) -> None:
    """Get a config value: what the file holds, `(not set)` for a known key it leaves out."""
    data = _load_global_config() if global_ else _load_config(Path(path).resolve())
    if key in data:
        console.print(f"{key}: {data[key]}")
        return
    if key not in _settable(global_):
        console.print(f"[red]Error:[/red] Unknown config key: {key}")
        raise typer.Exit(2)
    console.print(f"{key}: [dim](not set)[/dim]")


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
    merged: dict[str, tuple[JsonValue, str]] = {}
    for key, val in project_data.items():
        merged[key] = (val, "")
    for key in sorted(_GLOBAL_SETTABLE):
        if key not in merged and key in global_data:
            merged[key] = (global_data[key], " (global)")

    if not merged:
        console.print("[dim]No configuration set. Config file: .ails/config.yml[/dim]")
        return

    for key, (val, source) in sorted(merged.items()):
        console.print(f"{key}: {val}{source}")
