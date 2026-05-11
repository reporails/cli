"""Shared CLI utilities — app instance, console, environment helpers."""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="ails",
    help="Validate and score AI instruction files - what ails your repo?",
    no_args_is_help=True,
)
console = Console(emoji=False, highlight=False)


def _is_ci() -> bool:
    """Check if running in CI environment."""
    ci_vars = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI")
    return any(os.environ.get(var) for var in ci_vars)


def _default_format() -> str:
    """Return default format based on environment detection."""
    if _is_ci():
        return "json"
    if not sys.stdout.isatty():
        return "compact"
    return "text"


VALID_FORMATS = {"text", "json", "compact", "brief", "github", "agent"}


def _validate_agent(agent: str, con: Console) -> str:
    """Normalize and validate --agent value. Returns normalized agent or exits."""
    from reporails_cli.core.discovery.agents import get_known_agents as _get_known

    agent = agent.lower().strip()
    known = _get_known()
    if agent and agent not in known:
        con.print(f"[red]Error:[/red] Unknown agent: {agent}")
        con.print(f"Known agents: {', '.join(sorted(known))}")
        raise typer.Exit(2)
    return agent


def _validate_format(format: str | None, con: Console) -> None:
    """Validate --format value or exit."""
    if format and format not in VALID_FORMATS:
        con.print(f"[red]Error:[/red] Unknown format: {format}")
        con.print(f"Valid formats: {', '.join(sorted(VALID_FORMATS))}")
        raise typer.Exit(2)


def _show_agent_auto_detect_hint(
    effective_agent: str,
    output_format: str,
    assumed: bool,
    mixed_signals: bool,
    detected_agents: list[Any],
) -> None:
    """Show auto-detect or generic-fallback hint for agent resolution."""
    if output_format not in ("text", "compact") or not sys.stdout.isatty():
        return
    cmd = "ails config set default_agent"
    w = 64  # scorecard width
    non_generic = [a.agent_type.id for a in detected_agents if a.agent_type.id != "generic"]
    lines: list[str] = []
    if assumed:
        lines.append(f"Assumed {effective_agent} — lock in: {cmd} {effective_agent}")
    elif mixed_signals:
        lines.append(f"Lock in an agent: {cmd} <name>")
        lines.append("Add --global to set for all projects")
        lines.append(f"Available: {', '.join(non_generic)}")
    elif effective_agent == "generic" and non_generic:
        lines.append(f"Lock in: {cmd} {non_generic[0]}")
    if lines:
        for line in lines:
            console.print(f"[dim]{line:^{w}}[/dim]")


def _print_unknown_rule(rule_id: str, loaded_rules: dict[str, Any]) -> None:
    """Print grouped available rules when an unknown rule ID is given."""
    console.print(f"[red]Error:[/red] Unknown rule: {rule_id}")
    grouped: dict[str, list[str]] = {}
    for rid in sorted(loaded_rules):
        ns = rid.rsplit(":", 1)[0] if ":" in rid else rid
        grouped.setdefault(ns, []).append(rid.rsplit(":", 1)[-1] if ":" in rid else rid)
    console.print(f"Available rules ({len(loaded_rules)} total):")
    for ns, ids in sorted(grouped.items()):
        tail = f" ... ({len(ids) - 5} more)" if len(ids) > 5 else ""
        console.print(f"  {ns}: {', '.join(ids[:5])}{tail}")


def _resolve_agent_filters(
    agent: str,
    all_detected: list[Any],
    target: Path,
    exclude_dirs: list[str] | None,
) -> tuple[str, bool, bool, list[Any]]:
    """Resolve agent selection and filter detected agents. Returns (agent, assumed, mixed, filtered)."""
    from reporails_cli.core.discovery.agents import (
        detect_single_agent,
        filter_agents_by_exclude_dirs,
        filter_agents_by_id,
        resolve_agent,
    )

    agent, assumed, mixed = resolve_agent(agent, all_detected)
    effective = agent if agent else "generic"
    if mixed:
        filtered = [a for a in all_detected if a.agent_type.id != "generic"]
    else:
        filtered = filter_agents_by_id(all_detected, effective)
        if not filtered and agent:
            single = detect_single_agent(target, agent)
            if single:
                filtered = [single]
    return effective, assumed, mixed, filter_agents_by_exclude_dirs(filtered, target, exclude_dirs)


def _handle_no_instruction_files(effective_agent: str, output_format: str, con: Console) -> None:
    """Print appropriate message when no instruction files are found, then exit."""
    if output_format in ("json", "github"):
        print(json.dumps({"violations": [], "score": 0, "level": "L0"}))
    else:
        from reporails_cli.core.discovery.agents import get_known_agents

        at = get_known_agents().get(effective_agent)
        hint = at.instruction_patterns[0] if at else "AGENTS.md"
        con.print(f"No instruction files found.\nLevel: L0 (Absent)\n\n[dim]Create a {hint} to get started.[/dim]")


def _resolve_rules_paths(rules: list[str] | None, con: Console) -> list[Path] | None:
    """Validate and resolve --rules CLI option paths. Exits if any path missing."""
    if not rules:
        return None
    resolved = [Path(r).resolve() for r in rules]
    for rp in resolved:
        if not rp.is_dir():
            con.print(f"[red]Error:[/red] Rules directory not found: {rp}")
            raise typer.Exit(2)
    return resolved


def _print_section(title: str, data: Mapping[str, object]) -> None:
    """Print a labeled section, skipping null values."""
    non_null = {k: v for k, v in data.items() if v is not None}
    if not non_null:
        return
    console.print(f"[bold]{title}:[/bold]")
    for key, value in non_null.items():
        if isinstance(value, list):
            console.print(f"  {key}: {', '.join(str(v) for v in value)}")
        else:
            console.print(f"  {key}: {value}")
    console.print()


def _print_map_text(target: Path, agents: list[Any], elapsed_ms: float) -> None:
    """Print human-readable map output."""
    from reporails_cli.core.discovery.discover import (
        _detect_classification,
        _detect_commands,
        _detect_meta,
        _detect_paths,
    )

    console.print(f"[bold]Project Map[/bold] - {target.name}")
    console.print("=" * 50)
    console.print()

    for agent in agents:
        root_files = [f for f in agent.instruction_files if f.parent == target]
        main_file = root_files[0].relative_to(target).as_posix() if root_files else "?"
        console.print(f"[bold]{agent.agent_type.name}[/bold]")
        console.print(f"  main: {main_file}")
        for label, dir_path in agent.detected_directories.items():
            console.print(f"  {label}: {dir_path}")
        if agent.config_files:
            cf = agent.config_files[0]
            if cf.is_relative_to(target):
                console.print(f"  config: {cf.relative_to(target)}")
        console.print()

    _print_section("Classification", _detect_classification(target))
    _print_section("Paths", _detect_paths(target))
    _print_section("Commands", _detect_commands(target))
    _print_section("Meta", _detect_meta(target))

    console.print(f"[dim]Completed in {elapsed_ms:.0f}ms[/dim]")
