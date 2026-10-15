"""`ails rules` — browse the framework rule registry.

Subcommands:
- `ails rules list` — enumerate every rule, filterable (repeatable `--capability`).
- `ails rules agents` — enumerate known agents.
- `ails rules capabilities` — enumerate capability vocabulary for an agent.
"""

from __future__ import annotations

import json as _json
import sys
from pathlib import Path

import typer

from reporails_cli.core.discovery.agents import detect_agents
from reporails_cli.core.platform.adapters.rules_query import list_known_agents
from reporails_cli.core.platform.config.vocabulary import load_capability_vocabulary
from reporails_cli.interfaces.cli.helpers import console
from reporails_cli.interfaces.cli.output_formats import RULES_LIST_FORMATS, RULES_PLAIN_FORMATS
from reporails_cli.interfaces.cli.typer_app import HELP_CONTEXT_SETTINGS, app

rules_app = typer.Typer(
    help="Browse the framework rule registry.",
    no_args_is_help=True,
    context_settings=HELP_CONTEXT_SETTINGS,
)
app.add_typer(rules_app, name="rules", rich_help_panel="Explore")


def _require_format(output_format: str, valid: tuple[str, ...]) -> None:
    """Exit 2 with a usage error when `output_format` is not one of `valid`."""
    if output_format not in valid:
        valid_str = " | ".join(valid)
        console.print(f"[red]Error:[/red] invalid --format '{output_format}'; expected one of: {valid_str}")
        raise typer.Exit(2)


def _require_known_capabilities(capabilities: list[str] | None, agent: str | None) -> None:
    """Exit 2 naming a `--capability` the selected agent (or any agent) does not declare."""
    if not capabilities:
        return
    from reporails_cli.core.classify.capability_paths import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        available_capabilities,
        canonicalize_capability,
    )

    agents = [agent] if agent else list_known_agents()
    unknown = [c for c in capabilities if not any(canonicalize_capability(c, a) for a in agents)]
    if not unknown:
        return
    known = set(load_capability_vocabulary().virtual)
    for a in agents:
        known.update(available_capabilities(a))
    scope = f"agent '{agent}'" if agent else "any agent"
    names = ", ".join(repr(c) for c in unknown)
    console.print(
        f"[red]Error:[/red] unknown capability {names} for {scope}; known: {', '.join(sorted(known)) or '(none)'}"
    )
    raise typer.Exit(2)


@rules_app.command("list")
def rules_list(
    capabilities: list[str] = typer.Option(  # noqa: B008
        None,
        "--capability",
        "-c",
        help="Filter to rules that apply to this capability (e.g. skills, agents, hooks). Repeatable.",
    ),
    agent: str = typer.Option(None, "--agent", "-a", help="Restrict to this agent's namespace plus CORE."),
    severity: str = typer.Option(None, "--severity", "-s", help="Minimum severity (`critical|high|medium|low`)."),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text | md | json."),
    no_examples: bool = typer.Option(False, "--no-examples", help="Strip Pass / Fail blocks from md output."),
) -> None:
    """List rules in the registry, optionally filtered by capability / agent / severity."""
    _require_format(output_format, RULES_LIST_FORMATS)
    _require_known_capabilities(capabilities, agent)
    from reporails_cli.interfaces.cli.checks_command import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        list_checks,
    )

    list_checks(
        capabilities=capabilities or None,
        agent=agent,
        severity=severity,
        output_format=output_format,
        no_examples=no_examples,
    )


@rules_app.command("agents")
def rules_agents(
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text | json."),
) -> None:
    """List known agents."""
    _require_format(output_format, RULES_PLAIN_FORMATS)
    agents = list_known_agents()
    if output_format == "json":
        sys.stdout.write(_json.dumps({"agents": agents}, indent=2) + "\n")
        return
    if not agents:
        console.print("[yellow]No agents found.[/yellow]")
        return
    console.print(f"[bold]Known agents[/bold] ({len(agents)}):")
    for a in agents:
        console.print(f"  {a}")


def _capability_agent(agent: str | None) -> str | None:
    """The agent whose capabilities to list: the one named, else the first detected in the cwd."""
    if agent:
        return agent
    detected = detect_agents(Path.cwd())
    return detected[0].agent_type.id if detected else None


def _capability_resolution(agent: str) -> tuple[list[str], dict[str, str], dict[str, int]]:
    """The agent's capability names, the first path pattern each resolves to, and how many targets each finds."""
    from reporails_cli.core.classify import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        load_file_types,
    )
    from reporails_cli.core.classify.capability_paths import (  # pylint: disable=import-outside-toplevel  # startup: loads when the command runs
        available_capabilities,
        list_capability_targets,
    )

    caps = sorted(available_capabilities(agent, Path.cwd()))
    decls = {d.name: d for d in load_file_types(agent)}
    patterns = {c: (decls[c].patterns[0] if decls.get(c) and decls[c].patterns else "") for c in caps}
    found = {c: len(list_capability_targets(agent, c, Path.cwd(), None)) for c in caps}
    return caps, patterns, found


@rules_app.command("capabilities")
def rules_capabilities(
    agent: str = typer.Option(None, "--agent", "-a", help="Agent whose capability vocabulary to enumerate."),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text | json."),
) -> None:
    """List the capabilities you can target and what each resolves to."""
    _require_format(output_format, RULES_PLAIN_FORMATS)
    effective_agent = _capability_agent(agent)
    if not effective_agent:
        msg = "No agent detected; pass --agent <name>."
        if output_format == "json":
            sys.stdout.write(_json.dumps({"agent": None, "capabilities": [], "error": msg}, indent=2) + "\n")
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(2)

    caps, patterns, found = _capability_resolution(effective_agent)

    if output_format == "json":
        resolution = [{"name": c, "resolves_to": patterns[c], "found": found[c]} for c in caps]
        payload = {"agent": effective_agent, "capabilities": caps, "resolution": resolution}
        sys.stdout.write(_json.dumps(payload, indent=2) + "\n")
        return

    console.print(f"[bold]Capabilities for {effective_agent}[/bold] ({len(caps)}):")
    name_w = max((len(c) for c in caps), default=0)
    pat_w = max((len(patterns[c]) for c in caps), default=0)
    for c in caps:
        console.print(f"  {c:<{name_w}}  {patterns[c]:<{pat_w}}  {found[c]} found")
