"""`ails rules` — browse the framework rule registry.

Subcommands:
- `ails rules list` — enumerate every rule, filterable (repeatable `--capability`).
- `ails rules agents` — enumerate known agents.
- `ails rules capabilities` — enumerate capability vocabulary for an agent.
"""

from __future__ import annotations

import json as _json
import sys

import typer

from reporails_cli.interfaces.cli.checks_command import list_checks
from reporails_cli.interfaces.cli.helpers import app, console

rules_app = typer.Typer(
    help="Browse the reporails framework rule registry.",
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
app.add_typer(rules_app, name="rules", rich_help_panel="Commands")


@rules_app.command("list")
def rules_list(
    capabilities: list[str] = typer.Option(  # noqa: B008
        None,
        "--capability",
        "-c",
        help="Filter to rules whose `match.type` includes this capability. Repeatable.",
    ),
    agent: str = typer.Option(None, "--agent", "-a", help="Restrict to this agent's namespace plus CORE."),
    severity: str = typer.Option(None, "--severity", "-s", help="Minimum severity (`critical|high|medium|low`)."),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text | md | json."),
    no_examples: bool = typer.Option(False, "--no-examples", help="Strip Pass / Fail blocks from md output."),
) -> None:
    """List rules in the registry, optionally filtered by capability / agent / severity."""
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
    """List known agents (from `framework/rules/<agent>/`)."""
    from reporails_cli.core.platform.adapters.rules_query import list_known_agents

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


@rules_app.command("capabilities")
def rules_capabilities(
    agent: str = typer.Option(None, "--agent", "-a", help="Agent whose capability vocabulary to enumerate."),
    output_format: str = typer.Option("text", "--format", "-f", help="Output format: text | json."),
) -> None:
    """List the capability vocabulary (`skill`, `agent`, `rule`, `main`, ...) for an agent."""
    from pathlib import Path

    from reporails_cli.core.classify.capability_paths import available_capabilities
    from reporails_cli.core.discovery.agents import detect_agents

    effective_agent = agent
    if not effective_agent:
        detected = detect_agents(Path.cwd())
        if detected:
            effective_agent = detected[0].agent_type.id
    if not effective_agent:
        msg = "No agent detected; pass --agent <name>."
        if output_format == "json":
            sys.stdout.write(_json.dumps({"agent": None, "capabilities": [], "error": msg}, indent=2) + "\n")
        else:
            console.print(f"[red]Error:[/red] {msg}")
        raise typer.Exit(2)
    caps = available_capabilities(effective_agent, Path.cwd())
    if output_format == "json":
        sys.stdout.write(_json.dumps({"agent": effective_agent, "capabilities": sorted(caps)}, indent=2) + "\n")
        return
    console.print(f"[bold]Capabilities for {effective_agent}[/bold] ({len(caps)}):")
    for c in sorted(caps):
        console.print(f"  {c}")
