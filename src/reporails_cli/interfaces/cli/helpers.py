"""Shared CLI utilities — app instance, console, environment helpers."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="ails",
    help=("what ails your repo? Let's find out!\n\nrun `ails check` to diagnose your project's instructions"),
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
console = Console(emoji=False, highlight=False)


def _is_ci() -> bool:
    """Check if running in CI environment."""
    ci_vars = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI")
    return any(os.environ.get(var) for var in ci_vars)


def _warn_unresolved_skills(unresolved: list[Any], project_root: Path) -> None:
    """Print one stderr warning per declared-but-unresolved skill."""
    for skill in unresolved:
        try:
            rel = skill.declared_in.relative_to(project_root)
        except ValueError:
            rel = skill.declared_in
        print(
            f"Warning: {rel} declares skill {skill.skill_name!r} — not found under .claude/skills/",
            file=sys.stderr,
        )


def _default_format() -> str:
    """Return default format based on environment detection.

    A non-TTY pipe gets `text` — the worst-first summary `print_text_result`
    renders (colorless when piped) — the format `_dispatch_output` actually
    routes. Returning an undispatched value here silently fell through to the
    same renderer while promising a formatter that no longer runs.
    """
    if _is_ci():
        return "json"
    return "text"


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


def _print_no_instruction_files(effective_agent: str, con: Console, detected_agents: list[Any] | None = None) -> None:
    """Print the human message for a run that found nothing to check.

    Text surface only. The machine surfaces (`json` / `github`) render the same
    outcome as an ordinary empty result through their normal formatter, so a
    consumer reads one envelope shape whether or not anything was in scope —
    see `check_flow._emit_empty_run`.
    """
    from reporails_cli.core.discovery.agents import get_known_agents
    from reporails_cli.core.platform.dto.models import Level
    from reporails_cli.core.platform.policy.levels import LEVEL_LABELS

    at = get_known_agents().get(effective_agent)
    others = sorted(
        {a.agent_type.id for a in detected_agents or () if a.agent_type.id not in (effective_agent, "generic")}
    )
    if others:
        names = ", ".join(others)
        con.print(
            f"No instruction files found for {effective_agent}.\nLevel: L0 {LEVEL_LABELS[Level.L0]}\n\n"
            f"[dim]This project has files for: {names}. "
            f"Run with --agent {others[0]}, or: ails config set default_agent {others[0]}[/dim]"
        )
        return
    hint = at.instruction_patterns[0] if at else "AGENTS.md"
    article = "an" if hint[:1].upper() in "AEIOU" else "a"
    con.print(
        f"No instruction files found.\nLevel: L0 {LEVEL_LABELS[Level.L0]}\n\n"
        f"[dim]Create {article} {hint} to get started.[/dim]"
    )
