"""Shared CLI utilities — app instance, console, environment helpers."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from reporails_cli.core.models import ScanDelta, ValidationResult
from reporails_cli.formatters import github as github_formatter
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters import text as text_formatter

app = typer.Typer(
    name="ails",
    help="Validate and score AI instruction files - what ails your repo?",
    no_args_is_help=True,
)
console = Console(emoji=False)


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


def _resolve_recommended_rules(
    rules_paths: list[Path] | None,
    project_config: Any,
    format: str | None,
    con: Console,
) -> list[Path] | None:
    """Download recommended rules if needed and append the package path.

    Returns the updated rules_paths (may be mutated or newly created).
    """
    from reporails_cli.core.init import download_recommended, is_recommended_installed

    use_recommended = project_config.recommended
    has_recommended = (
        rules_paths
        and len(rules_paths) > 1
        and any(
            (p / "docs" / "sources.yml").exists() and p != (rules_paths[0] if rules_paths else None)
            for p in rules_paths[1:]
        )
    )

    if use_recommended and not has_recommended and not is_recommended_installed():
        try:
            if sys.stdout.isatty() and format not in ("json", "brief", "compact", "github"):
                with con.status("[bold]Downloading recommended rules...[/bold]"):
                    download_recommended()
            else:
                download_recommended()
        except Exception as e:
            con.print(f"[yellow]Warning:[/yellow] Could not download recommended rules: {e}")

    if use_recommended and not has_recommended:
        from reporails_cli.core.bootstrap import get_recommended_package_path

        rec_path = get_recommended_package_path()
        if rec_path.is_dir():
            if rules_paths is not None:
                if rec_path not in rules_paths:
                    rules_paths.append(rec_path)
            else:
                from reporails_cli.core.registry import get_rules_dir

                rules_paths = [get_rules_dir(), rec_path]

    return rules_paths


def _handle_update_check(con: Console) -> None:
    """Print installed vs latest versions for framework and recommended."""
    from reporails_cli.core.bootstrap import (
        get_installed_recommended_version,
        get_installed_version,
    )
    from reporails_cli.core.init import get_latest_recommended_version, get_latest_version

    current = get_installed_version()
    current_rec = get_installed_recommended_version()
    with con.status("[bold]Checking for updates...[/bold]"):
        latest = get_latest_version()
        latest_rec = get_latest_recommended_version()

    con.print("[bold]Framework:[/bold]")
    con.print(f"  Installed: {current or 'not installed'}")
    con.print(f"  Latest:    {latest or 'unknown'}")

    con.print("[bold]Recommended:[/bold]")
    con.print(f"  Installed: {current_rec or 'not installed'}")
    con.print(f"  Latest:    {latest_rec or 'unknown'}")

    rules_current = latest and current == latest
    rec_current = latest_rec and current_rec == latest_rec
    if rules_current and rec_current:
        con.print("\n[green]You are up to date.[/green]")
    else:
        con.print("\n[cyan]Run 'ails update' to update[/cyan]")


VALID_FORMATS = {"text", "json", "compact", "brief", "github"}


def _validate_agent(agent: str, con: Console) -> str:
    """Normalize and validate --agent value. Returns normalized agent or exits."""
    agent = agent.lower().strip()
    if agent:
        from reporails_cli.core.agents import KNOWN_AGENTS as _KNOWN

        if agent not in _KNOWN:
            con.print(f"[red]Error:[/red] Unknown agent: {agent}")
            con.print(f"Known agents: {', '.join(sorted(_KNOWN))}")
            raise typer.Exit(2)
    return agent


def _validate_format(format: str | None, con: Console) -> None:
    """Validate --format value or exit."""
    if format and format not in VALID_FORMATS:
        con.print(f"[red]Error:[/red] Unknown format: {format}")
        con.print(f"Valid formats: {', '.join(sorted(VALID_FORMATS))}")
        raise typer.Exit(2)


def _handle_no_instruction_files(
    effective_agent: str,
    output_format: str,
    con: Console,
) -> None:
    """Print appropriate message when no instruction files are found, then exit."""
    from reporails_cli.core.agents import KNOWN_AGENTS

    agent_type = KNOWN_AGENTS.get(effective_agent)
    hint_file = agent_type.instruction_patterns[0] if agent_type else "AGENTS.md"
    if output_format in ("json", "github"):
        print(json.dumps({"violations": [], "score": 0, "level": "L1"}))
    else:
        con.print("No instruction files found.")
        con.print("Level: L1 (Absent)")
        con.print()
        con.print(f"[dim]Create a {hint_file} to get started.[/dim]")


def _resolve_rules_paths(rules: list[str] | None, con: Console) -> list[Path] | None:
    """Validate and resolve --rules CLI option paths.

    Returns resolved Path list, or None if no --rules were provided.
    Exits with error if any path does not exist.
    """
    if not rules:
        return None
    rules_paths: list[Path] = []
    for r in rules:
        rp = Path(r).resolve()
        if not rp.is_dir():
            con.print(f"[red]Error:[/red] Rules directory not found: {rp}")
            raise typer.Exit(1)
        rules_paths.append(rp)
    return rules_paths


def _compute_file_checks(
    rules_paths: list[Path] | None,
    target: Path,
    instruction_files: list[Path],
    agent: str,
    experimental: bool,
) -> tuple[dict[str, list[str]], list[str], dict[str, str]]:
    """Compute per-file check ID lists (regex + mechanical) and rule titles.

    Returns:
        (file_path -> list of regex check IDs, list of mechanical check IDs, rule_id -> title)
    """
    from reporails_cli.core.engine import build_template_context
    from reporails_cli.core.models import RuleType
    from reporails_cli.core.regex import checks_per_file, get_rule_yml_paths
    from reporails_cli.core.registry import load_rules

    rules = load_rules(
        rules_paths, include_experimental=experimental, project_root=target, agent=agent, scan_root=target
    )
    yml_paths = get_rule_yml_paths(
        {k: v for k, v in rules.items() if v.type in (RuleType.DETERMINISTIC, RuleType.SEMANTIC)}
    )
    context = build_template_context(agent, instruction_files, rules_paths)
    mechanical_ids = [c.id for r in rules.values() if r.type == RuleType.MECHANICAL for c in r.checks]
    titles = {r.id: r.title for r in rules.values()}
    return checks_per_file(yml_paths, target, context, instruction_files), mechanical_ids, titles


def _check_id_to_rule_id(check_id: str) -> str:
    """Extract rule ID from a check ID (e.g., 'CORE.S.0001.check.0001' -> 'CORE:S:0001')."""
    parts = check_id.replace(".", ":").split(":")
    return ":".join(parts[:3]) if len(parts) >= 3 else check_id


def _print_verbose(  # pylint: disable=too-many-arguments,too-many-locals
    rules_paths: list[Path] | None,
    instruction_files: list[Path],
    result: ValidationResult,
    agent: str,
    elapsed_ms: float,
    target: Path,
    experimental: bool,
    con: Console,
) -> None:
    """Print verbose scan diagnostics with per-file check lists."""
    con.print()
    con.print("[dim]Verbose:[/dim]")
    if rules_paths:
        for rp in rules_paths:
            display = str(rp).replace(str(Path.home()), "~")
            con.print(f"[dim]  source: {display}[/dim]")
    con.print(f"[dim]  agent: {agent}, {result.rules_checked} rules, {elapsed_ms:.0f}ms[/dim]")

    file_checks, mechanical_ids, titles = _compute_file_checks(
        rules_paths,
        target,
        instruction_files,
        agent,
        experimental,
    )

    # Group violations by file and rule
    failed_by_file: dict[str, set[str]] = {}
    for v in result.violations:
        viol_path = v.location.rsplit(":", 1)[0] if ":" in v.location else v.location
        failed_by_file.setdefault(viol_path, set()).add(v.rule_id)

    con.print("[dim]  files:[/dim]")
    for ifile in sorted(instruction_files, key=lambda p: str(p)):
        try:
            rel = str(ifile.relative_to(target))
        except ValueError:
            rel = str(ifile)
        regex_ids = file_checks.get(rel, [])
        all_rule_ids = sorted({_check_id_to_rule_id(cid) for cid in regex_ids + mechanical_ids})
        failed = failed_by_file.get(rel, set())
        con.print(f"[dim]    {rel} ({len(all_rule_ids)} rules):[/dim]")
        for rid in all_rule_ids:
            if rid in failed:
                con.print(f"[dim]      [red]FAIL[/red] {rid} {titles.get(rid, '')}[/dim]")
            else:
                con.print(f"[dim]      [green]PASS[/green] {rid} {titles.get(rid, '')}[/dim]")


def _format_output(
    result: ValidationResult,
    delta: ScanDelta,
    output_format: str,
    ascii: bool,
    quiet_semantic: bool,
    elapsed_ms: float,
    con: Console,
) -> None:
    """Dispatch output formatting based on the chosen format."""
    if output_format == "json":
        data = json_formatter.format_result(result, delta)
        data["elapsed_ms"] = round(elapsed_ms, 1)
        print(json.dumps(data, indent=2))
    elif output_format == "compact":
        output = text_formatter.format_compact(result, ascii_mode=ascii, delta=delta)
        print(output)
    elif output_format == "github":
        output = github_formatter.format_result(result, delta)
        print(output)
    elif output_format == "brief":
        data = json_formatter.format_result(result, delta)
        score = data.get("score", 0)
        level = data.get("level", "?")
        violations = len(data.get("violations", []))
        check_mark = "ok" if ascii else "\u2713"
        cross_mark = "x" if ascii else "\u2717"
        status = check_mark if violations == 0 else f"{cross_mark} {violations} violations"
        print(f"ails: {score:.1f}/10 ({level}) {status}")
    else:
        output = text_formatter.format_result(result, ascii_mode=ascii, quiet_semantic=quiet_semantic, delta=delta)
        con.print(output)
        con.print(f"\n[dim]Completed in {elapsed_ms:.0f}ms[/dim]")
