"""Interactive heal command — ails heal.

Three-phase interactive flow:
1. Auto-fixable violations (apply/skip/dismiss)
2. Non-fixable violations requiring manual attention (dismiss/skip)
3. Semantic rules pending evaluation (pass/fail/skip/dismiss)

Verdicts and dismissals are cached immediately after each answer.
"""  # pylint: disable=too-many-lines

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from reporails_cli.core.engine import run_validation_sync
from reporails_cli.core.fixers import apply_single_fix, describe_fix, partition_violations

if TYPE_CHECKING:
    from reporails_cli.core.models import JudgmentRequest, Violation
from reporails_cli.formatters.text.heal import (
    extract_violation_snippet,
    format_fixable_violation_prompt,
    format_heal_summary,
    format_judgment_prompt,
    format_violation_prompt,
)
from reporails_cli.interfaces.cli.heal_prompts import (
    cache_verdict,
    cache_violation_dismissal,
    prompt_fix_action,
    prompt_reason,
    prompt_verdict,
    prompt_violation_action,
    run_non_interactive,
)
from reporails_cli.interfaces.cli.helpers import (
    _resolve_recommended_rules,
    _resolve_rules_paths,
    _validate_agent,
    app,
    console,
)


def _is_interactive() -> bool:
    """Check if stdout is an interactive terminal."""
    return sys.stdout.isatty()


@app.command()
def heal(  # pylint: disable=too-many-locals
    path: str = typer.Argument(".", help="Project root to heal"),
    rules: list[str] = typer.Option(  # noqa: B008
        None,
        "--rules",
        "-r",
        help="Directory containing rules (repeatable).",
    ),
    exclude_dir: list[str] = typer.Option(  # noqa: B008
        None,
        "--exclude-dir",
        "-x",
        help="Directory name to exclude from scanning (repeatable).",
    ),
    refresh: bool = typer.Option(
        False,
        "--refresh",
        help="Refresh file map cache (re-scan for instruction files)",
    ),
    ascii: bool = typer.Option(
        False,
        "--ascii",
        "-a",
        help="Use ASCII characters only (no Unicode box drawing)",
    ),
    agent: str = typer.Option(
        "",
        "--agent",
        help="Agent type for rule overrides and template vars (e.g., claude, cursor, codex)",
    ),
    experimental: bool = typer.Option(
        False,
        "--experimental",
        help="Include experimental rules",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        "-n",
        help="Non-interactive mode: auto-fix and output JSON (for scripts/agents)",
    ),
) -> None:
    """Interactively heal violations and evaluate semantic rules."""
    if not non_interactive and not _is_interactive():
        console.print("[red]Error:[/red] ails heal requires an interactive terminal.")
        console.print()
        console.print("[dim]Solutions:[/dim]")
        console.print("[dim]  1. Run with --non-interactive flag: ails heal --non-interactive[/dim]")
        console.print("[dim]  2. Use the MCP heal tool (Claude Code): 'use the heal tool'[/dim]")
        console.print("[dim]  3. Run ails heal in your actual terminal[/dim]")
        raise typer.Exit(2)

    # Normalize and validate agent
    agent = _validate_agent(agent, console)

    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(2)

    # Resolve rules paths
    rules_paths = _resolve_rules_paths(rules, console)

    # Load project config
    from reporails_cli.core.bootstrap import get_project_config

    project_config = get_project_config(target)

    # Resolve effective agent: CLI flag > config default_agent > engine defaults to generic
    if not agent and project_config.default_agent:
        agent = _validate_agent(project_config.default_agent, console)

    # Merge exclude_dirs
    merged_excludes: list[str] | None = None
    config_excludes = set(project_config.exclude_dirs)
    cli_excludes = set(exclude_dir or [])
    all_excludes = config_excludes | cli_excludes
    if all_excludes:
        merged_excludes = sorted(all_excludes)

    rules_paths = _resolve_recommended_rules(rules_paths, project_config, "text", console)

    # Run validation
    if non_interactive or not _is_interactive():
        result = run_validation_sync(
            target,
            rules_paths=rules_paths,
            use_cache=not refresh,
            agent=agent,
            include_experimental=experimental,
            exclude_dirs=merged_excludes,
            record_analytics=False,
        )
    else:
        with console.status("[bold]Scanning for violations and pending rules...[/bold]"):
            result = run_validation_sync(
                target,
                rules_paths=rules_paths,
                use_cache=not refresh,
                agent=agent,
                include_experimental=experimental,
                exclude_dirs=merged_excludes,
                record_analytics=False,
            )

    # Partition violations
    fixable, non_fixable = partition_violations(list(result.violations))
    requests = list(result.judgment_requests)

    # Non-interactive mode: auto-fix and output JSON
    if non_interactive:
        run_non_interactive(fixable, non_fixable, requests, target)
        return

    # Interactive mode
    _run_interactive(fixable, non_fixable, requests, target, ascii)


def _run_interactive(
    fixable: list[Violation],
    non_fixable: list[Violation],
    requests: list[JudgmentRequest],
    target: Path,
    ascii_mode: bool,
) -> None:
    """Interactive three-phase heal flow."""
    if not (fixable or non_fixable or requests):
        console.print("Nothing to heal. All rules pass or are cached.")
        return

    applied = 0
    violations_dismissed = 0
    violations_skipped = 0

    # Phase 1: Auto-fixable violations
    if fixable:
        console.print(f"\n[bold]Phase 1: {len(fixable)} auto-fixable violation(s)[/bold]\n")
        applied, vd, vs = _run_fixable_loop(fixable, target, ascii_mode)
        violations_dismissed += vd
        violations_skipped += vs

    # Phase 2: Non-fixable violations
    if non_fixable:
        console.print(f"\n[bold]Phase 2: {len(non_fixable)} violation(s) requiring manual attention[/bold]\n")
        vd, vs = _run_violation_loop(non_fixable, target, ascii_mode)
        violations_dismissed += vd
        violations_skipped += vs

    # Phase 3: Semantic rules
    sem = (0, 0, 0, 0)
    if requests:
        console.print(f"\n[bold]Phase 3: {len(requests)} semantic rule(s) pending evaluation[/bold]\n")
        sem = _run_semantic_loop(requests, target, ascii_mode)

    # Summary
    summary = format_heal_summary(
        sem[0],
        sem[1],
        sem[2],
        sem[3],
        auto_fixed=applied,
        violations_dismissed=violations_dismissed,
        violations_skipped=violations_skipped,
    )
    console.print(f"\n{summary}")
    console.print("\n[dim]Run 'ails check' to see your updated score.[/dim]")


def _run_fixable_loop(
    fixable: list[Violation],
    target: Path,
    ascii_mode: bool,
) -> tuple[int, int, int]:
    """Run interactive fixable violation loop. Returns (applied, dismissed, skipped)."""
    applied = 0
    dismissed = 0
    skipped = 0

    for i, v in enumerate(fixable, 1):
        fix_desc = describe_fix(v) or "Apply auto-fix"
        prompt_text = format_fixable_violation_prompt(
            v,
            fix_desc,
            i,
            len(fixable),
            ascii_mode=ascii_mode,
        )
        console.print(prompt_text)

        action = prompt_fix_action()
        if action == "a":
            fix_result = apply_single_fix(v, target)
            if fix_result:
                applied += 1
                console.print(f"[green]Applied:[/green] {fix_result.description}\n")
            else:
                console.print("[yellow]Fix had no effect (already satisfied).[/yellow]\n")
        elif action == "d":
            cache_violation_dismissal(target, v)
            dismissed += 1
            console.print("[yellow]Dismissed.[/yellow]\n")
        else:
            skipped += 1
            console.print("[dim]Skipped.[/dim]\n")

    return applied, dismissed, skipped


def _run_violation_loop(
    non_fixable: list[Violation],
    target: Path,
    ascii_mode: bool,
) -> tuple[int, int]:
    """Run interactive violation loop. Returns (dismissed, skipped)."""
    dismissed = 0
    skipped = 0

    for i, v in enumerate(non_fixable, 1):
        snippet = extract_violation_snippet(v.location, target)
        prompt_text = format_violation_prompt(
            v,
            i,
            len(non_fixable),
            snippet=snippet,
            ascii_mode=ascii_mode,
        )
        console.print(prompt_text)

        action = prompt_violation_action()
        if action == "d":
            cache_violation_dismissal(target, v)
            dismissed += 1
            console.print("[yellow]Dismissed.[/yellow]\n")
        else:
            skipped += 1
            console.print("[dim]Skipped.[/dim]\n")

    return dismissed, skipped


def _run_semantic_loop(
    requests: list[JudgmentRequest],
    target: Path,
    ascii_mode: bool,
) -> tuple[int, int, int, int]:
    """Run interactive semantic evaluation loop. Returns (passed, failed, skipped, dismissed)."""
    passed = 0
    failed = 0
    skipped = 0
    dismissed = 0

    for i, jr in enumerate(requests, 1):
        prompt_text = format_judgment_prompt(jr, i, len(requests), ascii_mode=ascii_mode)
        console.print(prompt_text)

        verdict = prompt_verdict()

        if verdict == "s":
            skipped += 1
            console.print("[dim]Skipped.[/dim]\n")
            continue

        if verdict == "p":
            cache_verdict(target, jr, "pass", "Passed via ails heal")
            passed += 1
            console.print("[green]Passed.[/green]\n")
        elif verdict == "f":
            reason = prompt_reason()
            cache_verdict(target, jr, "fail", reason)
            failed += 1
            console.print("[red]Failed.[/red]\n")
        elif verdict == "d":
            cache_verdict(target, jr, "pass", "Dismissed via ails heal")
            dismissed += 1
            console.print("[yellow]Dismissed.[/yellow]\n")

    return passed, failed, skipped, dismissed
