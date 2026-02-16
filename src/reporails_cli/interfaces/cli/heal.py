"""Interactive semantic judgment command — ails heal.

Runs validation, then presents each pending JudgmentRequest interactively.
Users evaluate content against criteria and provide pass/fail/skip/dismiss verdicts.
Verdicts are cached immediately after each answer.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from reporails_cli.core.cache import cache_judgments
from reporails_cli.core.engine import run_validation_sync
from reporails_cli.core.fixers import apply_auto_fixes

if TYPE_CHECKING:
    from reporails_cli.core.models import JudgmentRequest
from reporails_cli.formatters.text.heal import format_heal_summary, format_judgment_prompt
from reporails_cli.interfaces.cli.helpers import (
    _resolve_recommended_rules,
    _resolve_rules_paths,
    app,
    console,
)


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
    ascii: bool = typer.Option(
        False,
        "--ascii",
        "-a",
        help="Use ASCII characters only (no Unicode box drawing)",
    ),
    agent: str = typer.Option(
        "claude",
        "--agent",
        help="Agent type for rule overrides and template vars",
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
    """Interactively evaluate pending semantic rules."""
    if not non_interactive and not sys.stdout.isatty():
        console.print("[red]Error:[/red] ails heal requires an interactive terminal.")
        console.print()
        console.print("[dim]Solutions:[/dim]")
        console.print("[dim]  1. Run with --non-interactive flag: ails heal --non-interactive[/dim]")
        console.print("[dim]  2. Use the MCP heal tool (Claude Code): 'use the heal tool'[/dim]")
        console.print("[dim]  3. Run ails heal in your actual terminal[/dim]")
        raise typer.Exit(2)

    target = Path(path).resolve()
    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(2)

    # Resolve rules paths
    rules_paths = _resolve_rules_paths(rules, console)

    # Load project config
    from reporails_cli.core.bootstrap import get_project_config

    project_config = get_project_config(target)

    # Merge exclude_dirs
    merged_excludes: list[str] | None = None
    config_excludes = set(project_config.exclude_dirs)
    cli_excludes = set(exclude_dir or [])
    all_excludes = config_excludes | cli_excludes
    if all_excludes:
        merged_excludes = sorted(all_excludes)

    rules_paths = _resolve_recommended_rules(rules_paths, project_config, "text", console)

    # Run validation to get pending judgment requests
    if non_interactive or not sys.stdout.isatty():
        result = run_validation_sync(
            target,
            rules_paths=rules_paths,
            use_cache=True,
            agent=agent,
            include_experimental=experimental,
            exclude_dirs=merged_excludes,
            record_analytics=False,
        )
    else:
        with console.status("[bold]Scanning for pending semantic rules...[/bold]"):
            result = run_validation_sync(
                target,
                rules_paths=rules_paths,
                use_cache=True,
                agent=agent,
                include_experimental=experimental,
                exclude_dirs=merged_excludes,
                record_analytics=False,
            )

    # Phase 2: Auto-fix deterministic violations
    fixes = apply_auto_fixes(list(result.violations), target)
    if fixes and not non_interactive:
        for fix in fixes:
            console.print(f"[green]Fixed:[/green] {fix.description}")

    requests = list(result.judgment_requests)

    # Non-interactive mode: output JSON and exit
    if non_interactive:
        from reporails_cli.formatters import json as json_formatter

        auto_fixed_data = [
            {
                "rule_id": fix.rule_id,
                "file_path": str(Path(fix.file_path).relative_to(target))
                if Path(fix.file_path).is_relative_to(target)
                else fix.file_path,
                "description": fix.description,
            }
            for fix in fixes
        ]

        judgment_data = [
            {
                "rule_id": jr.rule_id,
                "rule_title": jr.rule_title,
                "question": jr.question,
                "content": jr.content,
                "location": jr.location,
                "criteria": jr.criteria,
                "examples": jr.examples,
                "choices": jr.choices,
                "pass_value": jr.pass_value,
            }
            for jr in requests
        ]

        import json

        output = json_formatter.format_heal_result(auto_fixed_data, judgment_data)
        print(json.dumps(output, indent=2))
        return

    # Interactive mode
    if not requests and not fixes:
        console.print("Nothing to heal. All rules pass or are cached.")
        return
    if not requests:
        console.print(f"\n{format_heal_summary(0, 0, 0, 0, auto_fixed=len(fixes))}")
        return

    console.print(f"\n[bold]{len(requests)} semantic rule(s) pending evaluation.[/bold]\n")

    # Interactive semantic loop
    passed, failed, skipped, dismissed = _run_semantic_loop(requests, target, ascii)

    # Summary
    console.print(f"\n{format_heal_summary(passed, failed, skipped, dismissed, auto_fixed=len(fixes))}")


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

        verdict = _prompt_verdict()

        if verdict == "s":
            skipped += 1
            console.print("[dim]Skipped.[/dim]\n")
            continue

        if verdict == "p":
            _cache_verdict(target, jr, "pass", "Passed via ails heal")
            passed += 1
            console.print("[green]Passed.[/green]\n")
        elif verdict == "f":
            reason = _prompt_reason()
            _cache_verdict(target, jr, "fail", reason)
            failed += 1
            console.print("[red]Failed.[/red]\n")
        elif verdict == "d":
            _cache_verdict(target, jr, "pass", "Dismissed via ails heal")
            dismissed += 1
            console.print("[yellow]Dismissed.[/yellow]\n")

    return passed, failed, skipped, dismissed


def _prompt_verdict() -> str:
    """Prompt for [p]ass / [f]ail / [s]kip / [d]ismiss."""
    while True:
        try:
            choice = input("\n  Your verdict [p/f/s/d]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "s"
        if choice in ("p", "f", "s", "d"):
            return choice
        print("  Please enter p (pass), f (fail), s (skip), or d (dismiss).")


def _prompt_reason() -> str:
    """Prompt for failure reason (required)."""
    while True:
        try:
            reason = input("  Reason: ").strip()
        except (EOFError, KeyboardInterrupt):
            return "No reason provided"
        if reason:
            return reason
        print("  Reason is required for failures.")


def _cache_verdict(target: Path, jr: JudgmentRequest, verdict: str, reason: str) -> None:
    """Cache a single verdict using the existing cache_judgments pipeline."""
    file_path = jr.location.rsplit(":", 1)[0] if ":" in jr.location else jr.location
    # Normalize to relative path
    with contextlib.suppress(ValueError):
        file_path = str(Path(file_path).relative_to(target))

    cache_judgments(
        target,
        [
            {
                "rule_id": jr.rule_id,
                "location": file_path,
                "verdict": verdict,
                "reason": reason,
            }
        ],
    )
