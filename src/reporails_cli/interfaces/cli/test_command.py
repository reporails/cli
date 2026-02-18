"""CLI command: ails test — validate rules against their own fixtures."""
# pylint: disable=too-many-lines

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import typer

from reporails_cli.interfaces.cli.helpers import app, console


@app.command("test")
def test_rules(  # pylint: disable=too-many-arguments,too-many-locals
    path: str = typer.Argument(None, help="Filter by path prefix (e.g., core/structure/)"),
    rule: str = typer.Option(
        None,
        "--rule",
        "-r",
        help="Run single rule by coordinate (e.g., CORE:S:0001)",
    ),
    agent: str = typer.Option(
        "claude",
        "--agent",
        "-a",
        help="Agent config for var resolution (default: claude)",
    ),
    rules_root: str = typer.Option(
        ".",
        "--rules-root",
        help="Primary rules directory (default: .)",
    ),
    package: list[str] = typer.Option(  # noqa: B008
        None,
        "--package",
        "-p",
        help="Additional package roots (repeatable)",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show per-check details for passing rules",
    ),
    format: str = typer.Option(
        "text",
        "--format",
        "-f",
        help="Output format: text (default), json",
    ),
    fail_on_not_impl: bool = typer.Option(
        False,
        "--fail-on-not-impl",
        help="Treat not_implemented rules as failures (for CI)",
    ),
    score: bool = typer.Option(
        False,
        "--score",
        help="Show quality delta between pass/fail fixtures",
    ),
    export_baseline: str = typer.Option(
        None,
        "--export-baseline",
        help="Export expected-rules baseline to JSON file",
    ),
    coverage_baseline: str = typer.Option(
        None,
        "--coverage-baseline",
        help="Check rules against expected-rules baseline JSON file",
    ),
) -> None:
    """Validate rules against their own test fixtures."""
    root = Path(rules_root).resolve()
    if not root.exists():
        console.print(f"[red]Error:[/red] Rules root not found: {root}")
        raise typer.Exit(2)

    package_roots = [Path(p).resolve() for p in (package or [])]

    if export_baseline:
        _run_export_baseline(root, package_roots, agent, export_baseline)
        return

    if coverage_baseline:
        _run_coverage_check(root, package_roots, agent, coverage_baseline)
        return

    if score:
        _run_score_mode(root, path, rule, package_roots, agent, format)
        return

    from reporails_cli.core.harness import HarnessStatus, run_harness

    results = run_harness(
        root,
        filter_path=path,
        filter_rule=rule,
        package_roots=package_roots,
        agent=agent,
    )

    if not results:
        console.print("[red]No rules found.[/red]")
        raise typer.Exit(1)

    if format == "json":
        _print_json(results)
    else:
        _print_text(results, verbose)

    # Determine exit code
    failures = [r for r in results if r.status == HarnessStatus.FAILED]
    if fail_on_not_impl:
        failures += [r for r in results if r.status == HarnessStatus.NOT_IMPLEMENTED]

    if failures:
        raise typer.Exit(1)


def _run_export_baseline(
    root: Path,
    package_roots: list[Path],
    agent: str,
    output_path: str,
) -> None:
    """Export expected-rules baseline to JSON."""
    from reporails_cli.core.harness import export_baseline

    entries = export_baseline(root, package_roots=package_roots, agent=agent)
    data = [{"rule_id": e.rule_id, "slug": e.slug, "has_fixtures": e.has_fixtures} for e in entries]

    Path(output_path).write_text(json.dumps(data, indent=2))
    console.print(f"Exported {len(data)} rules to {output_path}")


def _run_coverage_check(
    root: Path,
    package_roots: list[Path],
    agent: str,
    baseline_path: str,
) -> None:
    """Check rules against expected-rules baseline."""
    from reporails_cli.core.harness import check_coverage

    bp = Path(baseline_path)
    if not bp.exists():
        console.print(f"[red]Error:[/red] Baseline not found: {baseline_path}")
        raise typer.Exit(2)

    baseline = json.loads(bp.read_text())
    gaps = check_coverage(root, baseline, package_roots=package_roots, agent=agent)

    if not gaps:
        console.print(f"Coverage OK: all {len(baseline)} expected rules present")
        return

    console.print(f"[red]Coverage gaps: {len(gaps)} rule(s) missing or degraded[/red]")
    for gap in gaps:
        console.print(f"  {gap.rule_id}: {gap.reason}")

    raise typer.Exit(1)


def _run_score_mode(
    root: Path,
    filter_path: str | None,
    filter_rule: str | None,
    package_roots: list[Path],
    agent: str,
    format: str,
) -> None:
    """Run effectiveness scoring mode."""
    from reporails_cli.core.harness import score_rules

    deltas = score_rules(
        root,
        filter_path=filter_path,
        filter_rule=filter_rule,
        package_roots=package_roots,
        agent=agent,
    )

    if not deltas:
        console.print("[red]No rules with both pass and fail fixtures found.[/red]")
        return

    if format == "json":
        _print_score_json(deltas)
    else:
        _print_score_text(deltas)


def _print_score_text(deltas: list[Any]) -> None:
    """Print human-readable score deltas."""
    console.print(f"Effectiveness: {len(deltas)} rule(s) scored")
    console.print("-" * 55)
    console.print(f"  {'Rule':<20} {'Pass':>6} {'Fail':>6} {'Delta':>6}")
    console.print("-" * 55)

    flagged = 0
    for d in sorted(deltas, key=lambda x: x.delta, reverse=True):
        flag = " *" if d.delta < 0.5 else ""
        if d.delta < 0.5:
            flagged += 1
        console.print(f"  {d.rule_id:<20} {d.pass_score:>6.1f} {d.fail_score:>6.1f} {d.delta:>+6.1f}{flag}")

    console.print()
    if flagged:
        console.print(f"  * {flagged} rule(s) with delta < 0.5 — candidates for review")
        console.print()


def _print_score_json(deltas: list[Any]) -> None:
    """Print JSON score deltas."""
    data = {
        d.rule_id: {
            "slug": d.slug,
            "pass_score": d.pass_score,
            "fail_score": d.fail_score,
            "delta": d.delta,
        }
        for d in deltas
    }
    print(json.dumps(data, indent=2))


def _print_text(results: list[Any], verbose: bool) -> None:
    """Print human-readable test results."""
    from reporails_cli.core.harness import HarnessStatus

    passed = [r for r in results if r.status == HarnessStatus.PASSED]
    failed = [r for r in results if r.status == HarnessStatus.FAILED]
    not_impl = [r for r in results if r.status == HarnessStatus.NOT_IMPLEMENTED]
    no_fix = [r for r in results if r.status == HarnessStatus.NO_FIXTURES]
    skipped = [r for r in results if r.status == HarnessStatus.SKIPPED]

    # Progress line
    icons = {
        HarnessStatus.PASSED: ".",
        HarnessStatus.FAILED: "F",
        HarnessStatus.NOT_IMPLEMENTED: "-",
        HarnessStatus.NO_FIXTURES: "?",
        HarnessStatus.SKIPPED: "S",
    }
    progress = "".join(icons.get(r.status, "?") for r in results)
    console.print(f"Discovered {len(results)} rule(s)")
    console.print(progress)
    console.print()

    # Failures
    if failed:
        console.print("[red bold]FAILURES:[/red bold]")
        console.print("-" * 40)
        for r in failed:
            console.print(f"  [red]FAIL[/red]  {r.rule_id} ({r.slug})")
            for run in r.check_runs:
                status = "[green]PASS[/green]" if run.passed else "[red]FAIL[/red]"
                console.print(f"        [{status}] {run.check_id} ({run.check_type}, {run.fixture}): {run.message}")
            for msg in r.messages:
                console.print(f"        {msg}")
        console.print()

    # Passes (verbose only)
    if passed and verbose:
        console.print("[green]PASSES:[/green]")
        console.print("-" * 40)
        for r in passed:
            console.print(f"  [green]PASS[/green]  {r.rule_id} ({r.slug})")
            for run in r.check_runs:
                console.print(
                    f"        [green]PASS[/green] {run.check_id} ({run.check_type}, {run.fixture}): {run.message}"
                )
        console.print()

    # Summary
    console.print("[bold]SUMMARY:[/bold]")
    console.print("-" * 40)
    console.print(f"  Passed:          {len(passed)}")
    console.print(f"  Failed:          {len(failed)}")
    console.print(f"  Not implemented: {len(not_impl)}")
    console.print(f"  No fixtures:     {len(no_fix)}")
    if skipped:
        console.print(f"  Skipped:         {len(skipped)}")
    console.print(f"  Total:           {len(results)}")
    console.print()

    if not_impl:
        console.print(f"Not implemented ({len(not_impl)}):")
        for r in not_impl:
            console.print(f"  - {r.rule_id} {r.slug}")
        console.print()


def _print_json(results: list[Any]) -> None:
    """Print JSON test results."""
    from reporails_cli.core.harness import HarnessStatus

    data = {
        "rules": [
            {
                "rule_id": r.rule_id,
                "slug": r.slug,
                "title": r.title,
                "status": r.status,
                "check_runs": [
                    {
                        "check_id": cr.check_id,
                        "check_type": cr.check_type,
                        "fixture": cr.fixture,
                        "passed": cr.passed,
                        "message": cr.message,
                    }
                    for cr in r.check_runs
                ],
                "messages": r.messages,
            }
            for r in results
        ],
        "summary": {
            "passed": sum(1 for r in results if r.status == HarnessStatus.PASSED),
            "failed": sum(1 for r in results if r.status == HarnessStatus.FAILED),
            "not_implemented": sum(1 for r in results if r.status == HarnessStatus.NOT_IMPLEMENTED),
            "no_fixtures": sum(1 for r in results if r.status == HarnessStatus.NO_FIXTURES),
            "total": len(results),
        },
    }
    print(json.dumps(data, indent=2))
