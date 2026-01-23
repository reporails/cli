"""Typer CLI for reporails - lint and score AI instruction files."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import typer
from rich.console import Console

from reporails_cli.core.discover import generate_backbone_yaml, run_discovery, save_backbone
from reporails_cli.core.engine import run_validation_sync
from reporails_cli.core.registry import load_rules
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters import text as text_formatter

app = typer.Typer(
    name="ails",
    help="Lint and score CLAUDE.md files - what ails your repo?",
    no_args_is_help=True,
)
console = Console()


def _is_ci() -> bool:
    """Check if running in CI environment."""
    ci_vars = ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "CIRCLECI")
    return any(os.environ.get(var) for var in ci_vars)


def _is_claude_code() -> bool:
    """Check if running via Claude Code Bash tool (non-TTY, non-CI)."""
    return not sys.stdout.isatty() and not _is_ci()


def _default_format() -> str:
    """Return default format based on environment detection.

    - CI: json (for machine parsing)
    - Claude Code (non-TTY): brief (one-line summary, use MCP for details)
    - Interactive terminal: text (human-readable)
    """
    if _is_ci():
        return "json"
    if _is_claude_code():
        return "brief"
    return "text"


@app.command()
def check(
    path: str = typer.Argument(".", help="Directory to validate"),
    format: str = typer.Option(
        None,
        "--format",
        "-f",
        help="Output format: text, json (auto-detects: text for terminal, json for pipes/CI)",
    ),
    checks_dir: str = typer.Option(
        None,
        "--checks-dir",
        "-c",
        help="Directory containing check rules (defaults to ~/.reporails/checks/)",
    ),
    refresh: bool = typer.Option(
        False,
        "--refresh",
        "-r",
        help="Refresh file map cache (re-scan for CLAUDE.md files)",
    ),
    ascii: bool = typer.Option(
        False,
        "--ascii",
        "-a",
        help="Use ASCII characters only (no Unicode box drawing)",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Exit with code 1 if violations found (for CI pipelines)",
    ),
) -> None:
    """Validate CLAUDE.md files against reporails rules."""
    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    # Resolve checks directory
    checks_path = Path(checks_dir).resolve() if checks_dir else None

    # Run validation with timing
    start_time = time.perf_counter()
    try:
        result = run_validation_sync(target, checks_dir=checks_path, use_cache=not refresh)
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from None
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # Auto-detect format if not specified
    output_format = format if format else _default_format()

    # Format output
    if output_format == "json":
        data = json_formatter.format_result(result)
        data["elapsed_ms"] = round(elapsed_ms, 1)
        output = json.dumps(data, indent=2)
        console.print(output)
    elif output_format == "brief":
        # One-line summary for Claude Code - use MCP for full details
        data = json_formatter.format_result(result)
        score = data.get("score", 0)
        level = data.get("level", "?")
        violations = len(data.get("violations", []))
        check_mark = "ok" if ascii else "✓"
        cross_mark = "x" if ascii else "✗"
        status = check_mark if violations == 0 else f"{cross_mark} {violations} violations"
        console.print(f"ails: {score:.1f}/10 ({level}) {status}")
    else:
        output = text_formatter.format_result(result, ascii_mode=ascii)
        console.print(output)
        console.print(f"\n[dim]Completed in {elapsed_ms:.0f}ms[/dim]")
        # Hint about MCP integration
        if result.judgment_requests:
            console.print(
                "\n[dim]Tip: Add reporails MCP to Claude Code for semantic rule evaluation.[/dim]"
            )

    # Exit with error only in strict mode (for CI pipelines)
    if strict and result.violations:
        raise typer.Exit(1)


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Rule ID (e.g., S1, C2)"),
) -> None:
    """Show detailed information about a specific rule."""
    rules = load_rules()

    # Normalize rule ID
    rule_id_upper = rule_id.upper()

    if rule_id_upper not in rules:
        console.print(f"[red]Error:[/red] Unknown rule: {rule_id}")
        console.print(f"Available rules: {', '.join(sorted(rules.keys()))}")
        raise typer.Exit(1)

    rule = rules[rule_id_upper]
    rule_data = {
        "title": rule.title,
        "category": rule.category.value,
        "type": rule.type.value,
        "level": rule.level,
        "scoring": rule.scoring,
        "detection": rule.detection,
        "antipatterns": [
            {"id": ap.id, "name": ap.name, "severity": ap.severity.value, "points": ap.points}
            for ap in rule.antipatterns
        ],
        "see_also": rule.see_also,
    }

    # Read description from markdown file if available
    if rule.md_path and rule.md_path.exists():
        content = rule.md_path.read_text(encoding="utf-8")
        # Extract content after frontmatter
        parts = content.split("---", 2)
        if len(parts) >= 3:
            rule_data["description"] = parts[2].strip()[:500]

    output = text_formatter.format_rule(rule_id_upper, rule_data)
    console.print(output)


@app.command()
def map(
    path: str = typer.Argument(".", help="Project root to analyze"),
    output: str = typer.Option(
        "text",
        "--output",
        "-o",
        help="Output format: text, yaml, json",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        "-s",
        help="Save backbone.yml to .reporails/ directory",
    ),
) -> None:
    """Map project structure - find instruction files and components.

    Analyzes the project to find:
    - Instruction files (CLAUDE.md, .cursorrules, etc.)
    - Component hierarchy from directory structure
    - File references and dependencies

    Use --save to persist backbone.yml to your repo.
    """
    target = Path(path).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Path not found: {target}")
        raise typer.Exit(1)

    # Run discovery
    start_time = time.perf_counter()
    result = run_discovery(target)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # Generate backbone YAML
    backbone_yaml = generate_backbone_yaml(result)

    # Output based on format
    if output == "yaml":
        console.print(backbone_yaml)
    elif output == "json":
        import yaml as yaml_lib

        data = yaml_lib.safe_load(backbone_yaml)
        console.print(json.dumps(data, indent=2))
    else:
        # Text summary
        console.print(f"[bold]Discovery Results[/bold] - {target.name}")
        console.print("=" * 60)
        console.print()

        # Agents found
        console.print(f"[bold]Agents detected:[/bold] {len(result.agents)}")
        for agent in result.agents:
            console.print(
                f"  - {agent.agent_type.name}: {len(agent.instruction_files)} instruction file(s)"
            )

        console.print()

        # Components
        console.print(f"[bold]Components:[/bold] {len(result.components)}")
        for comp_id, comp in sorted(result.components.items()):
            indent = "  " * comp_id.count(".")
            files = len(comp.instruction_files)
            imports = len(comp.imports)
            console.print(f"  {indent}{comp_id}: {files} file(s), {imports} import(s)")

        console.print()

        # Shared files
        if result.shared_files:
            console.print(f"[bold]Shared files:[/bold] {len(result.shared_files)}")
            for sf in result.shared_files[:10]:
                console.print(f"  - {sf}")
            if len(result.shared_files) > 10:
                console.print(f"  ... and {len(result.shared_files) - 10} more")

        console.print()
        console.print(f"[dim]Total instruction files: {result.total_instruction_files}[/dim]")
        console.print(f"[dim]Total references: {result.total_references}[/dim]")
        console.print(f"[dim]Completed in {elapsed_ms:.0f}ms[/dim]")

    # Save if requested
    if save:
        backbone_path = save_backbone(target, backbone_yaml)
        console.print()
        console.print(f"[green]Saved:[/green] {backbone_path}")


@app.command()
def sync(
    checks_dir: str = typer.Argument(
        "checks",
        help="Local checks directory to sync .md files to",
    ),
) -> None:
    """Sync rule definitions from framework repo (dev command).

    Downloads .md files from reporails/framework to local checks directory.
    Preserves existing .yml files (OpenGrep patterns).

    Typical usage:
        ails sync checks
    """
    from reporails_cli.core.init import sync_rules_to_local

    target = Path(checks_dir).resolve()

    if not target.exists():
        console.print(f"[red]Error:[/red] Directory not found: {target}")
        raise typer.Exit(1)

    console.print(f"Syncing .md files from framework repo to {target}...")

    try:
        count = sync_rules_to_local(target)
        console.print(f"[green]Synced {count} rule definition(s)[/green]")
    except RuntimeError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from None


def main() -> None:
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
