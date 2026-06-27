"""Heal helpers — apply auto-fixes consumed by `ails check --heal`.

Combines additive fixers (missing sections) with mechanical fixers
(formatting, bold, italic, ordering) that operate on atom-level data.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def _apply_mechanical_fixes(
    ruleset_map: Any,
    target: Path,
    dry_run: bool,
    show_progress: bool,
    console: Any,
    allowed_files: list[Path] | None = None,
    suppressed: dict[Path, set[int]] | None = None,
) -> list[dict[str, Any]]:
    """Apply atom-level mechanical fixes. Returns list of fix dicts.

    `allowed_files` bounds the write set to the scoped heal files; a mapped file
    outside it (e.g. an in-tree symlink whose real path escapes the target) is skipped.
    `suppressed` maps a resolved file path to the line numbers the author annotated
    with an `ails-disable-line` directive; heal leaves those lines unmodified.
    """
    if ruleset_map is None:
        return []
    if show_progress:
        console.print("[bold]Applying mechanical fixes...[/bold]")
    from reporails_cli.core.heal.mechanical_fixers import apply_mechanical_fixes

    allowed = {p.resolve() for p in allowed_files} if allowed_files is not None else None
    mech_fixes = apply_mechanical_fixes(
        ruleset_map, target, dry_run=dry_run, allowed_files=allowed, suppressed=suppressed
    )
    return [
        {"rule_id": mf.fix_type, "file_path": mf.file_path, "line": mf.line, "description": mf.description}
        for mf in mech_fixes
    ]


def _apply_additive_fixes(
    target: Path,
    instruction_files: list[Path],
    effective_agent: str,
    dry_run: bool,
    show_progress: bool,
    console: Any,
) -> list[dict[str, Any]]:
    """Run M probes and apply additive fixes (missing sections)."""
    from reporails_cli.core.heal.fixers import apply_auto_fixes as _apply_auto_fixes
    from reporails_cli.core.lint.rule_runner import run_m_probes
    from reporails_cli.core.platform.dto.models import Severity, Violation

    if show_progress:
        console.print("[bold]Running structural checks...[/bold]")
    m_findings = run_m_probes(target, instruction_files, agent=effective_agent)

    if dry_run:
        return []

    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
    violations = [
        Violation(
            rule_id=f.rule,
            rule_title="",
            severity=sev_map.get(f.severity, Severity.MEDIUM),
            message=f.message,
            location=f"{f.file}:{f.line}" if f.line else f.file,
        )
        for f in m_findings
    ]
    add_fixes = _apply_auto_fixes(violations, target)
    return [{"rule_id": af.rule_id, "file_path": af.file_path, "description": af.description} for af in add_fixes]


def _output_heal_results(
    all_fixes: list[dict[str, Any]],
    mechanical_results: list[dict[str, Any]],
    additive_results: list[dict[str, Any]],
    dry_run: bool,
    elapsed_ms: float,
    output_format: str,
    console: Any,
) -> None:
    """Output heal results in the requested format."""
    if output_format == "json":
        data = {
            "auto_fixed": all_fixes,
            "summary": {
                "auto_fixed_count": len(all_fixes),
                "mechanical_count": len(mechanical_results),
                "additive_count": len(additive_results),
                "dry_run": dry_run,
                "elapsed_ms": elapsed_ms,
            },
        }
        print(json.dumps(data, indent=2))
    else:
        _print_text_result(all_fixes, dry_run, elapsed_ms, console)


def _print_text_result(
    fixes: list[dict[str, Any]],
    dry_run: bool,
    elapsed_ms: float,
    console: Any,
) -> None:
    """Print human-readable heal results."""
    prefix = "[dim]would fix[/dim]" if dry_run else "[green]fixed[/green]"

    if not fixes:
        console.print("[green]No fixable issues found.[/green]")
        console.print(f"[dim]{elapsed_ms:.0f}ms[/dim]")
        return

    # Group by file
    by_file: dict[str, list[dict[str, Any]]] = {}
    for f in fixes:
        by_file.setdefault(f.get("file_path", "?"), []).append(f)

    for filepath, file_fixes in sorted(by_file.items()):
        console.print(f"\n[bold]{filepath}[/bold]")
        for fix in file_fixes:
            line = fix.get("line", "")
            line_str = f"L{line} " if line else ""
            console.print(f"  {prefix} {line_str}{fix['description']}")

    console.print(
        f"\n[bold]{len(fixes)}[/bold] fix{'es' if len(fixes) != 1 else ''} "
        + ("(dry run)" if dry_run else "applied")
        + f" in {elapsed_ms:.0f}ms"
    )
