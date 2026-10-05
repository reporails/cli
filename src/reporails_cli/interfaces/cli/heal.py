"""Heal helpers — apply fixes and collect suggestions consumed by `ails check --heal`.

Combines mechanical fixers (formatting, bold, italic) that write atom-level data
with section suggesters (missing sections) that only report what to add —
`--heal`/`--fix`/`--dry-run` never write a section on a user's behalf.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import safe_resolve

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

    allowed = {safe_resolve(p) for p in allowed_files} if allowed_files is not None else None
    mech_fixes = apply_mechanical_fixes(
        ruleset_map, target, dry_run=dry_run, allowed_files=allowed, suppressed=suppressed
    )
    return [
        {"rule_id": mf.fix_type, "file_path": mf.file_path, "line": mf.line, "description": mf.description}
        for mf in mech_fixes
    ]


def _collect_section_suggestions(
    target: Path,
    instruction_files: list[Path],
    ruleset_map: Any,
    effective_agent: str,
    show_progress: bool,
    console: Any,
) -> list[dict[str, Any]]:
    """Run M probes + content-quality checks and collect missing-section suggestions.

    Never writes a file — read-only under `--heal`, `--fix`, and `--dry-run` alike,
    so this runs the same way regardless of `dry_run`. Constraints, commands, testing,
    and layered-structure findings are `content_query` checks that need the mapped
    `ruleset_map`; the directory-layout finding is deterministic and needs only the
    file text, so it still surfaces when mapping is unavailable. A finding suppressed
    on its line with an inline `<!-- ails-disable-line <rule> -->` directive — the
    same directive the main report honors — never turns into a suggestion either.
    """
    from reporails_cli.core.heal.fixers import suggest_missing_sections
    from reporails_cli.core.lint.rule_runner import run_content_quality_checks, run_m_probes
    from reporails_cli.core.mapper.skills import skill_membership

    if show_progress:
        console.print("[bold]Checking for missing sections...[/bold]")
    findings = run_m_probes(target, instruction_files, agent=effective_agent, skills=skill_membership(ruleset_map))
    findings += run_content_quality_checks(ruleset_map, target, instruction_files, agent=effective_agent)
    findings = _drop_suppressed(findings, target)

    violations = _findings_to_violations(findings)
    classified_files, rules = _classify_for_suggestions(target, instruction_files, effective_agent)
    suggestions = suggest_missing_sections(violations, target, classified_files, rules)
    return [
        {"rule_id": s.rule_id, "file_path": s.file_path, "section": s.section, "description": s.description}
        for s in suggestions
    ]


def _drop_suppressed(findings: list[Any], target: Path) -> list[Any]:
    """Drop a finding silenced by an inline `ails-disable-line` directive on its own
    line — the same suppression the main report already honors.
    """
    from reporails_cli.core.lint.suppression import build_index, is_suppressed

    index = build_index((f.file for f in findings), target)
    if not index:
        return findings
    return [f for f in findings if not is_suppressed(f, index)]


def _findings_to_violations(findings: list[Any]) -> list[Any]:
    """Convert `LocalFinding`s to the `Violation` shape the section suggesters read."""
    from reporails_cli.core.platform.dto.models import Severity, Violation

    sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}
    return [
        Violation(
            rule_id=f.rule,
            rule_title="",
            severity=sev_map.get(f.severity, Severity.MEDIUM),
            message=f.message,
            location=f"{f.file}:{f.line}" if f.line else f.file,
        )
        for f in findings
    ]


def _classify_for_suggestions(
    target: Path, instruction_files: list[Path], agent: str
) -> tuple[list[Any], dict[str, Any]]:
    """Classify files and load rules so a section suggestion can name the file the
    rule's own `match.type` is about, instead of wherever the underlying finding
    happened to be pinned (a project-wide content check reports the first matching
    file in sorted path order, which is not necessarily the project's main file).
    """
    from reporails_cli.core.classify import classify_files, load_file_types
    from reporails_cli.core.platform.adapters.registry import load_rules
    from reporails_cli.core.platform.config.config import get_project_config

    try:
        generic_scanning = get_project_config(target).generic_scanning
    except (OSError, ValueError):
        generic_scanning = False
    file_types = load_file_types(agent or "generic")
    classified = classify_files(target, instruction_files, file_types, generic_scanning=generic_scanning)
    rules = load_rules(project_root=target, scan_root=target, agent=agent)
    return classified, rules


def _output_heal_results(
    mechanical_results: list[dict[str, Any]],
    suggested: list[dict[str, Any]],
    dry_run: bool,
    elapsed_ms: float,
    output_format: str,
    console: Any,
) -> None:
    """Output heal results in the requested format.

    `auto_fixed` carries only what was written (or would be, under `--dry-run`);
    `suggested` carries missing-section findings — reported, never written.
    """
    if output_format == "json":
        data = {
            "auto_fixed": mechanical_results,
            "suggested": suggested,
            "summary": {
                "auto_fixed_count": len(mechanical_results),
                "suggested_count": len(suggested),
                "dry_run": dry_run,
                "elapsed_ms": elapsed_ms,
            },
        }
        print(json.dumps(data, indent=2))
    else:
        _print_text_result(mechanical_results, suggested, dry_run, elapsed_ms, console)


def _print_text_result(
    fixes: list[dict[str, Any]],
    suggested: list[dict[str, Any]],
    dry_run: bool,
    elapsed_ms: float,
    console: Any,
) -> None:
    """Print human-readable heal results: applied fixes, then suggested sections.

    The "N fixes applied" / "No fixable issues found." lines count applied fixes
    only; a run with suggestions and no applied fixes says so plainly before
    listing what it found.
    """
    prefix = "[dim]would fix[/dim]" if dry_run else "[green]fixed[/green]"

    if fixes:
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
    elif suggested:
        console.print("[green]No fixes applied.[/green]")
        console.print(f"[dim]{elapsed_ms:.0f}ms[/dim]")
    else:
        console.print("[green]No fixable issues found.[/green]")
        console.print(f"[dim]{elapsed_ms:.0f}ms[/dim]")

    if suggested:
        console.print("\n[bold]Sections to add (not written):[/bold]")
        for s in suggested:
            console.print(f"  {s['file_path']} — add {s['section']}: {s['description']}")
