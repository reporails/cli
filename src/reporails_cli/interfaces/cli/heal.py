"""Heal helpers — apply fixes and collect suggestions consumed by `ails check --heal`.

Combines mechanical fixers (formatting, bold, italic) that write atom-level data
with section suggesters (missing sections) that only report what to add —
`--heal`/`--fix`/`--dry-run` never write a section on a user's behalf.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.heal.apply import apply_keyed_heal
from reporails_cli.core.heal.fixers import suggest_missing_sections
from reporails_cli.core.heal.keyed import KeyedResult, put_back_line
from reporails_cli.core.lint.rule_runner import run_content_quality_checks, run_m_probes
from reporails_cli.core.lint.suppression import build_index, is_suppressed
from reporails_cli.core.mapper.skills import skill_membership
from reporails_cli.core.platform.adapters.registry import load_rules
from reporails_cli.core.platform.adapters.rules_query import rule_title
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.contract.json_value import JsonObject, as_str
from reporails_cli.core.platform.dto.models import ClassifiedFile, LocalFinding, Rule, Severity, Violation
from reporails_cli.formatters.json import format_notices

if TYPE_CHECKING:
    from rich.console import Console

    from reporails_cli.core.platform.dto.diagnostics import Notice, RemediationWorkflow
    from reporails_cli.core.platform.dto.ruleset import RulesetMap

logger = logging.getLogger(__name__)


def _apply_keyed_fixes(
    ruleset_map: RulesetMap | None,
    target: Path,
    workflow: RemediationWorkflow | None,
    *,
    dry_run: bool,
    show_progress: bool,
    console: Console,
    allowed_files: list[Path] | None = None,
    suppressed: dict[Path, set[int]] | None = None,
) -> KeyedResult:
    """Fix each finding at the place it names; list the places that need a decision (`apply_keyed_heal`)."""

    if show_progress and ruleset_map is not None and workflow is not None:
        console.print("[bold]Applying fixes...[/bold]")
    return apply_keyed_heal(
        ruleset_map, target, workflow, dry_run=dry_run, allowed_files=allowed_files, suppressed=suppressed
    )


def _collect_section_suggestions(
    target: Path,
    instruction_files: list[Path],
    ruleset_map: RulesetMap | None,
    effective_agent: str,
    *,
    show_progress: bool,
    console: Console,
    exclusions: RunExclusions | None = None,
) -> list[dict[str, str]]:
    """Run M probes + content-quality checks and collect missing-section suggestions.

    Never writes a file — read-only under `--heal`, `--fix`, and `--dry-run` alike,
    so this runs the same way regardless of `dry_run`. Constraints, commands, testing,
    and layered-structure findings are `content_query` checks that need the mapped
    `ruleset_map`; the directory-layout finding is deterministic and needs only the
    file text, so it still surfaces when mapping is unavailable. A finding suppressed
    on its line with an inline `<!-- ails-disable-line <rule> -->` directive — the
    same directive the main report honors — never turns into a suggestion either.
    """

    if show_progress:
        console.print("[bold]Checking for missing sections...[/bold]")
    findings = run_m_probes(
        target,
        instruction_files,
        agent=effective_agent,
        skills=skill_membership(ruleset_map),
        exclusions=exclusions,
    )
    findings += run_content_quality_checks(
        ruleset_map, target, instruction_files, agent=effective_agent, exclusions=exclusions
    )
    findings = _drop_suppressed(findings, target)

    classified_files, rules = _classify_for_suggestions(target, instruction_files, effective_agent, exclusions)
    suggestions = suggest_missing_sections(_findings_to_violations(findings), target, classified_files, rules)
    return [
        {"rule_id": s.rule_id, "file_path": s.file_path, "section": s.section, "description": s.description}
        for s in suggestions
    ]


def _drop_suppressed(findings: list[LocalFinding], target: Path) -> list[LocalFinding]:
    """Drop a finding silenced by an inline `ails-disable-line` directive on its own
    line — the same suppression the main report already honors.
    """

    index = build_index((f.file for f in findings), target)
    if not index:
        return findings
    return [f for f in findings if not is_suppressed(f, index)]


def _findings_to_violations(findings: list[LocalFinding]) -> list[Violation]:
    """Convert `LocalFinding`s to the `Violation` shape the section suggesters read."""

    return [
        Violation(
            rule_id=f.rule,
            rule_title="",
            severity=Severity.MEDIUM,
            message=f.message,
            location=f"{f.file}:{f.line}" if f.line else f.file,
        )
        for f in findings
    ]


def _classify_for_suggestions(
    target: Path, instruction_files: list[Path], agent: str, exclusions: RunExclusions | None = None
) -> tuple[list[ClassifiedFile], dict[str, Rule]]:
    """Classify files and load rules so a section suggestion can name the file the
    rule's own `match.type` is about, instead of wherever the underlying finding
    happened to be pinned (a project-wide content check reports the first matching
    file in sorted path order, which is not necessarily the project's main file).
    """

    generic_scanning = get_project_config(target).generic_scanning
    file_types = load_file_types(agent or "generic")
    classified = classify_files(
        target, instruction_files, file_types, generic_scanning=generic_scanning, exclusions=exclusions
    )
    rules = load_rules(project_root=target, scan_root=target, agent=agent)
    return classified, rules


def _output_heal_results(
    mechanical_results: list[JsonObject],
    suggested: list[dict[str, str]],
    *,
    dry_run: bool,
    elapsed_ms: float,
    output_format: str,
    console: Console,
    notices: tuple[Notice, ...] = (),
    keyed: KeyedResult | None = None,
) -> None:
    """Output heal results in the requested format.

    `keyed` carries the places that need a decision (`decisions`) and the files written back
    unchanged because the result departed from the plan (`put_back`).

    `auto_fixed` carries only what was written (or would be, under `--dry-run`);
    `suggested` carries missing-section findings — reported, never written.
    """
    decisions = keyed.decisions if keyed else []
    put_back = keyed.put_back if keyed else []
    if output_format == "json":
        data: dict[str, object] = {
            "auto_fixed": mechanical_results,
            "suggested": suggested,
            "decisions": decisions,
            "put_back": put_back,
            "notices": format_notices(notices),
            "summary": {
                "auto_fixed_count": len(mechanical_results),
                "suggested_count": len(suggested),
                "decisions_count": len(decisions),
                "put_back_count": len(put_back),
                "dry_run": dry_run,
                "elapsed_ms": elapsed_ms,
            },
        }
        print(json.dumps(data, indent=2))
    else:
        _print_text_result(
            mechanical_results,
            suggested,
            dry_run=dry_run,
            elapsed_ms=elapsed_ms,
            console=console,
            decisions=decisions,
            put_back=put_back,
        )


def _print_decisions(decisions: list[JsonObject], put_back: list[JsonObject], console: Console) -> None:
    """The files put back, then one line per place that needs a decision: `file:line  op  rule title`."""
    for pb in put_back:
        console.print(f"[yellow]{put_back_line(pb)}[/yellow]")
    if not decisions:
        return

    n = len(decisions)
    console.print(f"\n[bold]{n}[/bold] place{'s' if n != 1 else ''} need{'' if n != 1 else 's'} a decision:")
    for d in decisions:
        rule = as_str(d["rule"])
        console.print(f"  {d['file']}:{d['line']}  {d['op']}  {rule_title(rule) or rule}")


def _print_text_result(
    fixes: list[JsonObject],
    suggested: list[dict[str, str]],
    *,
    dry_run: bool,
    elapsed_ms: float,
    console: Console,
    decisions: list[JsonObject] | None = None,
    put_back: list[JsonObject] | None = None,
) -> None:
    """Print human-readable heal results: fixes, put-back files, decisions, then suggested sections.

    The "N fixes applied" / "No fixable issues found." lines count applied fixes
    only; a run with suggestions and no applied fixes says so plainly before
    listing what it found.
    """
    prefix = "[dim]would fix[/dim]" if dry_run else "[green]fixed[/green]"

    if fixes:
        # Group by file
        by_file: dict[str, list[JsonObject]] = {}
        for f in fixes:
            by_file.setdefault(as_str(f.get("file_path", "?")), []).append(f)

        for filepath, file_fixes in sorted(by_file.items()):
            console.print(f"\n[bold]{filepath}[/bold]")
            for fix in file_fixes:
                where = f"L{fix['line']} " if fix.get("line") else ""
                console.print(f"  {prefix} {where}{fix['description']}")

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

    _print_decisions(decisions or [], put_back or [], console)

    if suggested:
        console.print("\n[bold]Sections to add (not written):[/bold]")
        for s in suggested:
            console.print(f"  {s['file_path']} — add {s['section']}: {s['description']}")
