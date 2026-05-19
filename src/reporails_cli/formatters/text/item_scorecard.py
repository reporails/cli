"""Per-item health-bar rendering for capability listings.

`ails check skills` / `ails check rules` / `ails check agents` render one
bar per item via `compute_item_scores` + `render_item_health`. Same
score formula as the per-surface aggregate; one row per file.

Extracted from `scorecard.py` to stay under the 600-line module cap per
`.claude/rules/python-structure.md`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.console import Console

from reporails_cli.formatters.text.scorecard import SurfaceHealth, _score_bar

console = Console()


def compute_item_scores(
    result: Any,
    ruleset_map: Any,
    project_root: Any = None,
) -> list[SurfaceHealth]:
    """Per-file health scores — name + bar per scanned file.

    Used by capability-listing mode (`ails check <capability>`) so the
    operator sees which item is the worst at a glance. Score uses the
    same formula as `compute_surface_scores` but at file granularity:
    per-file compliance band, per-file errors/warnings/infos, per-file
    atom count from `per_file_analysis`.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    if ruleset_map is None:
        return []
    root = Path(project_root) if project_root is not None else Path.cwd()

    findings_by_file: dict[str, list[Any]] = {}
    for f in result.findings:
        findings_by_file.setdefault(f.file, []).append(f)
    analysis_by_file: dict[str, Any] = {fa.file: fa for fa in result.per_file_analysis}

    items: list[SurfaceHealth] = []
    try:
        files = list(ruleset_map.files)
    except (AttributeError, TypeError):
        return []
    for fr in files:
        rel = normalize_finding_path(str(fr.path), root)
        findings = findings_by_file.get(rel, [])
        analysis = analysis_by_file.get(rel)
        n_errors = sum(1 for f in findings if f.severity == "error")
        n_warnings = sum(1 for f in findings if f.severity == "warning")
        n_infos = sum(1 for f in findings if f.severity == "info")
        n_atoms = (analysis.stats.get("atoms", 0) if analysis else 0) or 0
        band = analysis.compliance_band if analysis else ""

        if n_errors + n_warnings + n_infos == 0:
            score = 10.0
        else:
            base = 6.0
            if band:
                base = 8.5 if band == "HIGH" else 5.5 if band == "MODERATE" else 3.0
            denom = max(n_atoms, n_errors + n_warnings + n_infos, 1)
            penalty = min(4.0, (n_errors / denom) * 30) + min(2.0, (n_warnings / denom) * 2)
            score = round(max(0.0, min(10.0, base - penalty)), 1)

        items.append(
            SurfaceHealth(
                name=_display_name_for_path(rel),
                score=score,
                file_count=1,
                finding_count=len(findings),
                errors=n_errors,
                warnings=n_warnings,
                infos=n_infos,
            )
        )
    items.sort(key=lambda it: (it.score, it.name))  # worst first, alphabetical tiebreak
    return items


def _display_name_for_path(rel: str) -> str:
    """Return the per-item display label for a path.

    Skills (`.claude/skills/<name>/SKILL.md`) → `<name>` (parent dir).
    Everything else → file stem so `git.md` → `git`,
    `agent-config-staleness.md` → `agent-config-staleness`.
    """
    p = Path(rel)
    if p.name == "SKILL.md":
        return p.parent.name
    return p.stem


def _item_cell(s: SurfaceHealth, label_w: int, bar_width: int = 15) -> str:
    """Format one item row: '<name>:  ▓▓▓▓░░░░░░░░░░░  4.2  (N: Xe/Yw/Zi)'."""
    label = f"{s.name}:"
    color = "green" if s.score >= 7.0 else "yellow" if s.score >= 4.0 else "red"
    bar = _score_bar(s.score, bar_width, color)
    breakdown = _severity_breakdown_markup(s)
    suffix = f"  {breakdown}" if breakdown else ""
    return f"{label:<{label_w}} {bar}  [{color} bold]{s.score:>4.1f}[/{color} bold]{suffix}"


def _severity_breakdown_markup(s: SurfaceHealth) -> str:
    """Severity-colored breakdown `(N: Xe/Yw/Zi)`; zero severities are omitted."""
    if s.finding_count == 0:
        return ""
    parts = []
    if s.errors:
        parts.append(f"[red]{s.errors}e[/red]")
    if s.warnings:
        parts.append(f"[yellow]{s.warnings}w[/yellow]")
    if s.infos:
        parts.append(f"[dim]{s.infos}i[/dim]")
    inner = "/".join(parts) if parts else ""
    return f"[dim]({s.finding_count}: {inner})[/dim]" if inner else f"[dim]({s.finding_count})[/dim]"


def render_item_health(items: list[SurfaceHealth]) -> None:
    """Render per-item health bars one per line with breathing room.

    Adds a blank line between severity bands (red → yellow → green) so
    the eye naturally chunks the list into "needs attention", "moderate",
    "healthy" clusters.
    """
    if not items:
        return
    label_w = max(len(s.name) for s in items) + 2  # name + ": "
    console.print()
    prev_band: str | None = None
    for s in items:
        band = "red" if s.score < 4.0 else "yellow" if s.score < 7.0 else "green"
        if prev_band is not None and band != prev_band:
            console.print()
        console.print(f"  {_item_cell(s, label_w)}")
        prev_band = band
