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

from reporails_cli.formatters.text.score import score_color
from reporails_cli.formatters.text.scorecard import SurfaceHealth, _score_bar

console = Console()


def compute_item_scores(
    result: Any,
    ruleset_map: Any,
    project_root: Any = None,
) -> list[SurfaceHealth]:
    """Per-file health scores — name + bar per scanned file.

    Used by capability-listing mode (`ails check <capability>`) so the
    operator sees which item is the worst at a glance. Each item's score is
    the api's per-file `display_score` verbatim; severity counts come from
    that file's findings.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    if ruleset_map is None:
        return []
    root = Path(project_root) if project_root is not None else Path.cwd()

    findings_by_file: dict[str, list[Any]] = {}
    for f in result.findings:
        findings_by_file.setdefault(f.file, []).append(f)
    # Server per-file paths are absolute; normalize to the same project-relative
    # key space as `rel` so the per-file display_score lookup matches.
    analysis_by_file: dict[str, Any] = {normalize_finding_path(fa.file, root): fa for fa in result.per_file_analysis}

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

        # `None` → unscored: either no server analysis for this file, or the server
        # returned no score (zero charged atoms — a non-instruction or empty file).
        score = float(analysis.display_score) if analysis is not None and analysis.display_score is not None else None

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
    # Worst first, alphabetical tiebreak; unscored items sort last (score is None).
    items.sort(key=lambda it: (it.score is None, it.score or 0.0, it.name))
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
    breakdown = _severity_breakdown_markup(s)
    suffix = f"  {breakdown}" if breakdown else ""
    if s.score is None:
        empty = "░" * bar_width
        return f"{label:<{label_w}} [dim]{empty}[/dim]  [dim]not scored[/dim]{suffix}"
    color = score_color(s.score)
    bar = _score_bar(s.score, bar_width, color)
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
        band = "unscored" if s.score is None else score_color(s.score)
        if prev_band is not None and band != prev_band:
            console.print()
        console.print(f"  {_item_cell(s, label_w)}")
        prev_band = band
