"""Scorecard rendering for text-mode CLI output.

Renders the bottom summary section: score bar, scope, findings, compliance, CTA.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from rich.console import Console

from reporails_cli.formatters.text.display_constants import (
    HRULE,
    RULE_CATEGORY_MAP,
    classify_file,
    finding_category,
    get_term_width,
)

console = Console()


# ── Score computation ─────────────────────────────────────────────────


def _hint_totals(result: Any) -> tuple[int, int]:
    """Sum hint error and warning counts from result.hints."""
    if not result.hints:
        return 0, 0
    errors = sum(getattr(h, "error_count", 0) for h in result.hints)
    warnings = sum(getattr(h, "warning_count", 0) for h in result.hints)
    return errors, warnings


def compute_score(result: Any, has_quality: bool, n_atoms: int = 0) -> float:
    """Compute a 0-10 display score from compliance band + finding severity.

    Band sets the base range, severity rates adjust within it.
    Rates are relative to instruction count so larger projects
    aren't penalized for having more atoms to check.
    """
    s = result.stats
    hint_errors, hint_warnings = _hint_totals(result)
    total_errors = s.errors + hint_errors
    total_warnings = s.warnings + hint_warnings

    if total_errors + total_warnings + s.infos == 0:
        return 10.0

    base = 6.0
    if has_quality:
        band = result.quality.compliance_band
        base = 8.5 if band == "HIGH" else 5.5 if band == "MODERATE" else 3.0

    denom = max(n_atoms, total_errors + total_warnings + s.infos, 1)
    penalty = min(4.0, (total_errors / denom) * 30) + min(2.0, (total_warnings / denom) * 2)

    return float(round(max(0.0, min(10.0, base - penalty)), 1))


def print_score_line(score: float, tw: int) -> None:
    """Print score with progress bar."""
    bar_width = min(40, tw - 26)
    filled = round(bar_width * score / 10)
    bar = "\u2593" * filled + "\u2591" * (bar_width - filled)
    color = "green" if score >= 7.0 else "yellow" if score >= 4.0 else "red"
    console.print(f"  Score: [{color} bold]{score:.1f}[/{color} bold] / 10  [dim]{bar}[/dim]")


# ── Surface health ────────────────────────────────────────────────────

_SURFACE_NAMES = {"main": "Main", "rule": "Rules", "skill": "Skills", "agent": "Agents", "memory": "Memory"}
_SURFACE_ORDER = ["main", "rule", "skill", "agent", "memory"]


@dataclass
class SurfaceHealth:
    """Per-surface health score for the scorecard."""

    name: str
    score: float
    file_count: int
    finding_count: int
    errors: int = 0
    warnings: int = 0
    infos: int = 0


def compute_surface_scores(
    result: Any,
    ruleset_map: Any = None,
) -> list[SurfaceHealth]:
    """Compute per-surface health scores from combined result.

    When ruleset_map is provided, file counts come from the mapper's
    discovery (all scanned files), not just files with findings.
    """
    # Count files per surface from ruleset_map (authoritative file list)
    surface_file_counts: dict[str, int] = {}
    if ruleset_map is not None:
        try:
            for fr in ruleset_map.files:
                tag = classify_file(fr.path).split(":")[0]
                surface_file_counts[tag] = surface_file_counts.get(tag, 0) + 1
        except (AttributeError, TypeError):
            pass

    # Group findings by surface
    surface_findings: dict[str, list[Any]] = {}
    for f in result.findings:
        tag = classify_file(f.file).split(":")[0]
        surface_findings.setdefault(tag, []).append(f)

    # Group per-file analysis by surface (for compliance band + atom counts)
    surface_analysis: dict[str, list[Any]] = {}
    for fa in result.per_file_analysis:
        tag = classify_file(fa.file).split(":")[0]
        surface_analysis.setdefault(tag, []).append(fa)

    # Collect all surfaces from any source
    all_keys = set(surface_findings) | set(surface_analysis) | set(surface_file_counts)

    surfaces = []
    for key in _SURFACE_ORDER:
        if key not in all_keys:
            continue
        display_name = _SURFACE_NAMES.get(key, key.title())
        findings = surface_findings.get(key, [])
        analyses = surface_analysis.get(key, [])

        n_errors = sum(1 for f in findings if f.severity == "error")
        n_warnings = sum(1 for f in findings if f.severity == "warning")
        n_infos = sum(1 for f in findings if f.severity == "info")
        n_atoms = sum(fa.stats.get("atoms", 0) for fa in analyses)
        # File count: prefer mapper discovery, fall back to findings/analysis
        n_files = surface_file_counts.get(key, max(len(analyses), len({f.file for f in findings})))

        # Derive compliance band (majority vote across files in surface)
        bands = [fa.compliance_band for fa in analyses if fa.compliance_band]
        has_band = bool(bands)
        if has_band:
            # Majority band: most files determine the surface band
            band_counts: Counter[str] = Counter(bands)
            majority_band = band_counts.most_common(1)[0][0]
        else:
            majority_band = ""

        # Score: same formula as compute_score
        if n_errors + n_warnings + n_infos == 0:
            score = 10.0
        else:
            base = 6.0
            if has_band:
                base = 8.5 if majority_band == "HIGH" else 5.5 if majority_band == "MODERATE" else 3.0
            denom = max(n_atoms, n_errors + n_warnings + n_infos, 1)
            penalty = min(4.0, (n_errors / denom) * 30) + min(2.0, (n_warnings / denom) * 2)
            score = round(max(0.0, min(10.0, base - penalty)), 1)

        surfaces.append(
            SurfaceHealth(
                name=display_name,
                score=score,
                file_count=n_files,
                finding_count=len(findings),
                errors=n_errors,
                warnings=n_warnings,
                infos=n_infos,
            )
        )
    return surfaces


def _surface_cell(s: SurfaceHealth, bar_width: int = 10) -> str:
    """Format one surface as a Rich-markup cell: 'Name (N):  ▓▓▓▓▓▓░░░░  7.2'."""
    label = f"{s.name} ({s.file_count}):"
    filled = round(bar_width * s.score / 10)
    bar = "\u2593" * filled + "\u2591" * (bar_width - filled)
    color = "green" if s.score >= 7.0 else "yellow" if s.score >= 4.0 else "red"
    return f"{label:16s} [{color}]{bar}[/{color}]  [{color} bold]{s.score:>4.1f}[/{color} bold]"


def _render_surface_health(surfaces: list[SurfaceHealth]) -> None:
    """Render compact 2-column per-surface health bars."""
    if not surfaces:
        return
    console.print()
    for i in range(0, len(surfaces), 2):
        left = _surface_cell(surfaces[i])
        right = _surface_cell(surfaces[i + 1]) if i + 1 < len(surfaces) else ""
        sep = "    " if right else ""
        console.print(f"  {left}{sep}{right}")


# ── Category bars ─────────────────────────────────────────────────────


def _render_category_bar(cat_key: str, count: int, has_errors: bool, bar_max: int, max_count: int) -> None:
    """Render a single category bar line."""
    name = RULE_CATEGORY_MAP.get(cat_key, cat_key)
    bar_len = max(1, round(bar_max * count / max_count))
    bar_color = "yellow" if has_errors else "green"
    bar = "\u2588" * bar_len
    pad = " " * (bar_max - bar_len + 1)
    sev_icon = "[red]\u2717[/red]" if has_errors else "[dim]\u25cb[/dim]"
    console.print(f"  {name:<14s}[{bar_color}]{bar}[/{bar_color}]{pad}[dim]{count:>4d}[/dim]  {sev_icon}")


def print_category_bars(findings: tuple[Any, ...], tw: int) -> None:
    """Print per-category finding breakdown with colored bars."""
    cat_counts: Counter[str] = Counter()
    cat_errors: Counter[str] = Counter()
    for f in findings:
        cat = finding_category(f.rule)
        cat_counts[cat] += 1
        if f.severity == "error":
            cat_errors[cat] += 1

    if not cat_counts:
        return

    max_count = max(cat_counts.values())
    bar_max = min(20, tw - 30)
    console.print()
    for cat_key in ["S", "C", "E", "G", "D"]:
        count = cat_counts.get(cat_key, 0)
        if count:
            _render_category_bar(cat_key, count, cat_errors.get(cat_key, 0) > 0, bar_max, max_count)
    console.print()


# ── Scorecard sub-renderers ───────────────────────────────────────────


def _render_score_bar(
    result: Any,
    has_quality: bool,
    n_atoms: int,
    elapsed_ms: float,
) -> None:
    """Render score line with progress bar."""
    tw = get_term_width()
    score = compute_score(result, has_quality, n_atoms)
    bar_width = min(30, tw - 40)
    filled = round(bar_width * score / 10)
    bar = "\u2593" * filled + "\u2591" * (bar_width - filled)
    color = "green" if score >= 7.0 else "yellow" if score >= 4.0 else "red"
    elapsed_s = f"  [dim]({elapsed_ms / 1000:.1f}s)[/dim]" if elapsed_ms else ""
    console.print(f"  Score: [{color} bold]{score:.1f}[/{color} bold] / 10  [dim]{bar}[/dim]{elapsed_s}")


@dataclass
class ScopeInfo:
    """Instruction scope breakdown for scorecard rendering."""

    type_str: str = ""
    n_dir: int = 0
    n_con: int = 0
    n_amb: int = 0
    n_prose: int = 0
    n_atoms: int = 0


def _render_scope(scope: ScopeInfo, has_surface_health: bool = False) -> None:
    """Render the Scope section of the scorecard."""
    console.print()
    console.print("  Scope:")
    # capabilities line is replaced by surface health bars when available
    if scope.type_str and not has_surface_health:
        console.print(f"    capabilities: {scope.type_str}")
    instr_parts = []
    if scope.n_dir or scope.n_prose:
        pct = round(100 * scope.n_prose / scope.n_atoms) if scope.n_atoms else 0
        instr_parts.append(f"{scope.n_dir} directive / {scope.n_prose} prose ({pct}%)")
    if scope.n_con or scope.n_amb:
        con_parts = [f"{scope.n_con} constraint"]
        if scope.n_amb:
            con_parts.append(f"{scope.n_amb} ambiguous")
        instr_parts.append(" / ".join(con_parts))
    if instr_parts:
        console.print(f"    instructions: {instr_parts[0]}")
        for extra in instr_parts[1:]:
            console.print(f"                  {extra}")


def _render_cross_file_counts(result: Any) -> None:
    """Render cross-file conflict/repetition counts in the scorecard."""
    if result.cross_file:
        items = result.cross_file
        n_conflicts = sum(1 for cf in items if cf.finding_type == "conflict")
        n_reps = sum(1 for cf in items if cf.finding_type == "repetition")
    elif result.cross_file_coordinates:
        items = result.cross_file_coordinates
        n_conflicts = sum(c.count for c in items if c.finding_type == "conflict")
        n_reps = sum(c.count for c in items if c.finding_type == "repetition")
    else:
        return
    cf_parts = []
    if n_conflicts:
        cf_parts.append(f"{n_conflicts} cross-file conflicts")
    if n_reps:
        cf_parts.append(f"{n_reps} cross-file repetitions")
    if cf_parts:
        console.print(f"  {' \u00b7 '.join(cf_parts)}")


def _render_results_summary(
    result: Any,
    has_quality: bool,  # noqa: ARG001 — kept for API stability
    hint_errors: int,
    hint_warnings: int,
) -> tuple[int, int]:
    """Render findings, pro diagnostics, and cross-file counts. Returns (visible_findings, pro_total)."""
    s = result.stats
    visible_findings = s.total_findings
    parts = []
    if s.errors:
        parts.append(f"[red]{s.errors} errors[/red]")
    parts.append(f"{s.warnings} warnings")
    parts.append(f"{s.infos} info")

    console.print()
    console.print(f"  {visible_findings} findings \u00b7 {' \u00b7 '.join(parts)}")

    pro_total = sum(h.count for h in result.hints) if result.hints else 0
    if pro_total:
        pro_parts = []
        if hint_errors:
            pro_parts.append(f"[red]{hint_errors} errors[/red]")
        if hint_warnings:
            pro_parts.append(f"{hint_warnings} warnings")
        pro_detail = f" ({' \u00b7 '.join(pro_parts)})" if pro_parts else ""
        console.print(f"  [dim]+ {pro_total} Pro diagnostics{pro_detail}[/dim]")

    _render_cross_file_counts(result)

    return visible_findings, pro_total


# ── Scorecard ─────────────────────────────────────────────────────────


def print_scorecard(
    result: Any,
    has_quality: bool,
    n_atoms: int = 0,
    tier: str = "",
    elapsed_ms: float = 0,
    agent: str = "",
    scope: ScopeInfo | None = None,
    surface_health: list[SurfaceHealth] | None = None,
) -> None:
    """Print the bottom scorecard — the payoff users scroll to."""
    hint_errors, hint_warnings = _hint_totals(result)

    console.print(f"  [dim]\u2500\u2500 Summary {HRULE}[/dim]\n")

    _render_score_bar(result, has_quality, n_atoms, elapsed_ms)

    agent_name = agent.title() if agent else "auto"
    console.print(f"  Agent: {agent_name}")

    if scope is not None:
        _render_scope(scope, has_surface_health=bool(surface_health))

    if surface_health:
        _render_surface_health(surface_health)

    visible_findings, pro_total = _render_results_summary(result, has_quality, hint_errors, hint_warnings)

    # CTA for free tier
    if tier == "free":
        all_total = visible_findings + pro_total
        console.print()
        console.print(f"  See all {all_total} findings with fixes \u2192 [bold]ails auth login[/bold]")

    console.print()
