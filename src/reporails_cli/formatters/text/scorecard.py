"""Scorecard rendering for text-mode CLI output.

Renders the bottom summary section: score bar, scope, findings, compliance, CTA.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from reporails_cli.formatters.text.display_constants import (
    HRULE,
    RULE_CATEGORY_MAP,
    classify_file,
    finding_category,
    get_term_width,
)
from reporails_cli.formatters.text.score import (
    SCORE_GREEN_CUTOFF,
    leverage_basis,
    score_color,
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


def compute_score(result: Any, has_quality: bool, n_atoms: int = 0) -> float:  # noqa: ARG001
    """Return the api's whole-project display score verbatim.

    The score is the analysis service's own verdict, computed server-side; the CLI
    renders it without re-deriving. Falls back to 0.0 when offline (no server quality).
    `n_atoms` is retained for call-signature stability.
    """
    if has_quality and result.quality is not None:
        return float(result.quality.display_score)
    return 0.0


def print_score_line(score: float, tw: int) -> None:
    """Print score with progress bar."""
    bar_width = min(40, tw - 26)
    filled = round(bar_width * score / 10)
    bar = "\u2593" * filled + "\u2591" * (bar_width - filled)
    color = score_color(score)
    console.print(f"  Score: [{color} bold]{score:.1f}[/{color} bold] / 10  [dim]{bar}[/dim]")


# ── Surface health ────────────────────────────────────────────────────

_SURFACE_NAMES = {
    "main": "Main",
    "nested": "Nested",
    "rule": "Rules",
    "skill": "Skills",
    "agent": "Agents",
    "memory": "Memory",
}
_SURFACE_ORDER = ["main", "nested", "rule", "skill", "agent", "memory"]


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
    # Findings grouped by Category enum value (`structure`, `direction`,
    # `coherence`, `efficiency`, `maintenance`, `governance`). Empty when no
    # findings have a recognizable category code. Sum of values equals
    # `finding_count` for findings whose rule-id second segment maps via
    # `CATEGORY_CODES`; rules with non-standard IDs are excluded.
    category_breakdown: dict[str, int] = field(default_factory=dict)


def compute_surface_scores(
    result: Any,
    ruleset_map: Any = None,
    project_root: Any = None,
) -> list[SurfaceHealth]:
    """Compute per-surface health scores from combined result.

    When ruleset_map is provided, file counts come from the mapper's
    discovery (all scanned files), not just files with findings.

    `project_root` is used to relativize `ruleset_map.files` paths before
    classification — `classify_file` distinguishes `main` (root-level) from
    `nested` (subdirectory copies) by path-component count, which only works
    on relative paths. `result.findings` and `result.per_file_analysis`
    already carry relative paths; `ruleset_map.files` does not.
    """
    from pathlib import Path

    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    root = Path(project_root) if project_root is not None else Path.cwd()

    # Count files per surface from ruleset_map (authoritative file list)
    surface_file_counts: dict[str, int] = {}
    if ruleset_map is not None:
        try:
            for fr in ruleset_map.files:
                rel = normalize_finding_path(fr.path, root)
                tag = classify_file(rel).split(":")[0]
                surface_file_counts[tag] = surface_file_counts.get(tag, 0) + 1
        except (AttributeError, TypeError):
            pass

    # Group findings by surface
    surface_findings: dict[str, list[Any]] = {}
    for f in result.findings:
        tag = classify_file(f.file).split(":")[0]
        surface_findings.setdefault(tag, []).append(f)

    # Group per-file analysis by surface. Server per-file paths are absolute, but
    # `classify_file` keys `main` on root-level path depth — so normalize to the
    # project-relative form first (as `result.findings` already are), or every
    # absolute path falls out of the `main` surface and its score reads 0.0.
    surface_analysis: dict[str, list[Any]] = {}
    for fa in result.per_file_analysis:
        tag = classify_file(normalize_finding_path(fa.file, root)).split(":")[0]
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
        # File count: prefer mapper discovery, fall back to findings/analysis
        n_files = surface_file_counts.get(key, max(len(analyses), len({f.file for f in findings})))

        # Score: mean of the api's per-file display scores over the surface's files.
        score = _mean_display_score(analyses)

        surfaces.append(
            SurfaceHealth(
                name=display_name,
                score=score,
                file_count=n_files,
                finding_count=len(findings),
                errors=n_errors,
                warnings=n_warnings,
                infos=n_infos,
                category_breakdown=_count_categories(findings),
            )
        )
    return surfaces


def _mean_display_score(analyses: list[Any]) -> float:
    """Atom-weighted mean of the api's per-file display scores.

    Mirrors the server's whole-project roll-up so a surface's bar (and the filtered
    headline) aggregate the same way the headline does. Falls back to a simple mean
    when atom counts are unavailable; 0.0 when there is no server analysis.
    """
    scored = [(float(fa.display_score), int(fa.stats.get("atoms", 0))) for fa in analyses if fa is not None]
    if not scored:
        return 0.0
    total_weight = sum(w for _, w in scored)
    if total_weight <= 0:
        return round(sum(s for s, _ in scored) / len(scored), 1)
    return round(sum(s * w for s, w in scored) / total_weight, 1)


def _count_categories(findings: list[Any]) -> dict[str, int]:
    """Group findings by rule-id-derived Category value.

    Reads each finding's rule id (e.g. `CORE:C:0042`), pulls the second
    segment (`C`), and maps it via `CATEGORY_CODES` to a category label.
    Rules whose id shape doesn't yield a known code are skipped — the
    counts only cover categorized findings.
    """
    from reporails_cli.core.platform.dto.models import CATEGORY_CODES

    counts: Counter[str] = Counter()
    for f in findings:
        parts = (f.rule or "").split(":")
        if len(parts) < 2:
            continue
        category = CATEGORY_CODES.get(parts[1])
        if category is None:
            continue
        counts[category.value] += 1
    return dict(counts)


def _surface_cell(s: SurfaceHealth, bar_width: int = 15) -> str:
    """Format one surface as a Rich-markup cell: 'Name (N):  ▓▓▓▓▓▓▓▓▓▓▓░░░░  7.2'.

    bar_width=15 is the smallest width that visually distinguishes 6.9 from 7.2
    under integer rounding — at width 10, scores 6.5-7.4 all map to 7 filled cells.
    """
    label = f"{s.name} ({s.file_count}):"
    color = score_color(s.score)
    bar = _score_bar(s.score, bar_width, color)
    # A surface can score well while errors remain, so the error count is what
    # routes attention — surface the per-surface error tally next to the bar.
    err = f"  [red]{s.errors} err[/red]" if s.errors else ""
    return f"{label:13s} {bar}  [{color} bold]{s.score:>4.1f}[/{color} bold]{err}"


def _score_bar(score: float, bar_width: int, color: str) -> str:
    """Render a score bar with colored fill + dim gray empty.

    Splitting the markup at the fill boundary gives every bar a
    consistent gray baseline so the colored fill is the only visual
    variable that changes across rows.
    """
    filled = round(bar_width * score / 10)
    fill = "\u2593" * filled
    empty = "\u2591" * (bar_width - filled)
    return f"[{color}]{fill}[/{color}][dim]{empty}[/dim]"


def _render_surface_health(surfaces: list[SurfaceHealth]) -> None:
    """Render compact 2-column per-surface health bars.

    Single-surface case is suppressed: the top `Score:` already
    represents that surface, so a second bar would just restate the
    same number.
    """
    if len(surfaces) <= 1:
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


_VERDICT_LABEL_W = 9  # widest label is "Findings"


def _render_verdict_block(
    result: Any,
    has_quality: bool,
    n_atoms: int,
    elapsed_ms: float,
) -> None:
    """Render the Quality headline and the findings worklist beneath it.

    One quality number — the server's single scoring verdict, which already folds in
    delivery (completeness + truncation) so a structurally incomplete or truncated file
    cannot read as high quality. The findings line below is the worklist, not a
    competing score.
    """
    tw = get_term_width()
    bar_width = min(20, max(10, tw - 48))
    elapsed_s = f"  [dim]({elapsed_ms / 1000:.1f}s)[/dim]" if elapsed_ms else ""

    score: float | None = None
    if has_quality and result.quality is not None:
        score = compute_score(result, has_quality, n_atoms)
        color = score_color(score)
        bar = _score_bar(score, bar_width, color)
        value = f"[{color} bold]{score:>4.1f}[/{color} bold] / 10"
        console.print(f"  {'Quality':<{_VERDICT_LABEL_W}}{value}  {bar}{elapsed_s}")
    else:
        console.print(f"  {'Quality':<{_VERDICT_LABEL_W}}[dim]n/a (server diagnostics unavailable)[/dim]{elapsed_s}")

    _render_findings_axis(result)

    # Bridging caption when the score is high but errors remain, so a green headline
    # above red errors does not read as "nothing to do".
    if score is not None and score >= SCORE_GREEN_CUTOFF and result.stats.errors:
        console.print("  [dim]Quality folds in the findings below; the listed errors are still your worklist.[/dim]")


def _render_findings_axis(result: Any) -> None:
    """Render the Findings worklist line — distinct from the score; errors carry red."""
    s = result.stats
    movers = leverage_basis(result.findings)[0]
    err = f"[red]{s.errors} errors[/red]" if s.errors else f"[dim]{s.errors} errors[/dim]"
    parts = [err, f"[yellow]{s.warnings} warnings[/yellow]", f"[dim]{s.infos} info[/dim]"]
    if movers:
        parts.append(f"{movers} score-movers")
    console.print(f"  {'Findings':<{_VERDICT_LABEL_W}}{' · '.join(parts)}")


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


_RULE_SEVERITY_RANK = {"error": 0, "warning": 1, "info": 2}
_RULE_SEVERITY_LABEL = {"error": "[red]err [/red]", "warning": "[yellow]warn[/yellow]", "info": "info"}


def _aggregate_top_rules(findings: Any, limit: int = 4) -> list[tuple[str, int, str, str]]:
    """Return up to `limit` rules ranked by finding count.

    Each entry: (rule_id, count, severity, sample_message). Severity is the
    worst severity (error > warning > info) recorded for that rule across
    the findings list; sample_message is the first finding's message,
    truncated for the scorecard column.
    """
    buckets: dict[str, dict[str, Any]] = {}
    for f in findings:
        bucket = buckets.setdefault(
            f.rule,
            {"count": 0, "severity": f.severity, "message": f.message},
        )
        bucket["count"] += 1
        if _RULE_SEVERITY_RANK.get(f.severity, 3) < _RULE_SEVERITY_RANK.get(bucket["severity"], 3):
            bucket["severity"] = f.severity
    rows = [(rule, b["count"], b["severity"], b["message"]) for rule, b in buckets.items()]
    rows.sort(key=lambda r: (-r[1], r[0]))
    return rows[:limit]


def _render_top_rules(result: Any) -> None:
    """Render the Top-rules block in the whole-repo scorecard."""
    if not result.findings:
        return
    rows = _aggregate_top_rules(result.findings)
    if not rows:
        return
    tw = get_term_width()
    console.print()
    console.print("  Top rules (by finding count):")
    rule_w = max((len(r[0]) for r in rows), default=12)
    max_count = max(r[1] for r in rows)
    count_w = len(str(max_count)) + 1  # for the x prefix
    # 4 (indent) + rule_w + 1 + count_w + 1 + 6 (severity label cell) + 2 (gap)
    fixed = 4 + rule_w + 1 + count_w + 1 + 6 + 2
    snippet_w = max(20, tw - fixed - 2)
    for rule, count, severity, message in rows:
        label = _RULE_SEVERITY_LABEL.get(severity, severity)
        snippet = message.split(".")[0].split("—")[0].strip()
        if len(snippet) > snippet_w:
            snippet = snippet[: snippet_w - 1] + "…"
        console.print(f"    {rule:<{rule_w}} x{count:<{count_w}} {label}  {snippet}")


def _render_results_summary(
    result: Any,
    has_quality: bool,  # noqa: ARG001 — kept for API stability
    hint_errors: int,
    hint_warnings: int,
) -> tuple[int, int]:
    """Render pro diagnostics + cross-file counts. Returns (visible_findings, pro_total).

    The error/warning/info breakdown now lives in the top verdict block's Findings
    line, so it is not repeated here.
    """
    s = result.stats
    visible_findings = s.total_findings

    pro_total = sum(h.count for h in result.hints) if result.hints else 0
    if pro_total:
        console.print()
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
    item_health: list[SurfaceHealth] | None = None,
) -> None:
    """Print the bottom scorecard — the payoff users scroll to.

    Exactly one of {surface_health (multi-surface), item_health
    (capability listing)} renders below the scope block. Single-surface
    single-file runs render neither — the top `Score:` covers it.
    """
    from reporails_cli.core.platform.dto.models import Level
    from reporails_cli.core.platform.policy.levels import LEVEL_LABELS

    hint_errors, hint_warnings = _hint_totals(result)

    console.print(f"  [dim]\u2500\u2500 Summary {HRULE}[/dim]\n")

    _render_verdict_block(result, has_quality, n_atoms, elapsed_ms)

    agent_name = agent.title() if agent else "auto"
    console.print(f"  Agent: {agent_name}")

    level = getattr(result, "level", Level.L0)
    label = LEVEL_LABELS.get(level, "Unknown")
    console.print(f"  Level: {level.value} [bold]{label}[/bold]")

    multi_surface = surface_health is not None and len(surface_health) > 1
    has_items = item_health is not None and len(item_health) > 1
    if scope is not None:
        _render_scope(scope, has_surface_health=multi_surface or has_items)

    if surface_health is not None and len(surface_health) > 1:
        _render_surface_health(surface_health)
    elif item_health is not None and len(item_health) > 1:
        from reporails_cli.formatters.text.item_scorecard import render_item_health

        render_item_health(item_health)

    _render_top_rules(result)

    visible_findings, pro_total = _render_results_summary(result, has_quality, hint_errors, hint_warnings)

    # CTA for free tier
    if tier == "free":
        all_total = visible_findings + pro_total
        console.print()
        console.print(f"  See all {all_total} findings with fixes \u2192 [bold]ails auth login[/bold]")

    console.print()
