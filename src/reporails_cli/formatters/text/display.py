"""Display functions for text-mode CLI output.

Renders file cards, file groups, cross-file coordinates, and the
master print_text_result dispatcher. Constants live in display_constants.py;
scorecard rendering lives in scorecard.py.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console

from reporails_cli.formatters.text.display_constants import (
    HRULE,
    SEV_WEIGHT,
    classify_file,
    file_type_summary,
    get_group_atoms,
    get_sev_icons,
    group_stats_line,
    short_path,
)
from reporails_cli.formatters.text.scorecard import (
    ScopeInfo,
    compute_score,
    print_category_bars,
    print_score_line,
    print_scorecard,
)
from reporails_cli.formatters.text.triage_view import print_file_card

console = Console()

# Re-export for backward compat (tests, other modules importing from display)
__all__ = [
    "compute_score",
    "print_category_bars",
    "print_score_line",
    "print_scorecard",
    "print_text_result",
]


# ── Group rendering ───────────────────────────────────────────────────

_GROUP_ORDER = ("main", "nested", "agent", "skill", "rule", "config", "memory", "imported", "referenced", "file")
_GROUP_LABELS = {
    "main": "Main",
    "nested": "Nested",
    "agent": "Agents",
    "skill": "Skills",
    "rule": "Rules",
    "config": "Config",
    "memory": "Memory",
    "imported": "Imported",
    "referenced": "Referenced",
    "file": "Files",
}


def _render_group_header(
    gkey: str,
    group_files: list[tuple[str, list[Any]]],
    ruleset_map: Any,
    project_root: Path,
    atoms_by_path: dict[str, list[Any]] | None = None,
) -> None:
    """Print group header with optional atom stats."""
    group_atoms = get_group_atoms(gkey, group_files, ruleset_map, project_root, atoms_by_path)
    stats = f"  [dim]{group_stats_line(group_atoms)}[/dim]" if group_atoms else ""
    label = _GROUP_LABELS.get(gkey, gkey.title())
    console.print(f"  [dim]\u250c\u2500[/dim] [bold]{label}[/bold] [dim]({len(group_files)})[/dim]{stats}")


@dataclass(frozen=True)
class _CardContext:
    """Per-run rendering inputs threaded into each file card."""

    sev_icons: dict[str, str]
    verbose: bool
    project_root: Path = field(default_factory=Path.cwd)
    ruleset_map: Any = None
    hints_by_file: dict[str, list[Any]] = field(default_factory=dict)
    aliases_by_file: dict[str, list[str]] = field(default_factory=dict)
    regime_by_file: dict[str, Any] = field(default_factory=dict)
    atoms_by_path: dict[str, list[Any]] = field(default_factory=dict)


def _render_one_group(gkey: str, group_files: list[tuple[str, list[Any]]], ctx: _CardContext) -> None:
    """Render a single file group: header, file cards, footer."""
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    _render_group_header(gkey, group_files, ctx.ruleset_map, ctx.project_root, ctx.atoms_by_path)
    max_cards = 3 if not ctx.verbose else 999

    for i, (filepath, findings) in enumerate(group_files):
        if i >= max_cards:
            remaining = sum(len(fs) for _, fs in group_files[i:])
            console.print(f"  [dim]\u2502   ... and {len(group_files) - i} more ({remaining} findings)[/dim]")
            break
        print_file_card(
            filepath,
            findings,
            ctx.sev_icons,
            ctx.verbose,
            ctx.regime_by_file.get(normalize_finding_path(filepath, ctx.project_root)),
            ruleset_map=ctx.ruleset_map,
            file_hints=ctx.hints_by_file.get(filepath),
            aliases_by_file=ctx.aliases_by_file,
            project_root=ctx.project_root,
            atoms_by_path=ctx.atoms_by_path,
        )

    console.print(f"  [dim]\u2514\u2500 {sum(len(fs) for _, fs in group_files)} findings[/dim]\n")


def _render_file_groups(groups: dict[str, list[tuple[str, list[Any]]]], ctx: _CardContext) -> None:
    """Render all file groups with cards."""
    for gkey in _GROUP_ORDER:
        group_files = groups.get(gkey, [])
        if group_files:
            _render_one_group(gkey, group_files, ctx)


def _render_cross_file_coordinates(result: Any, sev_icons: dict[str, str]) -> None:
    """Render the cross-file coordinates section (free tier)."""
    if not result.cross_file_coordinates:
        return
    console.print(f"  [dim]\u2500\u2500 Cross-file {HRULE}[/dim]\n")
    for coord in result.cross_file_coordinates:
        icon = sev_icons.get("error" if coord.finding_type == "conflict" else "warning", "\u25cf")
        s = "s" if coord.count != 1 else ""
        short_1 = short_path(coord.file_1)
        short_2 = short_path(coord.file_2)
        console.print(f"  {icon}  {short_1} \u2194 {short_2} \u2014 {coord.count} {coord.finding_type}{s}")
    console.print("\n  [dim]Line-level detail and fixes \u2192 [bold]ails auth login[/bold][/dim]")
    console.print()


# ── Master display function helpers ───────────────────────────────────


def _collect_files_and_scope(
    result: Any,
    ruleset_map: Any,
    project_root: Path,
) -> tuple[set[str], ScopeInfo]:
    """Collect all file paths and instruction scope breakdown.

    Returns (all_files, scope_info).
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    all_files: set[str] = set()
    if result.findings:
        # `FindingItem.file` is normalized at merge, but re-normalize defensively —
        # the idempotent call is cheap (~#findings) and avoids betting the display on
        # an unenforced single-producer invariant. The O(atoms x files) render hot loop
        # is fixed in the atoms-side index (see display_constants), not here.
        all_files.update(normalize_finding_path(f.file, project_root) for f in result.findings)

    scope = ScopeInfo()
    try:
        from reporails_cli.core.platform.dto.ruleset import RulesetMap

        if isinstance(ruleset_map, RulesetMap):
            all_files.update(normalize_finding_path(fr.path, project_root) for fr in ruleset_map.files)
            scope = _count_atoms(ruleset_map.atoms)
    except (ImportError, NameError):
        pass

    return all_files, scope


def _count_atoms(atoms: Any) -> ScopeInfo:
    """Count atom types and return as ScopeInfo."""
    n_dir = n_con = n_amb = n_total = 0
    for a in atoms:
        n_total += 1
        if a.charge_value == +1:
            n_dir += 1
        elif a.charge_value == -1:
            n_con += 1
        if a.ambiguous:
            n_amb += 1
    return ScopeInfo(n_dir=n_dir, n_con=n_con, n_amb=n_amb, n_prose=n_total - n_dir - n_con, n_atoms=n_total)


def _detect_agent_name(ruleset_map: Any) -> str:
    """Detect primary agent name from ruleset_map file records."""
    try:
        from reporails_cli.core.platform.dto.ruleset import RulesetMap

        if isinstance(ruleset_map, RulesetMap):
            agent_counts = Counter(fr.agent for fr in ruleset_map.files if fr.agent != "generic")
            if agent_counts:
                return agent_counts.most_common(1)[0][0]
    except (AttributeError, ImportError, TypeError):
        pass
    return ""


def _detect_tier(result: Any, has_quality: bool) -> str:
    """Determine the display tier string."""
    creds_tier = ""
    try:
        from reporails_cli.interfaces.cli.auth_command import _read_credentials

        creds_tier = _read_credentials().get("tier", "")
    except (FileNotFoundError, KeyError, OSError):
        pass
    if result.offline:
        return "offline"
    if creds_tier == "beta":
        return "Pro (beta)"
    if result.hints:
        return "free"
    if has_quality:
        return "Pro"
    return "free"


def _build_file_groups(
    result: Any,
    file_type_by_path: dict[str, str] | None = None,
    project_root: Path | None = None,
) -> dict[str, list[tuple[str, list[Any]]]]:
    """Group findings by file type, sorted worst-first within each group.

    Generic-scanned files route by classifier `file_type`: `@`-import (`generic`) → the
    `imported` group, markdown-link (`referenced`) → the `referenced` group. Everything else
    falls back to the path-based `classify_file` tag.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    ft = file_type_by_path or {}
    root = project_root or Path.cwd()
    by_file: dict[str, list[Any]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    groups: dict[str, list[tuple[str, list[Any]]]] = {}
    for filepath, findings in by_file.items():
        if filepath in (".", ".:0"):
            continue
        file_type = ft.get(normalize_finding_path(filepath, root), "")
        if file_type == "generic":
            group_key = "imported"
        elif file_type == "referenced":
            group_key = "referenced"
        else:
            group_key = classify_file(filepath).split(":")[0]
        groups.setdefault(group_key, []).append((filepath, findings))

    for group_files in groups.values():
        group_files.sort(key=lambda x: (min(SEV_WEIGHT.get(f.severity, 9) for f in x[1]), -len(x[1])))

    return groups


def _build_hints_by_file(hints: Any, project_root: Path) -> dict[str, list[Any]]:
    """Build a file-keyed index of hints for inline display."""
    result: dict[str, list[Any]] = {}
    if hints:
        from reporails_cli.core.platform.runtime.merger import normalize_finding_path

        for h in hints:
            norm = normalize_finding_path(h.file, project_root)
            result.setdefault(norm, []).append(h)
    return result


def _build_regime_by_file(result: Any, project_root: Path) -> dict[str, Any]:
    """Build a file-keyed index of per-file regimes from server analysis stats.

    Empty for offline runs (no `per_file_analysis`) — callers then render the
    neutral findings view.
    """
    from reporails_cli.core.platform.policy.leverage import classify_regime
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    regimes: dict[str, Any] = {}
    for fa in result.per_file_analysis:
        regime = classify_regime(fa.stats)
        if regime is not None:
            regimes[normalize_finding_path(fa.file, project_root)] = regime
    return regimes


def _build_aliases_by_file(project_root: Path, result: Any) -> dict[str, list[str]]:
    """Combine discovery-time symlink aliases with display-time same-dir content aliases.

    `get_file_aliases` returns paths the discovery layer already collapsed
    (symlinks to one inode). `compute_same_dir_content_aliases` runs against
    the union of files referenced by findings — catches manual AGENTS.md /
    CLAUDE.md pairs that classify under different agents but should render as
    one row. Both alias sources are returned as project-relative posix strings
    so `_print_file_card` can do a plain dict lookup.
    """
    from reporails_cli.core.discovery.agents import compute_same_dir_content_aliases, get_file_aliases
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    out: dict[str, list[str]] = {}
    for canonical, alias_paths in get_file_aliases(project_root).items():
        key = normalize_finding_path(str(canonical), project_root)
        values = [normalize_finding_path(str(a), project_root) for a in alias_paths]
        if values:
            out[key] = values

    finding_paths: set[Path] = set()
    if result.findings:
        for f in result.findings:
            p = Path(f.file)
            finding_paths.add(p if p.is_absolute() else (project_root / p))
    for canonical, alias_paths in compute_same_dir_content_aliases(finding_paths).items():
        key = normalize_finding_path(str(canonical), project_root)
        values = [normalize_finding_path(str(a), project_root) for a in alias_paths]
        if values:
            out.setdefault(key, []).extend(values)
    return out


# ── Master display function ───────────────────────────────────────────


def _print_header(tier: str) -> None:
    """Print the Reporails diagnostics header line."""
    tier_badge = f" \u2014 [bold]{tier}[/bold]" if tier and tier != "free" else ""
    console.print(f"\n[bold]Reporails[/bold] \u2014 Diagnostics{tier_badge}\n")


def print_text_result(
    result: object,
    elapsed_ms: float,
    ascii_mode: bool,
    verbose: bool,
    ruleset_map: object = None,
    funnel_error: object = None,
    project_root: Path | None = None,
    file_type_by_path: dict[str, str] | None = None,
) -> None:
    """Print compact text output: files sorted worst-first, aggregated counts, scorecard at bottom.

    `funnel_error` is a FunnelError from the API client when a 4xx response or
    local preflight rejected the payload — surfaces the upgrade CTA below the
    scorecard so users see why server diagnostics are missing.

    `project_root` is the root finding/regime paths are keyed against — passed
    from the run's `target` so single-path scans line up with their findings
    instead of falling back to the neutral view. Defaults to cwd.
    """
    from reporails_cli.core.platform.runtime.merger import CombinedResult

    if not isinstance(result, CombinedResult):
        return

    root = project_root or Path.cwd()
    all_files, scope = _collect_files_and_scope(result, ruleset_map, root)
    has_quality = result.quality is not None and bool(result.quality.compliance_band)
    tier = _detect_tier(result, has_quality)
    scope.type_str = file_type_summary(all_files) if all_files else "0 files"

    _print_header(tier)
    if not result.findings:
        console.print(f"  {'ok' if ascii_mode else chr(0x2713)}  No findings.")
        _render_funnel_cta(funnel_error)
        return

    _render_findings_and_scorecard(
        result, ruleset_map, ascii_mode, verbose, scope, tier, elapsed_ms, root, file_type_by_path or {}
    )
    _render_funnel_cta(funnel_error)


def _render_findings_and_scorecard(
    result: Any,
    ruleset_map: Any,
    ascii_mode: bool,
    verbose: bool,
    scope: Any,
    tier: str,
    elapsed_ms: float,
    project_root: Path,
    file_type_by_path: dict[str, str],
) -> None:
    """Render file groups, cross-file coordinates, and the bottom scorecard.

    Scorecard health-bars: multi-surface runs show per-surface; a
    single-surface run with multiple files shows per-item bars (so
    `ails check skills` lists each skill with its own score);
    single-file runs show neither — the top `Score:` covers it.
    """
    from reporails_cli.formatters.text.display_constants import index_atoms_by_norm_path
    from reporails_cli.formatters.text.item_scorecard import compute_item_scores
    from reporails_cli.formatters.text.scorecard import compute_surface_scores

    has_quality = result.quality is not None and bool(result.quality.compliance_band)
    sev_icons = get_sev_icons(ascii_mode)
    atoms_by_path = (
        index_atoms_by_norm_path(ruleset_map.atoms, project_root) if getattr(ruleset_map, "atoms", None) else {}
    )
    ctx = _CardContext(
        sev_icons=sev_icons,
        verbose=verbose,
        project_root=project_root,
        ruleset_map=ruleset_map,
        hints_by_file=_build_hints_by_file(result.hints, project_root),
        aliases_by_file=_build_aliases_by_file(project_root, result),
        regime_by_file=_build_regime_by_file(result, project_root),
        atoms_by_path=atoms_by_path,
    )
    _render_file_groups(_build_file_groups(result, file_type_by_path, project_root), ctx)
    _render_cross_file_coordinates(result, sev_icons)

    surfaces = compute_surface_scores(
        result, ruleset_map=ruleset_map, project_root=project_root, file_type_by_path=file_type_by_path
    )
    item_health = None
    if len(surfaces) == 1 and surfaces[0].file_count > 1:
        item_health = compute_item_scores(result, ruleset_map=ruleset_map, project_root=project_root)

    print_scorecard(
        result,
        has_quality,
        n_atoms=scope.n_atoms,
        tier=tier,
        elapsed_ms=elapsed_ms,
        agent=_detect_agent_name(ruleset_map),
        scope=scope,
        surface_health=surfaces,
        item_health=item_health,
    )


def _render_funnel_cta(funnel_error: object) -> None:
    """Render the conversion CTA + bug-report link when a FunnelError is present."""
    from reporails_cli.core.funnel import FunnelError, _short_url_label, format_bug_report_url, format_cta

    if not isinstance(funnel_error, FunnelError):
        return
    cta = format_cta(funnel_error)
    if not cta:
        return
    bug_url = format_bug_report_url(funnel_error)
    bug_label = _short_url_label(bug_url)
    console.print()
    console.print("  [yellow]⚠[/yellow]  Server diagnostics unavailable.")
    console.print(f"  {cta}")
    console.print(f"  [dim]Did you see an error? Let us know: [link={bug_url}][bold]{bug_label}[/bold][/link][/dim]")
    console.print()


def filter_result_to_paths(result: Any, paths: set[Path], project_root: Path) -> Any:
    """Return a CombinedResult containing only rows for `paths`.

    Filters findings, cross-file pairs, per-file analysis, AND the
    aggregate `quality.compliance_band` — without filtering the band,
    the top score uses whole-project base while surface-health uses the
    filtered base and the two scores disagree.
    """
    from dataclasses import replace as _replace

    from reporails_cli.core.platform.runtime.merger import CombinedStats, normalize_finding_path

    def _in_scope(path: str) -> bool:
        # `findings` are already project-relative; server `per_file` / `cross_file`
        # carry absolute paths, so normalize before the membership test.
        return normalize_finding_path(path, project_root) in rel_keys

    # Normalize keys through the same function as findings so out-of-tree
    # targets (e.g. `~/.claude/...` memory) match — `_relativize` falls back to
    # the absolute path while `normalize_finding_path` yields the `~/` form.
    rel_keys = {normalize_finding_path(str(p), project_root) for p in paths}
    findings = tuple(f for f in result.findings if _in_scope(f.file))
    cross = tuple(cf for cf in result.cross_file if _in_scope(cf.file_1) or _in_scope(cf.file_2))
    per_file = tuple(fa for fa in result.per_file_analysis if _in_scope(fa.file))
    sev = Counter(f.severity for f in findings)
    stats = CombinedStats(
        total_findings=len(findings),
        errors=sev.get("error", 0),
        warnings=sev.get("warning", 0),
        infos=sev.get("info", 0),
        cross_file_conflicts=sum(1 for c in cross if c.finding_type == "conflict"),
        cross_file_repetitions=sum(1 for c in cross if c.finding_type == "repetition"),
        m_probe_count=result.stats.m_probe_count,
        client_check_count=result.stats.client_check_count,
        server_diagnostic_count=result.stats.server_diagnostic_count,
    )
    quality = _filter_quality(result.quality, per_file)
    return _replace(
        result,
        findings=findings,
        cross_file=cross,
        stats=stats,
        per_file_analysis=per_file,
        quality=quality,
    )


def _filter_quality(quality: Any, per_file: tuple[Any, ...]) -> Any:
    """Rewrite the aggregate band + display score from the filtered per-file set.

    The whole-project `display_score` is the api's verdict over every file; once
    the view is narrowed to a subset (e.g. `ails check skills`) there is no api
    aggregate for that subset, so the headline becomes the mean of the subset's
    per-file display scores — matching the per-surface/per-item bars.
    """
    if quality is None:
        return None
    from dataclasses import replace as _replace

    from reporails_cli.formatters.text.scorecard import _mean_display_score

    bands = [fa.compliance_band for fa in per_file if fa.compliance_band]
    if not bands:
        return None
    majority = Counter(bands).most_common(1)[0][0]
    # All-unscored subset (every file has a None score) → keep the server's aggregate
    # rather than rendering a 0.0/empty headline.
    mean_score = _mean_display_score(list(per_file)) if per_file else quality.display_score
    if mean_score is None:
        mean_score = quality.display_score
    return _replace(quality, compliance_band=majority, display_score=mean_score)


def filter_ruleset_map_to_paths(ruleset_map: Any, paths: set[Path], project_root: Path) -> Any:
    """Return a RulesetMap restricted to `paths` (matching files + their atoms)."""
    from dataclasses import replace as _replace

    if ruleset_map is None or not paths:
        return ruleset_map
    keep = {str(_relativize(p, project_root)) for p in paths} | {str(p) for p in paths}
    files = tuple(fr for fr in ruleset_map.files if str(fr.path) in keep)
    atoms = tuple(a for a in ruleset_map.atoms if a.file_path in keep)
    return _replace(ruleset_map, files=files, atoms=atoms)


def _relativize(path: Path, project_root: Path) -> Path:
    """Return `path` relative to `project_root` without resolving symlinks.

    Symlinks may point outside the project (e.g. hub-symlinked skills);
    resolving would push the path outside `project_root` and force the
    fallback. Use textual prefix stripping instead.
    """
    try:
        return path.relative_to(project_root)
    except ValueError:
        pass
    try:
        return Path(path).resolve().relative_to(project_root.resolve())
    except ValueError:
        return path
