"""Display functions for text-mode CLI output.

Renders file cards, file groups, cross-file coordinates, and the
master print_text_result dispatcher. Constants live in display_constants.py;
scorecard rendering lives in scorecard.py.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.formatters.text.display_constants import (
    HRULE,
    NAMED_OVERLAP_PAIRS,
    Element,
    element_namer,
    file_type_summary,
    get_group_atoms,
    get_sev_icons,
    group_stats_line,
    more_pairs_line,
    partner_lookup,
    short_path,
    skill_lookup,
)
from reporails_cli.formatters.text.file_groups import (
    build_aliases_by_file,
    build_file_groups,
    build_hints_by_file,
    build_regime_by_file,
)
from reporails_cli.formatters.text.scorecard import (
    ScopeInfo,
    print_scorecard,
)
from reporails_cli.formatters.text.triage_view import print_file_card
from reporails_cli.formatters.triage import split_conventions

console = Console()


# ── Group rendering ───────────────────────────────────────────────────

_GROUP_ORDER = ("main", "nested", "agents", "skills", "rules", "config", "memory", "imported", "referenced", "file")
_GROUP_LABELS = {
    "main": "Main",
    "nested": "Nested",
    "agents": "Agents",
    "skills": "Skills",
    "rules": "Rules",
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
    skill_of: dict[str, str] | None = None,
    scanned_items: int | None = None,
) -> None:
    """Print group header with optional atom stats.

    The count is the surface's scanned item count when the run has one (the number the Summary's
    surface row states), else the items in the group that carry findings.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    group_atoms = get_group_atoms(gkey, group_files, ruleset_map, project_root, atoms_by_path)
    stats = f"  [dim]{group_stats_line(group_atoms)}[/dim]" if group_atoms else ""
    label = _GROUP_LABELS.get(gkey, gkey.title())
    norms = [normalize_finding_path(fp, project_root) for fp, _ in group_files]
    n_items = scanned_items if scanned_items is not None else len({(skill_of or {}).get(norm, norm) for norm in norms})
    console.print(f"  [dim]\u250c\u2500[/dim] [bold]{label}[/bold] [dim]({n_items})[/dim]{stats}")


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
    skill_of: dict[str, str] | None = None
    element_of: Callable[[str], Element] | None = None
    partners_of: Callable[[str], list[str]] | None = None
    # Scanned item count per surface label, as the Summary's surface rows state it.
    scanned_items: dict[str, int] = field(default_factory=dict)


def _render_one_group(gkey: str, group_files: list[tuple[str, list[Any]]], ctx: _CardContext) -> None:
    """Render a single file group: header, file cards, footer."""
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    _render_group_header(
        gkey,
        group_files,
        ctx.ruleset_map,
        ctx.project_root,
        ctx.atoms_by_path,
        ctx.skill_of,
        ctx.scanned_items.get(_GROUP_LABELS.get(gkey, gkey.title())),
    )
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
            skill_of=ctx.skill_of,
            element_of=ctx.element_of,
            partners_of=ctx.partners_of,
        )

    shown = sum(len(split_conventions(fs, ctx.verbose)[0]) for _, fs in group_files)
    console.print(f"  [dim]\u2514\u2500 {shown} findings[/dim]\n")


def _render_file_groups(groups: dict[str, list[tuple[str, list[Any]]]], ctx: _CardContext) -> None:
    """Render all file groups with cards."""
    for gkey in _GROUP_ORDER:
        group_files = groups.get(gkey, [])
        if group_files:
            _render_one_group(gkey, group_files, ctx)


def _render_detail_cta() -> None:
    """Print the "how to get line-level detail" call to action.

    Keyed on whether a key is held locally, not on the reported tier: a
    signed-in user told to run `ails login` is sent to a dead end, so
    they get the upgrade surface instead.
    """
    from reporails_cli.core.platform.adapters.api_client import has_api_key
    from reporails_cli.formatters.text.funnel_cta import upgrade_link

    if has_api_key():
        console.print(f"\n  [dim]Line-level detail \u2192 {upgrade_link()}[/dim]")
    else:
        console.print(
            "\n  [dim]Line-level detail \u2192 sign in with [bold]ails login[/bold], then upgrade to Pro[/dim]"
        )


def _render_cross_file_coordinates(result: Any, sev_icons: dict[str, str], verbose: bool = False) -> None:
    """Render the cross-file coordinates section (free tier).

    Only `repetition` and `overlap` coordinates reach here \u2014 `merge_results`
    drops `conflict` entries. A run names the pairs with the highest counts and counts
    the rest on one line; `-v` names every pair.
    """
    if not result.cross_file_coordinates:
        return
    console.print(f"  [dim]\u2500\u2500 Cross-file {HRULE}[/dim]\n")
    ranked = sorted(result.cross_file_coordinates, key=lambda c: -c.count)
    named, hidden = (ranked, 0) if verbose else (ranked[:NAMED_OVERLAP_PAIRS], len(ranked[NAMED_OVERLAP_PAIRS:]))
    for coord in named:
        icon = sev_icons.get("warning", "\u25cf")
        s = "s" if coord.count != 1 else ""
        short_1 = short_path(coord.file_1)
        short_2 = short_path(coord.file_2)
        console.print(f"  {icon}  {short_1} \u2194 {short_2} \u2014 {coord.count} {coord.finding_type}{s}")
    if hidden:
        console.print(f"  [dim]{more_pairs_line(hidden)}[/dim]")
    _render_detail_cta()
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


def _detect_agent_name(ruleset_map: Any, run_agents: tuple[str, ...] = ()) -> str:
    """Detect the agent(s) whose rules ran, from the ruleset map's file records.

    A single resolved agent returns its id, unchanged. Two or more distinct agent ids
    among the file records name a union run (two or more agents own files natively,
    each running its own rules on its own files, never collapsed to `generic`) — every
    one of them is returned, joined, so the scorecard names every agent whose rules ran
    rather than only the most common one. `map_instruction_files`'s `stamp_file_agents`
    is what makes each record's `agent` the discovery-resolved owner rather than the
    mapper's own, independently-guessed match, so this count is trustworthy.

    A run without a ruleset map (no model on disk) falls back to `run_agents`, the agents
    whose rules ran, so an explicit or detected agent is still named.
    """
    try:
        from reporails_cli.core.platform.dto.ruleset import RulesetMap

        if isinstance(ruleset_map, RulesetMap):
            ids = sorted({fr.agent for fr in ruleset_map.files if fr.agent != "generic"})
            if ids:
                return " + ".join(ids)
    except (AttributeError, ImportError, TypeError):
        pass
    return " + ".join(sorted({a for a in run_agents if a != "generic"}))


def _detect_tier(result: Any, has_quality: bool) -> str:
    """Determine the display tier string from the wire tier, never local credentials.

    `result.tier` is the tier the diagnostic response reported and is the single
    source of truth for the banner — the local credentials file (which may carry a
    retired legacy tier string) must never influence this. The `hints`/`has_quality`
    fallback only applies when the result carries no tier at all.

    Only an EMPTY wire tier reaches that fallback. A tier the response DID name is
    decided on the shared tier vocabulary: unentitled when it is in
    `UNENTITLED_TIERS`, entitled otherwise — so a tier name this client build does
    not know yet (a new paid plan) reads as entitled rather than silently
    downgrading a paying session to the free banner.
    """
    from reporails_cli.core.platform.dto.diagnostics import UNENTITLED_TIERS

    refusal = getattr(result, "server_error", None)
    # Only a refusal the server sent (it carries an HTTP status) names a real tier; a local
    # preflight refusal's tier is a guess.
    refused_tier = getattr(refusal, "tier", "") if getattr(refusal, "status", None) else ""
    wire_tier = getattr(result, "tier", "") or refused_tier or ""
    if result.offline and not wire_tier:
        return "offline"
    if wire_tier:
        return "free" if wire_tier in UNENTITLED_TIERS else "Pro"
    if result.hints:
        return "free"
    if has_quality:
        return "Pro"
    return "free"


# ── Master display function ───────────────────────────────────────────


def _print_header(tier: str) -> None:
    """Print the Reporails diagnostics header line."""
    tier_badge = f" \u2014 [bold]{tier}[/bold]" if tier and tier != "free" else ""
    console.print(f"\n[bold]Reporails[/bold] \u2014 Diagnostics{tier_badge}\n")


def _print_notices(notices: Any) -> None:
    """Print the notices under the header, then a blank line; nothing when there are none."""
    if not notices:
        return
    from reporails_cli.formatters.text.notices import print_notices

    print_notices(console, notices)
    console.print()


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
    has_quality = result.quality is not None
    tier = _detect_tier(result, has_quality)
    skill_of = skill_lookup(ruleset_map, root)
    scope.type_str = file_type_summary(all_files, skill_of) if all_files else "0 files"

    _print_header(tier)
    _print_notices(result.notices)
    if not result.findings:
        console.print(f"  {'ok' if ascii_mode else chr(0x2713)}  No findings.")
        _render_funnel_cta(funnel_error)
        return

    _render_findings_and_scorecard(
        result, ruleset_map, ascii_mode, verbose, scope, tier, elapsed_ms, root, file_type_by_path or {}, skill_of
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
    skill_of: dict[str, str] | None = None,
) -> None:
    """Render file groups, cross-file coordinates, and the bottom scorecard.

    Scorecard health-bars: multi-surface runs show per-surface; a
    single-surface run with several items (a skill folder is one item) shows per-item
    bars (so `ails check skills` lists each skill with its own score);
    a single item shows neither — the top `Score:` covers it.
    """
    from reporails_cli.formatters.text.display_constants import index_atoms_by_norm_path
    from reporails_cli.formatters.text.item_scorecard import compute_item_scores
    from reporails_cli.formatters.text.scorecard import compute_surface_scores

    has_quality = result.quality is not None
    sev_icons = get_sev_icons(ascii_mode)
    skill_of = skill_lookup(ruleset_map, project_root) if skill_of is None else skill_of
    # Built once per run, and only when an overlap line or a per-file overlap row will name an element.
    names_elements = bool(
        result.cross_file or result.cross_file_coordinates or any(f.rule == "CORE:C:0044" for f in result.findings)
    )
    element_of = element_namer(ruleset_map, project_root) if names_elements else None
    partners_of = partner_lookup(result, project_root) if names_elements else None
    atoms_by_path = (
        index_atoms_by_norm_path(ruleset_map.atoms, project_root) if getattr(ruleset_map, "atoms", None) else {}
    )
    aliases_by_file = build_aliases_by_file(project_root, result)
    surfaces = compute_surface_scores(
        result,
        ruleset_map=ruleset_map,
        project_root=project_root,
        file_type_by_path=file_type_by_path,
        skill_of=skill_of,
    )
    ctx = _CardContext(
        sev_icons=sev_icons,
        verbose=verbose,
        project_root=project_root,
        ruleset_map=ruleset_map,
        hints_by_file=build_hints_by_file(result.hints, project_root, aliases_by_file),
        aliases_by_file=aliases_by_file,
        regime_by_file=build_regime_by_file(result, project_root),
        atoms_by_path=atoms_by_path,
        skill_of=skill_of,
        element_of=element_of,
        partners_of=partners_of,
        scanned_items={s.name: s.item_count for s in surfaces},
    )
    _render_file_groups(build_file_groups(result, file_type_by_path, project_root, skill_of, aliases_by_file), ctx)
    _render_cross_file_coordinates(result, sev_icons, verbose)

    item_health = None
    if len(surfaces) == 1 and surfaces[0].item_count > 1:
        item_health = compute_item_scores(result, ruleset_map=ruleset_map, project_root=project_root, skill_of=skill_of)

    print_scorecard(
        result,
        has_quality,
        n_atoms=scope.n_atoms,
        tier=tier,
        elapsed_ms=elapsed_ms,
        agent=_detect_agent_name(ruleset_map, result.stats.agents),
        scope=scope,
        surface_health=surfaces,
        item_health=item_health,
        verbose=verbose,
        project_root=project_root,
        element_of=element_of,
    )


def _render_funnel_cta(funnel_error: object) -> None:
    """Render the conversion CTA + bug-report link when a FunnelError is present."""
    from reporails_cli.core.platform.dto.diagnostics import KNOWN_ERRORS, FunnelError
    from reporails_cli.formatters.text.funnel_cta import _short_url_label, format_bug_report_url, format_cta

    if not isinstance(funnel_error, FunnelError):
        return
    cta = format_cta(funnel_error)
    if not cta:
        return
    if funnel_error.retryable:
        console.print()
        console.print(f"  [yellow]⚠[/yellow]  {cta}")
        console.print()
        return
    bug_url = format_bug_report_url(funnel_error)
    bug_label = _short_url_label(bug_url)
    console.print()
    console.print("  [yellow]⚠[/yellow]  Server diagnostics unavailable.")
    console.print(f"  {cta}")
    if funnel_error.error not in KNOWN_ERRORS:
        link = f"[link={bug_url}][bold]{bug_label}[/bold][/link]"
        console.print(f"  [dim]Did you see an error? Let us know: {link}[/dim]")
    console.print()


def filter_result_to_paths(result: Any, paths: set[Path], project_root: Path) -> Any:
    """Return a CombinedResult containing only rows for `paths`.

    Filters findings, cross-file pairs, per-file analysis, AND the
    aggregate quality — without filtering it, the top score uses the
    whole project while surface-health uses the filtered files and the
    two scores disagree.
    """
    from dataclasses import replace as _replace

    from reporails_cli.core.platform.runtime.merger import (
        CombinedStats,
        count_cross_file_overlaps,
        count_cross_file_repetitions,
        normalize_finding_path,
    )

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
    # The aggregate form is scoped by the same rule, so the narrowed view's
    # repetition and overlap counts match its narrowed pair list at every tier.
    coords = tuple(c for c in result.cross_file_coordinates if _in_scope(c.file_1) or _in_scope(c.file_2))
    per_file = tuple(fa for fa in result.per_file_analysis if _in_scope(fa.file))
    sev = Counter(f.severity for f in findings)
    stats = CombinedStats(
        total_findings=len(findings),
        errors=sev.get("error", 0),
        warnings=sev.get("warning", 0),
        infos=sev.get("info", 0),
        cross_file_repetitions=count_cross_file_repetitions(cross, coords),
        cross_file_overlaps=count_cross_file_overlaps(cross, coords),
        m_probe_count=result.stats.m_probe_count,
        client_check_count=result.stats.client_check_count,
        server_diagnostic_count=result.stats.server_diagnostic_count,
    )
    quality = _filter_quality(result.quality, per_file)
    return _replace(
        result,
        findings=findings,
        cross_file=cross,
        cross_file_coordinates=coords,
        stats=stats,
        per_file_analysis=per_file,
        quality=quality,
    )


def _filter_quality(quality: Any, per_file: tuple[Any, ...]) -> Any:
    """Rewrite the aggregate display score from the filtered per-file set.

    The whole-project `display_score` covers every file; once
    the view is narrowed to a subset (e.g. `ails check skills`) there is no
    aggregate for that subset, so the headline becomes the mean of the subset's
    per-file display scores — matching the per-surface/per-item bars.
    """
    if quality is None:
        return None
    from dataclasses import replace as _replace

    from reporails_cli.formatters.text.scorecard import _mean_display_score

    if not any(int(fa.stats.get("atoms", 0) or 0) > 0 for fa in per_file):
        return None
    # All-unscored subset (every file has a None score) → fall back to the reported
    # whole-project aggregate, which itself may be `None` when the whole project has
    # no scorable content — the renderer treats that as "n/a", never as a fabricated
    # score, so passing `None` through here is correct, not a missed case.
    mean_score = _mean_display_score(list(per_file)) if per_file else quality.display_score
    if mean_score is None:
        mean_score = quality.display_score
    return _replace(quality, display_score=mean_score)


def filter_ruleset_map_to_paths(ruleset_map: Any, paths: set[Path], project_root: Path) -> Any:
    """Return a RulesetMap restricted to `paths` (matching files + their atoms)."""
    if ruleset_map is None or not paths:
        return ruleset_map
    keep = {_relativize(p, project_root).as_posix() for p in paths} | {p.as_posix() for p in paths}
    files = tuple(fr for fr in ruleset_map.files if fr.path in keep)
    atoms = tuple(a for a in ruleset_map.atoms if a.file_path in keep)
    # RulesetMap/RulesetSummary are Pydantic models; dataclasses.replace
    # raises TypeError on a BaseModel, so use model_copy for the Pydantic target.
    return ruleset_map.model_copy(update={"files": files, "atoms": atoms})


def _relativize(path: Path, project_root: Path) -> Path:
    """Return `path` relative to `project_root` without resolving symlinks.

    Symlinks may point outside the project (e.g. symlinked skills);
    resolving would push the path outside `project_root` and force the
    fallback. Use textual prefix stripping instead.
    """
    try:
        return path.relative_to(project_root)
    except ValueError:
        pass
    try:
        return safe_resolve(Path(path)).relative_to(safe_resolve(project_root))
    except ValueError:
        return path
