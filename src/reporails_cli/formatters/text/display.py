"""Display functions for text-mode CLI output.

Renders file cards, file groups, cross-file coordinates, and the
master print_text_result dispatcher. Constants live in display_constants.py;
scorecard rendering lives in scorecard.py.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from reporails_cli.core.platform.adapters.api_key import has_api_key
from reporails_cli.core.platform.dto.diagnostics import KNOWN_ERRORS, UNENTITLED_TIERS, FindingItem, FunnelError, Notice
from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap
from reporails_cli.core.platform.runtime.merger import (
    CombinedResult,
    normalize_finding_path,
)
from reporails_cli.formatters.text.display_constants import (
    FILE_PANEL_ORDER,
    HRULE,
    NAMED_OVERLAP_PAIRS,
    Element,
    element_namer,
    file_type_summary,
    get_group_atoms,
    get_sev_icons,
    group_stats_line,
    index_atoms_by_norm_path,
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
from reporails_cli.formatters.text.funnel_cta import _short_url_label, format_bug_report_url, format_cta, upgrade_link
from reporails_cli.formatters.text.health import SurfaceHealth
from reporails_cli.formatters.text.item_scorecard import compute_item_scores
from reporails_cli.formatters.text.not_evaluated import not_evaluated_lines, print_not_evaluated
from reporails_cli.formatters.text.notices import print_notices
from reporails_cli.formatters.text.scorecard import (
    ScopeInfo,
    ScorecardDetail,
    compute_surface_scores,
    print_scorecard,
)
from reporails_cli.formatters.text.triage_view import CardContext, print_file_card
from reporails_cli.formatters.text.verdict import render_excluded_line
from reporails_cli.formatters.triage import split_conventions

console = Console()


# ── Group rendering ───────────────────────────────────────────────────

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
    group_files: list[tuple[str, list[FindingItem]]],
    ruleset_map: RulesetMap | None,
    project_root: Path,
    *,
    atoms_by_path: dict[str, list[Atom]] | None = None,
    skill_of: dict[str, str] | None = None,
    scanned_items: int | None = None,
) -> None:
    """Print group header with optional atom stats.

    The count is the surface's scanned item count when the run has one (the number the Summary's
    surface row states), else the items in the group that carry findings.
    """

    group_atoms = get_group_atoms(group_files, ruleset_map, project_root, atoms_by_path)
    stats = f"  [dim]{group_stats_line(group_atoms)}[/dim]" if group_atoms else ""
    label = _GROUP_LABELS.get(gkey, gkey.title())
    norms = [normalize_finding_path(fp, project_root) for fp, _ in group_files]
    n_items = scanned_items if scanned_items is not None else len({(skill_of or {}).get(norm, norm) for norm in norms})
    console.print(f"  [dim]\u250c\u2500[/dim] [bold]{label}[/bold] [dim]({n_items})[/dim]{stats}")


def _render_one_group(gkey: str, group_files: list[tuple[str, list[FindingItem]]], ctx: CardContext) -> None:
    """Render a single file group: header, file cards, footer."""

    _render_group_header(
        gkey,
        group_files,
        ctx.ruleset_map,
        ctx.project_root,
        atoms_by_path=ctx.atoms_by_path,
        skill_of=ctx.skill_of,
        scanned_items=ctx.scanned_items.get(_GROUP_LABELS.get(gkey, gkey.title())),
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
            ctx,
            ctx.regime_by_file.get(normalize_finding_path(filepath, ctx.project_root)),
            ctx.hints_by_file.get(filepath),
        )

    shown = sum(len(split_conventions(fs, ctx.verbose)[0]) for _, fs in group_files)
    console.print(f"  [dim]\u2514\u2500 {shown} findings[/dim]\n")


def _render_file_groups(groups: dict[str, list[tuple[str, list[FindingItem]]]], ctx: CardContext) -> None:
    """Render all file groups with cards."""
    for gkey in FILE_PANEL_ORDER:
        group_files = groups.get(gkey, [])
        if group_files:
            _render_one_group(gkey, group_files, ctx)


def _render_detail_cta() -> None:
    """Print the "how to get line-level detail" call to action.

    Keyed on whether a key is held locally, not on the reported tier: a
    signed-in user told to run `ails login` is sent to a dead end, so
    they get the upgrade surface instead.
    """

    if has_api_key():
        console.print(f"\n  [dim]Line-level detail \u2192 {upgrade_link()}[/dim]")
    else:
        console.print(
            "\n  [dim]Line-level detail \u2192 sign in with [bold]ails login[/bold], then upgrade to Pro[/dim]"
        )


def _render_cross_file_coordinates(result: CombinedResult, sev_icons: dict[str, str], verbose: bool = False) -> None:
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
    result: CombinedResult,
    ruleset_map: RulesetMap | None,
    project_root: Path,
) -> tuple[set[str], ScopeInfo]:
    """Collect all file paths and instruction scope breakdown.

    Returns (all_files, scope_info).
    """

    all_files: set[str] = set()
    if result.findings:
        # `FindingItem.file` is normalized at merge, but re-normalize defensively —
        # the idempotent call is cheap (~#findings) and avoids betting the display on
        # an unenforced single-producer invariant. The O(atoms x files) render hot loop
        # is fixed in the atoms-side index (see display_constants), not here.
        all_files.update(normalize_finding_path(f.file, project_root) for f in result.findings)

    scope = ScopeInfo()
    try:
        if isinstance(ruleset_map, RulesetMap):
            all_files.update(normalize_finding_path(fr.path, project_root) for fr in ruleset_map.files)
            scope = _count_atoms(ruleset_map.atoms)
    except (ImportError, NameError):
        pass

    return all_files, scope


def _count_atoms(atoms: Iterable[Atom]) -> ScopeInfo:
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


def _detect_agent_name(ruleset_map: RulesetMap | None, run_agents: tuple[str, ...] = ()) -> str:
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
        if isinstance(ruleset_map, RulesetMap):
            ids = sorted({fr.agent for fr in ruleset_map.files if fr.agent != "generic"})
            if ids:
                return " + ".join(ids)
    except (AttributeError, ImportError, TypeError):
        pass
    return " + ".join(sorted({a for a in run_agents if a != "generic"}))


def _detect_tier(result: CombinedResult, has_quality: bool) -> str:
    """Determine the display tier string from the wire tier, never local credentials.

    `result.reply.tier` is the tier the diagnostic response reported and is the single
    source of truth for the banner — the local credentials file (which may carry a
    retired legacy tier string) must never influence this. The `hints`/`has_quality`
    fallback only applies when the result carries no tier at all.

    Only an EMPTY wire tier reaches that fallback. A tier the response DID name is
    decided on the shared tier vocabulary: unentitled when it is in
    `UNENTITLED_TIERS`, entitled otherwise — so a tier name this client build does
    not know yet (a new paid plan) reads as entitled rather than silently
    downgrading a paying session to the free banner.
    """

    refusal = result.reply.server_error
    # Only a refusal the server sent (it carries an HTTP status) names a real tier; a local
    # preflight refusal's tier is a guess.
    refused_tier = getattr(refusal, "tier", "") if getattr(refusal, "status", None) else ""
    wire_tier = result.reply.tier or refused_tier or ""
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


def _print_notices(notices: Sequence[Notice], ascii_mode: bool, *, blank_before: bool) -> None:
    """Print the notices last, one blank line after the output before them; nothing when there are none.

    `blank_before` is False when the output already ends on a blank line.
    """
    if not notices:
        return

    if blank_before:
        console.print()
    print_notices(console, notices, ascii_mode=ascii_mode)


def print_text_result(
    result: CombinedResult,
    elapsed_ms: float,
    ascii_mode: bool,
    verbose: bool,
    *,
    ruleset_map: RulesetMap | None = None,
    funnel_error: FunnelError | None = None,
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

    root = project_root or Path.cwd()
    all_files, scope = _collect_files_and_scope(result, ruleset_map, root)
    has_quality = result.quality is not None
    tier = _detect_tier(result, has_quality)
    skill_of = skill_lookup(ruleset_map, root)
    scope.type_str = file_type_summary(all_files, skill_of) if all_files else "0 files"

    _print_header(tier)
    if not result.findings:
        console.print(f"  {'ok' if ascii_mode else chr(0x2713)}  No findings.")
        render_excluded_line(result, scored=False)
        print_not_evaluated(console, result.omissions.not_evaluated)
        _print_notices(result.reply.notices, ascii_mode, blank_before=not _render_funnel_cta(funnel_error))
        return

    _render_findings_and_scorecard(
        result,
        ruleset_map,
        ascii_mode=ascii_mode,
        verbose=verbose,
        summary=_SummaryInputs(scope=scope, tier=tier, elapsed_ms=elapsed_ms),
        project_root=root,
        file_type_by_path=file_type_by_path or {},
        skill_of=skill_of,
    )
    print_not_evaluated(console, result.omissions.not_evaluated)
    # The scorecard ends on a blank line; the not-evaluated lines, when printed, end the output without one.
    ends_blank = not not_evaluated_lines(result.omissions.not_evaluated)
    _print_notices(result.reply.notices, ascii_mode, blank_before=not (_render_funnel_cta(funnel_error) or ends_blank))


@dataclass(frozen=True)
class _SummaryInputs:
    """What the bottom scorecard states about the run: scope, tier and elapsed time."""

    scope: ScopeInfo
    tier: str
    elapsed_ms: float


def _element_lookups(
    result: CombinedResult, ruleset_map: RulesetMap | None, project_root: Path
) -> tuple[Callable[[str], Element] | None, Callable[[str], list[str]] | None]:
    """The element and partner lookups, built once per run and only when an overlap line or a
    per-file overlap row will name an element."""
    names_elements = bool(
        result.cross_file or result.cross_file_coordinates or any(f.rule == "CORE:C:0044" for f in result.findings)
    )
    if not names_elements:
        return None, None
    return element_namer(ruleset_map, project_root), partner_lookup(result, project_root)


def _build_card_context(
    result: CombinedResult,
    ruleset_map: RulesetMap | None,
    project_root: Path,
    *,
    ascii_mode: bool,
    verbose: bool,
    file_type_by_path: dict[str, str],
    skill_of: dict[str, str] | None,
) -> tuple[CardContext, list[SurfaceHealth]]:
    """The per-run card context and the per-surface scores its group headers quote."""
    element_of, partners_of = _element_lookups(result, ruleset_map, project_root)
    atoms_by_path = (
        index_atoms_by_norm_path(ruleset_map.atoms, project_root)
        if ruleset_map is not None and ruleset_map.atoms
        else {}
    )
    aliases_by_file = build_aliases_by_file(project_root, result)
    surfaces = compute_surface_scores(
        result,
        ruleset_map=ruleset_map,
        project_root=project_root,
        file_type_by_path=file_type_by_path,
        skill_of=skill_of,
    )
    ctx = CardContext(
        sev_icons=get_sev_icons(ascii_mode),
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
    return ctx, surfaces


def _render_findings_and_scorecard(
    result: CombinedResult,
    ruleset_map: RulesetMap | None,
    *,
    ascii_mode: bool,
    verbose: bool,
    summary: _SummaryInputs,
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

    skill_of = skill_lookup(ruleset_map, project_root) if skill_of is None else skill_of
    ctx, surfaces = _build_card_context(
        result,
        ruleset_map,
        project_root,
        ascii_mode=ascii_mode,
        verbose=verbose,
        file_type_by_path=file_type_by_path,
        skill_of=skill_of,
    )
    groups = build_file_groups(result, file_type_by_path, project_root, skill_of, ctx.aliases_by_file)
    _render_file_groups(groups, ctx)
    _render_cross_file_coordinates(result, ctx.sev_icons, verbose)

    item_health = None
    if len(surfaces) == 1 and surfaces[0].item_count > 1:
        item_health = compute_item_scores(result, ruleset_map=ruleset_map, project_root=project_root, skill_of=skill_of)

    print_scorecard(
        result,
        result.quality is not None,
        tier=summary.tier,
        elapsed_ms=summary.elapsed_ms,
        agent=_detect_agent_name(ruleset_map, result.stats.agents),
        scope=summary.scope,
        verbose=verbose,
        detail=ScorecardDetail(
            surface_health=surfaces,
            item_health=item_health,
            project_root=project_root,
            element_of=ctx.element_of,
        ),
    )


def _render_funnel_cta(funnel_error: FunnelError | None) -> bool:
    """Render the conversion CTA + bug-report link when a FunnelError is present.

    Returns True when it printed, which is always followed by a blank line.
    """

    if funnel_error is None:
        return False
    cta = format_cta(funnel_error)
    if not cta:
        return False
    if funnel_error.retryable:
        console.print()
        console.print(f"  [yellow]⚠[/yellow]  {cta}")
        console.print()
        return True
    bug_url = format_bug_report_url(funnel_error)
    bug_label = _short_url_label(bug_url)
    console.print()
    console.print("  [yellow]⚠[/yellow]  Server diagnostics unavailable.")
    console.print("  " + cta.replace("\n", "\n  "))
    if funnel_error.error not in KNOWN_ERRORS:
        link = f"[link={bug_url}][bold]{bug_label}[/bold][/link]"
        console.print(f"  [dim]Did you see an error? Let us know: {link}[/dim]")
    console.print()
    return True
