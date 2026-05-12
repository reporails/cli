"""Display functions for text-mode CLI output.

Renders file cards, file groups, cross-file coordinates, and the
master print_text_result dispatcher. Constants live in display_constants.py;
scorecard rendering lives in scorecard.py.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from rich.console import Console

from reporails_cli.formatters.text.display_constants import (
    AGG_ORDER,
    AGGREGATE_LABELS,
    AGGREGATE_RULES,
    HINT_SEV_ORDER,
    HINT_TYPE_LABELS,
    HRULE,
    SEV_WEIGHT,
    classify_file,
    file_type_summary,
    friendly_name,
    get_group_atoms,
    get_sev_icons,
    get_term_width,
    group_stats_line,
    per_file_stats,
    short_path,
    truncate,
)
from reporails_cli.formatters.text.scorecard import (
    ScopeInfo,
    compute_score,
    print_category_bars,
    print_score_line,
    print_scorecard,
)

console = Console()

# Re-export for backward compat (tests, other modules importing from display)
__all__ = [
    "compute_score",
    "print_category_bars",
    "print_score_line",
    "print_scorecard",
    "print_text_result",
]


# ── Inline hints ──────────────────────────────────────────────────────


def _print_inline_hints(file_hints: list[Any], border: str) -> None:
    """Render inline Pro diagnostic counts inside a file card (free tier)."""
    pro_total = sum(h.count for h in file_hints)
    pro_errors = sum(getattr(h, "error_count", 0) for h in file_hints)
    err_str = f" ({pro_errors} error{'s' if pro_errors != 1 else ''})" if pro_errors else ""
    sorted_hints = sorted(file_hints, key=lambda h: HINT_SEV_ORDER.get(getattr(h, "severity", "warning"), 9))
    categories: list[str] = []
    seen: set[str] = set()
    for h in sorted_hints:
        label = HINT_TYPE_LABELS.get(h.diagnostic_type, h.diagnostic_type)
        if label not in seen:
            categories.append(label)
            seen.add(label)
        if len(categories) >= 2:
            break
    cat_str = f" \u2014 {', '.join(categories)}" if categories else ""
    console.print(f"  [dim]{border}     \u2295 {pro_total} Pro diagnostics{err_str}{cat_str}[/dim]")


# ── File card ─────────────────────────────────────────────────────────


def _render_structural_findings(
    structural: list[Any],
    sev_icons: dict[str, str],
    verbose: bool,
    border: str,
    msg_width: int,
) -> None:
    """Render structural (non-aggregate) findings in a file card."""
    structural.sort(key=lambda f: SEV_WEIGHT.get(f.severity, 9))
    limit = 2 if not verbose else 999
    for f in structural[:limit]:
        icon = sev_icons.get(f.severity, " ")
        raw = f.message or ""
        msg = truncate(raw, msg_width).replace("[", "\\[")
        line_ref = f"L{f.line:<4d} " if f.line > 1 else "      "
        rule_id = f.rule.replace("[", "\\[")
        console.print(f"  [dim]{border}[/dim]   {icon} {line_ref}{msg}  [dim]{rule_id}[/dim]")
    if len(structural) > limit:
        console.print(f"  [dim]{border}     ... and {len(structural) - limit} more[/dim]")


def _render_quality_verbose(
    findings: list[Any],
    border: str,
    msg_width: int,
) -> None:
    """Render quality findings in verbose mode (deduped per-line detail)."""
    quality_findings = [f for f in findings if f.rule in AGGREGATE_RULES]
    quality_findings.sort(key=lambda f: (f.line, f.rule))
    seen_q: dict[tuple[int, str, str], int] = {}
    for f in quality_findings:
        msg = f.message or AGGREGATE_LABELS.get(f.rule, f.rule)
        key = (f.line, msg, f.rule)
        seen_q[key] = seen_q.get(key, 0) + 1
    for (line, msg, rule), count in seen_q.items():
        line_ref = f"L{line:<4d} " if line > 1 else "      "
        suffix = f" ({count}\u00d7)" if count > 1 else ""
        console.print(f"  [dim]{border}     {line_ref}{truncate(f'{msg}{suffix}', msg_width)}  {rule}[/dim]")


def _render_quality_compact(
    quality_counts: Counter[str],
    border: str,
    tw: int,
) -> None:
    """Render quality findings in compact mode (aggregate counts)."""
    parts = [f"{quality_counts[rule]} {AGGREGATE_LABELS[rule]}" for rule in AGG_ORDER if rule in quality_counts]
    if parts:
        agg_line = " \u00b7 ".join(parts)
        console.print(f"  [dim]{border}     {truncate(agg_line, tw - 8)}[/dim]")


def _format_alias_suffix(canonical: str, aliases: list[str]) -> str:
    """Build the ` (+alias1, +alias2)` label for a file with duplicates.

    Picks the shortest distinguishing fragment per alias — the differing leading
    path component when the alias lives under a different parent (e.g.
    `.claude/skills/foo` vs canonical `.agents/skills/foo` → render `+.claude`),
    or the filename when only the leaf differs (e.g. `AGENTS.md` vs `CLAUDE.md`
    in the same dir → render `+CLAUDE.md`).
    """
    if not aliases:
        return ""
    canonical_parts = Path(canonical).parts
    labels: list[str] = []
    for alias in aliases:
        alias_p = Path(alias)
        alias_parts = alias_p.parts
        label = alias_p.name
        for i, (c, a) in enumerate(zip(canonical_parts, alias_parts, strict=False)):
            if c != a:
                label = a if i < len(alias_parts) - 1 else alias_p.name
                break
        labels.append(label)
    return f" (+{', +'.join(labels)})"


def _print_file_card(
    filepath: str,
    findings: list[Any],
    sev_icons: dict[str, str],
    verbose: bool,
    ruleset_map: Any = None,
    file_hints: list[Any] | None = None,
    aliases_by_file: dict[str, list[str]] | None = None,
) -> None:
    """Print one file's card: name, stats, structural findings, then quality aggregate."""
    quality_counts: Counter[str] = Counter()
    structural: list[Any] = []
    for f in findings:
        if f.rule in AGGREGATE_RULES:
            quality_counts[f.rule] += 1
        else:
            structural.append(f)

    name = friendly_name(filepath, classify_file(filepath))
    alias_list = (aliases_by_file or {}).get(filepath, [])
    name = f"{name}{_format_alias_suffix(filepath, alias_list)}"
    stats = per_file_stats(filepath, ruleset_map)
    b = "\u2502"
    msg_width = get_term_width() - 35

    console.print(f"  [dim]{b}[/dim] [bold]{name}[/bold]{f'  [dim]{stats}[/dim]' if stats else ''}")
    if verbose:
        short = short_path(filepath)
        if short != name:
            console.print(f"  [dim]{b}   {short}[/dim]")

    _render_structural_findings(structural, sev_icons, verbose, b, msg_width)

    if verbose:
        _render_quality_verbose(findings, b, msg_width)
    else:
        _render_quality_compact(quality_counts, b, msg_width + 35)

    if file_hints:
        _print_inline_hints(file_hints, b)

    console.print(f"  [dim]{b}[/dim]")


# ── Group rendering ───────────────────────────────────────────────────

_GROUP_ORDER = ("main", "nested", "agent", "skill", "rule", "config", "memory")
_GROUP_LABELS = {
    "main": "Main",
    "nested": "Nested",
    "agent": "Agents",
    "skill": "Skills",
    "rule": "Rules",
    "config": "Config",
    "memory": "Memory",
}


def _render_group_header(gkey: str, group_files: list[tuple[str, list[Any]]], ruleset_map: Any) -> None:
    """Print group header with optional atom stats."""
    group_atoms = get_group_atoms(gkey, group_files, ruleset_map)
    stats = f"  [dim]{group_stats_line(group_atoms)}[/dim]" if group_atoms else ""
    label = _GROUP_LABELS.get(gkey, gkey.title())
    console.print(f"  [dim]\u250c\u2500[/dim] [bold]{label}[/bold] [dim]({len(group_files)})[/dim]{stats}")


def _render_one_group(
    gkey: str,
    group_files: list[tuple[str, list[Any]]],
    sev_icons: dict[str, str],
    verbose: bool,
    ruleset_map: Any,
    hints_by_file: dict[str, list[Any]],
    aliases_by_file: dict[str, list[str]] | None = None,
) -> None:
    """Render a single file group: header, file cards, footer."""
    _render_group_header(gkey, group_files, ruleset_map)
    b = "\u2502"
    max_cards = 3 if not verbose else 999

    for i, (filepath, findings) in enumerate(group_files):
        if i >= max_cards:
            remaining = sum(len(fs) for _, fs in group_files[i:])
            console.print(f"  [dim]{b}   ... and {len(group_files) - i} more ({remaining} findings)[/dim]")
            break
        _print_file_card(
            filepath,
            findings,
            sev_icons,
            verbose,
            ruleset_map=ruleset_map,
            file_hints=hints_by_file.get(filepath),
            aliases_by_file=aliases_by_file,
        )

    console.print(f"  [dim]\u2514\u2500 {sum(len(fs) for _, fs in group_files)} findings[/dim]\n")


def _render_file_groups(
    groups: dict[str, list[tuple[str, list[Any]]]],
    sev_icons: dict[str, str],
    verbose: bool,
    ruleset_map: Any,
    hints_by_file: dict[str, list[Any]],
    aliases_by_file: dict[str, list[str]] | None = None,
) -> None:
    """Render all file groups with cards."""
    for gkey in _GROUP_ORDER:
        group_files = groups.get(gkey, [])
        if group_files:
            _render_one_group(gkey, group_files, sev_icons, verbose, ruleset_map, hints_by_file, aliases_by_file)


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


def _build_file_groups(result: Any) -> dict[str, list[tuple[str, list[Any]]]]:
    """Group findings by file type, sorted worst-first within each group."""
    by_file: dict[str, list[Any]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    groups: dict[str, list[tuple[str, list[Any]]]] = {}
    for filepath, findings in by_file.items():
        if filepath in (".", ".:0"):
            continue
        tag = classify_file(filepath)
        group_key = tag.split(":")[0]
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
) -> None:
    """Print compact text output: files sorted worst-first, aggregated counts, scorecard at bottom.

    `funnel_error` is a FunnelError from the API client when a 4xx response or
    local preflight rejected the payload — surfaces the upgrade CTA below the
    scorecard so users see why server diagnostics are missing.
    """
    from reporails_cli.core.platform.runtime.merger import CombinedResult

    if not isinstance(result, CombinedResult):
        return

    project_root = Path.cwd()
    all_files, scope = _collect_files_and_scope(result, ruleset_map, project_root)
    has_quality = result.quality is not None and bool(result.quality.compliance_band)
    tier = _detect_tier(result, has_quality)
    scope.type_str = file_type_summary(all_files) if all_files else "0 files"

    _print_header(tier)
    if not result.findings:
        console.print(f"  {'ok' if ascii_mode else chr(0x2713)}  No findings.")
        _render_funnel_cta(funnel_error)
        return

    _render_findings_and_scorecard(result, ruleset_map, ascii_mode, verbose, scope, has_quality, tier, elapsed_ms)
    _render_funnel_cta(funnel_error)


def _render_findings_and_scorecard(
    result: Any,
    ruleset_map: Any,
    ascii_mode: bool,
    verbose: bool,
    scope: Any,
    has_quality: bool,
    tier: str,
    elapsed_ms: float,
) -> None:
    """Render file groups, cross-file coordinates, and the bottom scorecard."""
    from reporails_cli.formatters.text.scorecard import compute_surface_scores

    sev_icons = get_sev_icons(ascii_mode)
    hints_idx = _build_hints_by_file(result.hints, Path.cwd())
    aliases_idx = _build_aliases_by_file(Path.cwd(), result)
    _render_file_groups(_build_file_groups(result), sev_icons, verbose, ruleset_map, hints_idx, aliases_idx)
    _render_cross_file_coordinates(result, sev_icons)

    print_scorecard(
        result,
        has_quality,
        n_atoms=scope.n_atoms,
        tier=tier,
        elapsed_ms=elapsed_ms,
        agent=_detect_agent_name(ruleset_map),
        scope=scope,
        surface_health=compute_surface_scores(result, ruleset_map=ruleset_map, project_root=Path.cwd()),
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
