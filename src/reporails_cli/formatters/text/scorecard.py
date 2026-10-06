"""Scorecard rendering for text-mode CLI output.

Renders the bottom summary section: score bar, scope, findings, compliance, CTA.
"""

from __future__ import annotations

import fnmatch
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.text import Text

from reporails_cli.core.discovery.features import agent_main_literal_paths, agent_rule_surface_markers
from reporails_cli.formatters.text.display_constants import (
    HRULE,
    Element,
    display_rule_id,
    element_namer,
    get_term_width,
    group_element_pairs,
    partner_list,
    path_tag,
    rule_docs_url,
    rule_title,
    skill_lookup,
)
from reporails_cli.formatters.text.score import score_color
from reporails_cli.formatters.text.verdict import (
    _plural,
    _render_verdict_block,
    _score_bar,
    compute_score,
    console,
)
from reporails_cli.formatters.triage import split_conventions

__all__ = ["ScopeInfo", "SurfaceHealth", "compute_score", "compute_surface_scores", "print_scorecard"]


# ── Score computation ─────────────────────────────────────────────────


def _hint_totals(result: Any) -> tuple[int, int]:
    """Sum hint error and warning counts from result.hints."""
    if not result.hints:
        return 0, 0
    errors = sum(getattr(h, "error_count", 0) for h in result.hints)
    warnings = sum(getattr(h, "warning_count", 0) for h in result.hints)
    return errors, warnings


# ── Surface health ────────────────────────────────────────────────────

_SURFACE_NAMES = {
    "main": "Main",
    "nested": "Nested",
    "rules": "Rules",
    "skills": "Skills",
    "agents": "Agents",
    "memory": "Memory",
    "imported": "Imported",
}
# `imported` (eager `@`-imports) earns a scored bar. `referenced` (discoverable markdown
# links) deliberately gets NO surface bar — the harness never loads it, so a score would be
# a false signal; its findings surface in the Referenced file-panel group instead.
_SURFACE_ORDER = ["main", "nested", "rules", "skills", "agents", "memory", "imported"]


def _surface_key(rel: str, ft_by_path: dict[str, str], skill_of: dict[str, str] | None) -> str:
    """Surface tag for a path.

    A file inside a skill folder is on the Skills surface first, whatever else marks it. With a
    skill lookup (a ruleset map is present) membership alone decides Skills, so a `SKILL.md`
    outside every skill folder is a plain file; without one the path-based tag decides.
    `@`-import-reached files (`file_type == "generic"`, eager) map to the Imported surface; every
    other path takes the `path_tag` tag, corrected for two shapes a path-only, Claude-shaped
    classifier cannot see on its own: an agent whose main file sits one fixed directory deep
    (Copilot) reads as `nested`, and a path-scoped rule surface named or extended differently
    from Claude's own (`.github/instructions/*.instructions.md`, Cursor's `.mdc`) matches nothing
    at all and falls back to the generic `file` tag. Both are re-keyed here from every agent's
    own bundled config.
    """
    if skill_of is not None and rel in skill_of:
        return "skills"
    if ft_by_path.get(rel, "") == "generic":
        return "imported"
    tag = path_tag(rel, skill_of).split(":")[0]
    if tag in ("nested", "file") and rel.lstrip("/") in agent_main_literal_paths():
        return "main"
    if tag == "file":
        parts = Path(rel).parts
        name = Path(rel).name
        dir_names, filename_globs = agent_rule_surface_markers()
        if dir_names & set(parts) and any(fnmatch.fnmatchcase(name, g) for g in filename_globs):
            return "rules"
    return tag


@dataclass
class SurfaceHealth:
    """Per-surface health score for the scorecard."""

    name: str
    # `None` marks an unscored item/surface (no charged atoms — a non-instruction
    # surface or an empty instruction file); rendered as "not scored", no bar/band.
    score: float | None
    file_count: int
    finding_count: int
    # Items beside the type name: a skill folder counts once, every other file once.
    item_count: int
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
    file_type_by_path: dict[str, str] | None = None,
    skill_of: dict[str, str] | None = None,
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
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    root = Path(project_root) if project_root is not None else Path.cwd()

    # Per-path classifier file_type (computed at the composition root for generic-scanned
    # files) routes `@`-import-reached files to the Imported surface.
    ft_by_path = file_type_by_path or {}
    skill_of = skill_lookup(ruleset_map, root) if skill_of is None else skill_of

    # Files per surface from ruleset_map (authoritative file list)
    surface_paths: dict[str, set[str]] = {}
    if ruleset_map is not None:
        try:
            for fr in ruleset_map.files:
                rel = normalize_finding_path(fr.path, root)
                surface_paths.setdefault(_surface_key(rel, ft_by_path, skill_of), set()).add(rel)
        except (AttributeError, TypeError):
            pass

    # Group findings and per-file analysis by surface, re-normalizing defensively. Server
    # per-file paths are absolute, but `main` keys on root-level path depth, so normalize to
    # the project-relative form first or every absolute path falls out of `main`.
    def by_surface(items: Any) -> dict[str, list[Any]]:
        grouped: dict[str, list[Any]] = {}
        for it in items:
            key = _surface_key(normalize_finding_path(it.file, root), ft_by_path, skill_of)
            grouped.setdefault(key, []).append(it)
        return grouped

    surface_findings, surface_analysis = by_surface(result.findings), by_surface(result.per_file_analysis)

    # Collect all surfaces from any source
    all_keys = set(surface_findings) | set(surface_analysis) | set(surface_paths)

    surfaces = []
    for key in _SURFACE_ORDER:
        if key not in all_keys:
            continue
        display_name = _SURFACE_NAMES.get(key, key.title())
        findings = surface_findings.get(key, [])
        analyses = surface_analysis.get(key, [])

        by_severity = Counter(f.severity for f in findings)
        # Files: prefer mapper discovery, fall back to the files findings/analysis name.
        paths = surface_paths.get(key) or {
            normalize_finding_path(p, root) for p in [*(f.file for f in findings), *(a.file for a in analyses)]
        }

        surfaces.append(
            SurfaceHealth(
                name=display_name,
                # Mean of the reported per-file display scores over the surface's files.
                score=_mean_display_score(analyses),
                file_count=len(paths),
                item_count=len({(skill_of or {}).get(p, p) for p in paths}),
                finding_count=len(findings),
                errors=by_severity["error"],
                warnings=by_severity["warning"],
                infos=by_severity["info"],
                category_breakdown=_count_categories(findings),
            )
        )
    return surfaces


def _mean_display_score(analyses: list[Any]) -> float | None:
    """Atom-weighted mean of the reported per-file display scores.

    A surface's bar (and the filtered headline) aggregate the same way the
    whole-project headline does. Unscored files (`display_score`
    is `None`) are excluded from the aggregation. Falls back to a
    simple mean when atom counts are unavailable; `None` when there is no scored analysis to aggregate.
    """
    scored = [
        (float(fa.display_score), int(fa.stats.get("atoms", 0)))
        for fa in analyses
        if fa is not None and fa.display_score is not None
    ]
    if not scored:
        return None
    total_weight = sum(w for _, w in scored)
    if total_weight <= 0:
        return round(sum(s for s, _ in scored) / len(scored), 1)
    return round(sum(s * w for s, w in scored) / total_weight, 1)


def _count_categories(findings: list[Any]) -> dict[str, int]:
    """Group findings by rule-id-derived Category value.

    Canonicalizes each finding's rule id first (a bare client-check token like
    `format` maps to `CORE:E:0003`), pulls the second segment, and maps it via
    `CATEGORY_CODES`. Only ids that still lack a known code after canonicalization
    are skipped, so the breakdown stays consistent with the per-finding categories.
    """
    from reporails_cli.core.platform.dto.models import CATEGORY_CODES

    counts: Counter[str] = Counter()
    for f in findings:
        parts = display_rule_id(f.rule or "").split(":")
        if len(parts) < 2:
            continue
        category = CATEGORY_CODES.get(parts[1])
        if category is None:
            continue
        counts[category.value] += 1
    return dict(counts)


def _surface_cell(s: SurfaceHealth, bar_width: int = 15, label_width: int = 13, count_width: int = 0) -> str:
    """Format one surface as a Rich-markup cell: 'Name (N):  ▓▓▓▓▓▓▓▓▓▓▓░░░░  7.2  27 findings · 10 errors'.

    bar_width=15 is the smallest width that visually distinguishes 6.9 from 7.2
    under integer rounding — at width 10, scores 6.5-7.4 all map to 7 filled cells.
    label_width pads the name column to the widest label in the set so the two
    columns stay aligned when a long name carries a 2-digit count; count_width
    right-aligns the finding counts the same way.
    """
    label = f"{s.name} ({s.item_count}):"
    tag = _count_tag(s, count_width)
    if s.score is None:
        empty = "░" * bar_width
        return f"{label:<{label_width}s} [dim]{empty}[/dim]  [dim]not scored[/dim]{tag}"
    color = score_color(s.score)
    bar = _score_bar(s.score, bar_width, color)
    return f"{label:<{label_width}s} {bar}  [{color} bold]{s.score:>4.1f}[/{color} bold]{tag}"


def _count_tag(s: SurfaceHealth, count_width: int = 0) -> str:
    """Tag beside a health bar: `N findings · M errors` (the error part only when M > 0).

    One axis, whole then part, so the row answers "which surface is worst" without
    competing with the bar. Empty when the surface has no findings at all.
    """
    if not s.finding_count:
        return ""
    count = f"{s.finding_count:,}".rjust(count_width)
    tag = f"  [dim]{count} finding{'' if s.finding_count == 1 else 's'}[/dim]"
    if s.errors:
        tag += f"[dim] · [/dim][red]{_plural(s.errors, 'error')}[/red]"
    return tag


def _render_surface_health(surfaces: list[SurfaceHealth]) -> None:
    """Render compact 2-column per-surface health bars.

    Single-surface case is suppressed: the top `Score:` already
    represents that surface, so a second bar would just restate the
    same number.
    """
    if len(surfaces) <= 1:
        return
    label_width = max(len(f"{s.name} ({s.item_count}):") for s in surfaces)
    count_width = max(len(f"{s.finding_count:,}") for s in surfaces)
    cells = [_surface_cell(s, label_width=label_width, count_width=count_width) for s in surfaces]
    # Pair two cells per row only when the widest pair fits the terminal; a pair
    # that overflows wraps its second label onto the next line and the grid
    # stops reading as rows.
    widest = max(Text.from_markup(c).cell_len for c in cells)
    per_row = 2 if 2 + widest + 4 + widest <= get_term_width() else 1
    console.print()
    for i in range(0, len(cells), per_row):
        row = cells[i : i + per_row]
        console.print("  " + "    ".join(row))


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


_NAMED_OVERLAP_PAIRS = 3  # element lines the scorecard names; the rest are counted
_OVERLAP_HINT = "ails check -v shows each file's overlaps"


def _render_cross_file_counts(
    result: Any, project_root: Path | None = None, element_of: Callable[[str], Element] | None = None
) -> None:
    """Render the cross-file repetition and topic-overlap counts.
    With detailed rows the headline counts the element pairs named below; else the `stats` count stands.
    """
    from reporails_cli.core.platform.runtime.merger import overlapping_pairs

    n_reps = getattr(result.stats, "cross_file_repetitions", 0)
    if n_reps:
        console.print(f"  {n_reps} cross-file repetition{'s' if n_reps != 1 else ''}")
    n_pairs = getattr(result.stats, "cross_file_overlaps", 0)
    if not n_pairs:
        return
    groups: list[tuple[str, list[str]]] = []
    if pairs := overlapping_pairs(result.cross_file):
        element_of = element_of or element_namer(None, project_root)
        groups = group_element_pairs([(element_of(file_1), element_of(file_2)) for file_1, file_2 in pairs])
        n_pairs = sum(len(partners) for _head, partners in groups)
        if not n_pairs:
            return
    noun = "pair overlaps" if n_pairs == 1 else "pairs overlap"
    console.print(f"  {n_pairs} element {noun} in topic \u2014 keep each topic in one file")
    width = max((len(head) for head, _ in groups[:_NAMED_OVERLAP_PAIRS]), default=0)
    for head, partners in groups[:_NAMED_OVERLAP_PAIRS]:
        console.print(f"    [dim]{head:<{width}} \u2194 {partner_list(partners)}[/dim]")
    if hidden := sum(len(partners) for _head, partners in groups[_NAMED_OVERLAP_PAIRS:]):
        console.print(f"    [dim]+{hidden} more pair{'s' * (hidden != 1)} \u00b7 {_OVERLAP_HINT}[/dim]")


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
            display_rule_id(f.rule),
            {"count": 0, "severity": f.severity, "message": f.message},
        )
        bucket["count"] += 1
        if _RULE_SEVERITY_RANK.get(f.severity, 3) < _RULE_SEVERITY_RANK.get(bucket["severity"], 3):
            bucket["severity"] = f.severity
    rows = [(rule, b["count"], b["severity"], b["message"]) for rule, b in buckets.items()]
    rows.sort(key=lambda r: (-r[1], r[0]))
    return rows[:limit]


_QUOTE_CHARS = "'\"`"


def _open_quote_start(text: str) -> int | None:
    """Index of the quote or backtick that `text` leaves open, or None when it closes every one.

    An apostrophe inside a word (`don't`) is not a quote."""
    opener: str | None = None
    start = 0
    for i, ch in enumerate(text):
        if ch not in _QUOTE_CHARS:
            continue
        if opener is None:
            if ch == "'" and i > 0 and text[i - 1].isalnum():
                continue
            opener, start = ch, i
        elif ch == opener:
            opener = None
    return start if opener is not None else None


def _first_sentence(message: str) -> str:
    """The message up to its first sentence end, never ending inside a quoted or backticked token."""
    for i, ch in enumerate(message):
        ends_sentence = ch == "—" or (ch == "." and (i + 1 == len(message) or message[i + 1].isspace()))
        if ends_sentence and _open_quote_start(message[:i]) is None:
            return message[:i].strip()
    return message.strip()


def _fit(text: str, width: int) -> str:
    """`text` cut to `width` columns with an ellipsis, backing off a token the cut would split."""
    if len(text) <= width:
        return text
    cut = text[: width - 1]
    opened = _open_quote_start(cut)
    if opened is not None and opened > 0:
        cut = cut[:opened]
    return cut.rstrip() + "…"


def _rule_label(rule: str, message: str) -> str:
    """What a Top-rules row says about a rule: its title, else the message's first sentence."""
    return rule_title(rule) or _first_sentence(message)


def _render_top_rules(result: Any, verbose: bool = True) -> None:
    """Render the Top-rules block in the whole-repo scorecard.

    Outside verbose output the documentation conventions are left out, as they are in the file cards.
    """
    findings, _ = split_conventions(result.findings, verbose)
    if not findings:
        return
    rows = _aggregate_top_rules(findings)
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
        snippet = _fit(_rule_label(rule, message), snippet_w)
        # Hyperlink the ID but pad by its visible length — the link markup is zero-width.
        url = rule_docs_url(rule)
        rule_cell = f"[link={url}]{rule}[/link]" if url else rule
        pad = " " * max(0, rule_w - len(rule))
        console.print(f"    {rule_cell}{pad} x{count:<{count_w}} {label}  {snippet}")


def _render_results_summary(
    result: Any,
    hint_errors: int,
    hint_warnings: int,
    project_root: Path | None = None,
    element_of: Callable[[str], Element] | None = None,
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

    _render_cross_file_counts(result, project_root, element_of)

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
    verbose: bool = False,
    project_root: Path | None = None,
    element_of: Callable[[str], Element] | None = None,
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

    _render_verdict_block(result, has_quality, n_atoms, elapsed_ms, hint_errors=hint_errors, verbose=verbose)

    if agent:
        console.print(f"  Agent: {agent.title()}")
    else:
        console.print("  Agent: not determined, only the rules every agent shares ran")
        console.print("  [dim]Name your agent: --agent <name>, or ails config set default_agent <name>[/dim]")

    level = getattr(result, "level", Level.L0)
    label = LEVEL_LABELS.get(level, "Unknown")
    console.print(f"  Level: {level.value} [bold]{label}[/bold]")

    # Offline runs carry no server scores, so suppress the per-surface / per-item bars
    # entirely — rendering every surface as "not scored" reads as broken. The "Quality
    # n/a (server diagnostics unavailable)" headline already states the offline state.
    multi_surface = has_quality and surface_health is not None and len(surface_health) > 1
    has_items = has_quality and item_health is not None and len(item_health) > 1
    if scope is not None:
        _render_scope(scope, has_surface_health=multi_surface or has_items)

    if multi_surface and surface_health is not None:
        _render_surface_health(surface_health)
        # Generic-scanned `@`-imports now count toward Quality — name the headline shift
        # so the number isn't a surprise the user has to reverse-engineer.
        if any(s.name == "Imported" for s in surface_health):
            console.print("\n  [dim]Imported files (@-imports) are eagerly loaded, so they count toward Quality.[/dim]")
    elif has_items and item_health is not None:
        from reporails_cli.formatters.text.item_scorecard import render_item_health

        render_item_health(item_health)

    _render_top_rules(result, verbose)

    _visible_findings, _pro_total = _render_results_summary(
        result, hint_errors, hint_warnings, project_root, element_of
    )

    # One line per run for an unpaid tier, in place of any per-finding remedy
    # (the reply carries none for an anonymous or free run) — keyed on whether a
    # key is held, not on the reported tier: a signed-in free user told to run
    # `ails auth login` is sent to a dead end. Never claims a fix for every
    # finding — only that Pro adds the remedies and the order to apply them.
    refused = getattr(result, "server_error", None) is not None
    if tier == "free" and not refused:
        from reporails_cli.core.platform.adapters.api_client import has_api_key
        from reporails_cli.formatters.text.funnel_cta import _SUBSCRIBE_URL

        console.print()
        console.print("  Pro adds the remedies and the order to apply them.")
        if has_api_key():
            console.print(f"  \u2192 [link={_SUBSCRIBE_URL}][bold]Upgrade to Pro[/bold] reporails.com/account[/link]")
        else:
            console.print("  \u2192 sign in with [bold]ails auth login[/bold], then upgrade to Pro")
    elif tier == "Pro" and not refused:
        console.print()
        console.print("  [dim]The remedies are in --format json. Run [bold]ails install[/bold], then[/dim]")
        console.print(
            "  [dim][bold]/reporails:ails heal[/bold] in Claude Code to rewrite your instruction files.[/dim]"
        )

    console.print()
