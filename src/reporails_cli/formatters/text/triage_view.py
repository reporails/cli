"""File-card rendering with leverage-based finding triage.

Renders one file's card. When a confident per-file read is available, the
high-leverage findings stay as lines and the low-leverage tail collapses into
a single `+N lower-priority` row (re-keyed by leverage). Verbose and
low-confidence runs fall back to the full per-line view.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from rich.console import Console

from reporails_cli.core.platform.policy.leverage import Regime, TriageFinding, triage
from reporails_cli.formatters.text.display_constants import (
    AGG_ORDER,
    AGGREGATE_LABELS,
    AGGREGATE_RULES,
    HINT_SEV_ORDER,
    HINT_TYPE_LABELS,
    SEV_WEIGHT,
    classify_file,
    friendly_name,
    get_term_width,
    per_file_stats,
    short_path,
    truncate,
)

console = Console()


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
    cat_str = f" — {', '.join(categories)}" if categories else ""
    console.print(f"  [dim]{border}     ⊕ {pro_total} Pro diagnostics{err_str}{cat_str}[/dim]")


# ── Neutral (non-triaged) renderers ───────────────────────────────────


def _print_action(fix: str, border: str, msg_width: int) -> None:
    """Render a finding's server action text as an indented `→` line (skipped when empty)."""
    if not fix:
        return
    action = truncate(" ".join(fix.split()), msg_width).replace("[", "\\[")
    console.print(f"  [dim]{border}       → {action}[/dim]")


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
        _print_action(getattr(f, "fix", ""), border, msg_width)
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
        agg_line = " · ".join(parts)
        console.print(f"  [dim]{border}     {truncate(agg_line, tw - 8)}[/dim]")


# ── Triaged renderer ──────────────────────────────────────────────────


def _generalize_message(message: str, rule: str) -> str:
    """Strip instance-specific detail so same-rule findings dedup to one line.

    `Buried instruction at position 12 of 79 \u2014 vague` -> `Buried instruction`;
    `Vague instruction \u2014 doesn't name...` -> `Vague instruction`. Falls back to
    the aggregate label, then the rule id, when no message survives.
    """
    head = message.split(" at position")[0].split(" \u2014 ")[0].split(". ")[0].strip()
    return head or AGGREGATE_LABELS.get(rule, rule)


def _group_shown(shown: tuple[TriageFinding, ...]) -> list[tuple[str, str, str, int, str]]:
    """Order shown findings by display severity, dedup same-rule repeats to counts.

    Returns `(severity, message, rule, count, fix)` rows. A single occurrence
    keeps its full message; repeats collapse to a generalized message + `(xN)`.
    `fix` is the server's per-finding action text (first occurrence in the group).
    """
    ordered = sorted(shown, key=lambda tf: (SEV_WEIGHT.get(tf.display_severity, 9), tf.finding.rule, tf.finding.line))
    by_rule: dict[tuple[str, str], list[TriageFinding]] = {}
    for tf in ordered:
        by_rule.setdefault((tf.display_severity, tf.finding.rule), []).append(tf)
    rows: list[tuple[str, str, str, int, str]] = []
    for (sev, rule), tfs in by_rule.items():
        msgs = [tf.finding.message or AGGREGATE_LABELS.get(tf.finding.rule, tf.finding.rule) for tf in tfs]
        message = msgs[0] if len(msgs) == 1 else _generalize_message(msgs[0], rule)
        fix = getattr(tfs[0].finding, "fix", "") or ""
        rows.append((sev, message, rule, len(tfs), fix))
    return rows


def _render_triaged(
    findings: list[Any],
    regime: Regime,
    sev_icons: dict[str, str],
    border: str,
    msg_width: int,
) -> None:
    """Render high-leverage findings as lines, collapse the low-leverage tail."""
    result = triage(findings, regime, verbose=False)
    for sev, msg, rule, count, fix in _group_shown(result.shown):
        icon = sev_icons.get(sev, " ")
        suffix = f" (\u00d7{count})" if count > 1 else ""
        text = truncate(f"{msg}{suffix}", msg_width).replace("[", "\\[")
        rule_id = rule.replace("[", "\\[")
        console.print(f"  [dim]{border}[/dim]   {icon} {text}  [dim]{rule_id}[/dim]")
        _print_action(fix, border, msg_width)
    if result.collapsed:
        n = len(result.collapsed)
        console.print(f"  [dim]{border}     ◦ +{n} lower-priority (won't move your score yet) · -v to list[/dim]")


def _render_card_body(
    findings: list[Any],
    sev_icons: dict[str, str],
    verbose: bool,
    regime: Regime | None,
    border: str,
    msg_width: int,
) -> None:
    """Render the finding body: triaged when a confident regime is present, else neutral."""
    if not verbose and regime is not None and regime.confident:
        _render_triaged(findings, regime, sev_icons, border, msg_width)
        return
    structural = [f for f in findings if f.rule not in AGGREGATE_RULES]
    _render_structural_findings(structural, sev_icons, verbose, border, msg_width)
    if verbose:
        _render_quality_verbose(findings, border, msg_width)
    else:
        quality_counts: Counter[str] = Counter(f.rule for f in findings if f.rule in AGGREGATE_RULES)
        _render_quality_compact(quality_counts, border, msg_width + 35)


# ── Alias suffix + file card ──────────────────────────────────────────


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


def print_file_card(
    filepath: str,
    findings: list[Any],
    sev_icons: dict[str, str],
    verbose: bool,
    regime: Regime | None = None,
    ruleset_map: Any = None,
    file_hints: list[Any] | None = None,
    aliases_by_file: dict[str, list[str]] | None = None,
    project_root: Path | None = None,
) -> None:
    """Print one file's card: name, stats, triaged findings (or neutral fallback)."""
    name = friendly_name(filepath, classify_file(filepath))
    alias_list = (aliases_by_file or {}).get(filepath, [])
    name = f"{name}{_format_alias_suffix(filepath, alias_list)}"
    stats = per_file_stats(filepath, ruleset_map, project_root or Path.cwd())
    border = "│"
    msg_width = get_term_width() - 35

    console.print(f"  [dim]{border}[/dim] [bold]{name}[/bold]{f'  [dim]{stats}[/dim]' if stats else ''}")
    if verbose:
        short = short_path(filepath)
        if short != name:
            console.print(f"  [dim]{border}   {short}[/dim]")

    _render_card_body(findings, sev_icons, verbose, regime, border, msg_width)

    if file_hints:
        _print_inline_hints(file_hints, border)

    console.print(f"  [dim]{border}[/dim]")
