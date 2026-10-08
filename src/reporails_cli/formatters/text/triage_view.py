"""File-card rendering with leverage-based finding triage.

Renders one file's card. When a confident per-file read is available, the
findings that carry the most weight stay as lines and the rest collapse into
a single `+N more` row. Verbose and low-confidence runs fall back to the full
per-line view.
"""

from __future__ import annotations

import contextlib
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from rich.console import Console

from reporails_cli.core.lint.client_checks import PACKED_SENTENCE_RULE
from reporails_cli.formatters.text.display_constants import (
    AGG_ORDER,
    AGGREGATE_KEY,
    AGGREGATE_LABELS,
    AGGREGATE_RULES,
    HINT_TYPE_LABELS,
    SEV_WEIGHT,
    Element,
    conventions_phrase,
    counted,
    element_labels,
    element_namer,
    friendly_name,
    get_term_width,
    path_tag,
    per_file_stats,
    short_path,
    truncate,
)
from reporails_cli.formatters.text.rule_meta import linked_rule_id
from reporails_cli.formatters.triage import Regime, TriageFinding, is_triaged, split_conventions, triage

console = Console()


# ── Inline hints ──────────────────────────────────────────────────────


def _print_inline_hints(file_hints: list[Any], border: str) -> None:
    """Render inline Pro diagnostic counts inside a file card (free tier)."""
    pro_total = sum(h.count for h in file_hints)
    pro_errors = sum(getattr(h, "error_count", 0) for h in file_hints)
    err_str = f" ({counted(pro_errors, 'error')})" if pro_errors else ""
    sorted_hints = sorted(file_hints, key=lambda h: SEV_WEIGHT.get(getattr(h, "severity", "warning"), 9))
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
    console.print(f"  [dim]{border}     ⊕ {counted(pro_total, 'Pro diagnostic')}{err_str}{cat_str}[/dim]")


# ── Packed sentences ──────────────────────────────────────────────────

# A nested line sits this many columns right of its sentence's row.
_NEST_INDENT = 4


def _packed_children(findings: list[Any]) -> dict[int, list[Any]]:
    """Per line holding a packed-sentence finding, the instruction findings that print under it.

    The first packed-sentence finding of a line holds the line's findings that address an
    instruction (`pi` set); later ones hold nothing. Line 0 and 1 carry whole-file findings,
    so a packed sentence there holds nothing.
    """
    lines = {f.line for f in findings if f.rule == PACKED_SENTENCE_RULE and f.line > 1}
    out: dict[int, list[Any]] = {line: [] for line in lines}
    for f in findings:
        if f.rule != PACKED_SENTENCE_RULE and f.pi is not None and f.line in out:
            out[f.line].append(f)
    return out


def _print_nested(
    children: list[tuple[str, str, str, int]],
    sev_icons: dict[str, str],
    border: str,
    msg_width: int,
) -> None:
    """Print `(severity, message, rule, count)` rows indented beneath their sentence's row."""
    pad = " " * _NEST_INDENT
    for sev, msg, rule, count in children:
        suffix = f" (\u00d7{count})" if count > 1 else ""
        text = truncate(f"{msg}{suffix}", msg_width - _NEST_INDENT).replace("[", "\\[")
        console.print(
            f"  [dim]{border}[/dim]   {pad}{sev_icons.get(sev, ' ')} {text}  [dim]{linked_rule_id(rule)}[/dim]"
        )


def _group_plain(findings: list[Any]) -> list[tuple[str, str, str, int]]:
    """Order plain findings by severity and fold identical `(rule, message)` repeats into counts."""
    counts: dict[tuple[str, str, str], int] = {}
    for f in sorted(findings, key=lambda f: (SEV_WEIGHT.get(f.severity, 9), f.rule)):
        msg = f.message or AGGREGATE_LABELS.get(f.rule, f.rule)
        key = (f.severity, msg, f.rule)
        counts[key] = counts.get(key, 0) + 1
    return [(sev, msg, rule, n) for (sev, msg, rule), n in counts.items()]


# ── Neutral (non-triaged) renderers ───────────────────────────────────


def _line_cell(line: int) -> str:
    """The `L12   ` cell in front of a finding's message; a whole-file finding (line 0 or 1) has none."""
    return f"L{line:<4d} " if line > 1 else ""


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
        rule_id = linked_rule_id(f.rule)
        console.print(f"  [dim]{border}[/dim]   {icon} {_line_cell(f.line)}{msg}  [dim]{rule_id}[/dim]")
    if len(structural) > limit:
        console.print(f"  [dim]{border}     ... and {len(structural) - limit} more[/dim]")


def _render_quality_verbose(
    findings: list[Any],
    border: str,
    msg_width: int,
    nested: dict[int, list[Any]] | None = None,
    sev_icons: dict[str, str] | None = None,
) -> None:
    """Render quality findings in verbose mode (deduped per-line detail).

    The findings in `nested` (by line) print indented beneath their line's packed-sentence row.
    """
    nested = dict(nested or {})
    quality_findings = [f for f in findings if f.rule in AGGREGATE_RULES]
    quality_findings.sort(key=lambda f: (f.line, f.rule))
    seen_q: dict[tuple[int, str, str], int] = {}
    for f in quality_findings:
        msg = f.message or AGGREGATE_LABELS.get(f.rule, f.rule)
        key = (f.line, msg, f.rule)
        seen_q[key] = seen_q.get(key, 0) + 1
    for (line, msg, rule), count in seen_q.items():
        line_ref = _line_cell(line)
        suffix = f" ({count}\u00d7)" if count > 1 else ""
        console.print(
            f"  [dim]{border}     {line_ref}{truncate(f'{msg}{suffix}', msg_width)}  {linked_rule_id(rule)}[/dim]"
        )
        if rule == PACKED_SENTENCE_RULE and nested.get(line):
            _print_nested(_group_plain(nested.pop(line)), sev_icons or {}, border, msg_width)


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


# One finding's own length, e.g. `(6 words)`: wrong for every other line in a grouped row.
_WORD_COUNT_RE = re.compile(r"\s*\(\d+ words?\)")


def _generalize_message(message: str, rule: str) -> str:
    """Strip instance-specific detail so same-rule findings dedup to one line.

    `Buried instruction at position 12 of 79 \u2014 vague` -> `Buried instruction`;
    `Vague instruction \u2014 doesn't name...` -> `Vague instruction`;
    `Too brief (6 words) \u2014 ...` -> `Too brief`. Falls back to the aggregate label,
    then the rule id, when no message survives.
    """
    head = message.split(" at position")[0].split(" \u2014 ")[0].split(". ")[0]
    head = _WORD_COUNT_RE.sub("", head).strip()
    return head or AGGREGATE_LABELS.get(rule, rule)


def _group_shown(shown: tuple[TriageFinding, ...]) -> list[tuple[str, str, str, int]]:
    """Order shown findings by display severity, dedup same-rule repeats to counts.

    Returns `(severity, message, rule, count)` rows. A single occurrence
    keeps its full message; repeats collapse to a generalized message + `(xN)`.
    """
    ordered = sorted(shown, key=lambda tf: (SEV_WEIGHT.get(tf.display_severity, 9), tf.finding.rule, tf.finding.line))
    by_rule: dict[tuple[str, str], list[TriageFinding]] = {}
    for tf in ordered:
        by_rule.setdefault((tf.display_severity, tf.finding.rule), []).append(tf)
    rows: list[tuple[str, str, str, int]] = []
    for (sev, rule), tfs in by_rule.items():
        msgs = [tf.finding.message or AGGREGATE_LABELS.get(tf.finding.rule, tf.finding.rule) for tf in tfs]
        message = msgs[0] if len(msgs) == 1 else _generalize_message(msgs[0], rule)
        rows.append((sev, message, rule, len(tfs)))
    return rows


def _triaged_entries(shown: tuple[TriageFinding, ...]) -> list[tuple[str, Any]]:
    """The shown findings as display entries in severity order.

    A `("row", row)` entry is a grouped `(severity, message, rule, count)` row; a
    `("packed", (head, children))` entry is a packed-sentence finding with the other shown
    findings of its line.
    """
    heads = sorted(
        (tf for tf in shown if tf.finding.rule == PACKED_SENTENCE_RULE and tf.finding.line > 1),
        key=lambda tf: tf.finding.line,
    )
    held = _packed_children([tf.finding for tf in shown])
    owner_by_line: dict[int, TriageFinding] = {}
    for tf in heads:
        owner_by_line.setdefault(tf.finding.line, tf)
    child_ids = {id(f) for fs in held.values() for f in fs}
    children = [tf for tf in shown if id(tf.finding) in child_ids]
    claimed = {id(tf) for tf in (*heads, *children)}
    rest = tuple(tf for tf in shown if id(tf) not in claimed)
    entries: list[tuple[int, str, Any]] = [(SEV_WEIGHT.get(row[0], 9), "row", row) for row in _group_shown(rest)]
    for tf in heads:
        owns = owner_by_line[tf.finding.line] is tf
        kids = tuple(c for c in children if c.finding.line == tf.finding.line) if owns else ()
        entries.append((SEV_WEIGHT.get(tf.display_severity, 9), "packed", (tf, kids)))
    entries.sort(key=lambda e: e[0])
    return [(kind, payload) for _w, kind, payload in entries]


def _print_row(
    row: tuple[str, str, str, int],
    sev_icons: dict[str, str],
    border: str,
    msg_width: int,
    line_ref: str = "",
) -> None:
    """Print one `(severity, message, rule, count)` row of the triaged view."""
    sev, msg, rule, count = row
    suffix = f" (\u00d7{count})" if count > 1 else ""
    text = truncate(f"{msg}{suffix}", msg_width - len(line_ref)).replace("[", "\\[")
    console.print(
        f"  [dim]{border}[/dim]   {sev_icons.get(sev, ' ')} {line_ref}{text}  [dim]{linked_rule_id(rule)}[/dim]"
    )


def _render_triaged(
    findings: list[Any],
    sev_icons: dict[str, str],
    border: str,
    msg_width: int,
) -> None:
    """Render graded findings that matter as lines, collapse the rest."""
    result = triage(findings, verbose=False)
    for kind, payload in _triaged_entries(result.shown):
        if kind == "row":
            _print_row(payload, sev_icons, border, msg_width)
            continue
        head, children = payload
        message = head.finding.message or AGGREGATE_LABELS.get(PACKED_SENTENCE_RULE, PACKED_SENTENCE_RULE)
        row = (head.display_severity, message, PACKED_SENTENCE_RULE, 1)
        _print_row(row, sev_icons, border, msg_width, f"L{head.finding.line} ")
        _print_nested(_group_shown(children), sev_icons, border, msg_width)
    if result.collapsed:
        n = len(result.collapsed)
        console.print(f"  [dim]{border}     ◦ +{n} more · -v to list[/dim]")


_FILE_OVERLAP_RULE = "CORE:C:0044"
_FILE_OVERLAP_MESSAGE = re.compile(r"\d+% of the instructions in this file and ")


def _is_file_overlap(f: Any) -> bool:
    """Whether a finding is the file-pair topic overlap: it concerns the whole file, whatever line it is pinned to."""
    return f.rule == _FILE_OVERLAP_RULE and bool(_FILE_OVERLAP_MESSAGE.match(f.message or ""))


_OVERLAP_PARTNER = re.compile(r"(\d+)% of the instructions in this file and `([^`]+)`")


def _overlap_partner(full: str, filepath: str, element_of: Callable[[str], Element]) -> Element:
    """The element an overlap names; a sibling file of the card's own element is named by its path inside it."""
    partner = element_of(full)
    if partner.key != element_of(filepath).key:
        return partner
    inside = full
    with contextlib.suppress(ValueError):
        inside = str(PurePosixPath(full).relative_to(partner.where))
    return Element(full, inside, "same skill", full)


def _render_file_overlaps(
    findings: list[Any],
    border: str,
    msg_width: int,
    element_of: Callable[[str], Element] | None,
    filepath: str = "",
    resolve: Callable[[str, str], str] | None = None,
) -> None:
    """Print the file-pair overlap findings once each, unanchored, right under the file's header.

    Each partner element gets one row, `NN% topic overlap with <partner element>` at its highest
    percentage, highest first; a message that does not parse prints as sent, after them."""
    element_of = element_of or element_namer(None, None)
    best: dict[Element, int] = {}
    unparsed: list[str] = []
    for f in findings:
        if m := _OVERLAP_PARTNER.search(f.message or ""):
            partner = _overlap_partner(resolve(filepath, m[2]) if resolve else m[2], filepath, element_of)
            best[partner] = max(best.get(partner, -1), int(m[1]))
        elif (text := truncate(f.message, msg_width)) not in unparsed:
            unparsed.append(text)
    label = element_labels(best)
    parsed = [f"{pct}% topic overlap with {label[e.key]}" for e, pct in sorted(best.items(), key=lambda kv: -kv[1])]
    for text in (*parsed, *unparsed):
        console.print(
            f"  [dim]{border}     {text.replace('[', chr(92) + '[')}  {linked_rule_id(_FILE_OVERLAP_RULE)}[/dim]"
        )


def _render_card_body(
    findings: list[Any],
    sev_icons: dict[str, str],
    verbose: bool,
    regime: Regime | None,
    border: str,
    msg_width: int,
) -> None:
    """Render the finding body: triaged when the file's token asks for it and a finding is graded, else neutral."""
    if not verbose and is_triaged(findings, regime):
        _render_triaged(findings, sev_icons, border, msg_width)
        return
    nested = _packed_children(findings) if verbose else {}
    nested_ids = {id(f) for fs in nested.values() for f in fs}
    structural = [f for f in findings if f.rule not in AGGREGATE_RULES and id(f) not in nested_ids]
    _render_structural_findings(structural, sev_icons, verbose, border, msg_width)
    if verbose:
        _render_quality_verbose([f for f in findings if id(f) not in nested_ids], border, msg_width, nested, sev_icons)
    else:
        quality_counts: Counter[str] = Counter(
            AGGREGATE_KEY.get(f.rule, f.rule) for f in findings if f.rule in AGGREGATE_RULES
        )
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
    atoms_by_path: dict[str, list[Any]] | None = None,
    skill_of: dict[str, str] | None = None,
    element_of: Callable[[str], Element] | None = None,
    partner_of: Callable[[str, str], str] | None = None,
) -> None:
    """Print one file's card: name, stats, triaged findings (or neutral fallback). `skill_of` is the
    skill-folder lookup; a file in a skill folder is named inside it."""
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    norm = normalize_finding_path(filepath, project_root or Path.cwd())
    skill_dir = (skill_of or {}).get(norm)
    if skill_dir:
        name = friendly_name(norm, path_tag(filepath, skill_of, norm), skill_dir)
    elif skill_of is not None and PurePosixPath(norm).name == "SKILL.md":
        name = norm  # a SKILL.md in no skill is a plain file, named by its path
    else:
        name = friendly_name(filepath, path_tag(filepath, skill_of, norm))
    alias_list = (aliases_by_file or {}).get(filepath, [])
    name = f"{name}{_format_alias_suffix(filepath, alias_list)}"
    stats = per_file_stats(filepath, ruleset_map, project_root or Path.cwd(), atoms_by_path)
    border = "│"
    msg_width = get_term_width() - 35

    console.print(f"  [dim]{border}[/dim] [bold]{name}[/bold]{f'  [dim]{stats}[/dim]' if stats else ''}")
    if verbose:
        short = short_path(filepath)
        if short != name:
            console.print(f"  [dim]{border}   {short}[/dim]")

    findings, conventions = split_conventions(findings, verbose)
    overlaps = [f for f in findings if _is_file_overlap(f)]
    _render_file_overlaps(overlaps, border, msg_width, element_of, filepath, partner_of)
    _render_card_body([f for f in findings if f not in overlaps], sev_icons, verbose, regime, border, msg_width)
    if conventions:
        console.print(f"  [dim]{border}     \u25e6 {conventions_phrase(len(conventions))} \u00b7 -v to list[/dim]")

    if file_hints:
        _print_inline_hints(file_hints, border)

    console.print(f"  [dim]{border}[/dim]")
