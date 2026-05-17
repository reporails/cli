"""Focus-mode renderer for per-capability `ails check`.

When a capability target resolves to a small set of files, the per-group
scorecard is overkill — the operator wants every finding for those files
grouped by rule, plus a "next action" pointer. This renderer is the
output of `ails check <capability> <name>`.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from rich.console import Console

from reporails_cli.formatters.text.display_constants import get_term_width
from reporails_cli.formatters.text.scorecard import (
    _RULE_SEVERITY_LABEL,
    _RULE_SEVERITY_RANK,
)

console = Console()


def print_focus_result(
    result: Any,
    capability: str,
    name: str,
    agent: str,
    focus_paths: set[Path],
    project_root: Path,
    elapsed_ms: float,
    ruleset_map: Any = None,
) -> None:
    """Render the focus-mode output block.

    Layout:
      Reporails — <capability> <name> (<agent>)

        <file_path>
        Score: X.X / 10  ▓▓▓...
        <scope line: atom counts>

        Findings by rule (N):
          RULE_ID  xcount  severity  message
            line refs

        Cross-file: <count> involving this file …  (when present)

        Next: fix RULE_ID (xcount) — highest-frequency warning.
    """
    rel_paths = sorted(_to_rel(p, project_root) for p in focus_paths)
    findings = [f for f in result.findings if f.file in {str(p) for p in rel_paths}]

    header = f"[bold]Reporails[/bold] — {capability} {name}".rstrip()
    if agent:
        header += f" ([dim]{agent}[/dim])"
    console.print()
    console.print(header)
    console.print()

    if len(rel_paths) == 1:
        _render_single_file(rel_paths[0], findings, result, ruleset_map)
    else:
        _render_multi_file(rel_paths, findings, result, ruleset_map)

    _render_findings_by_rule(findings)
    _render_cross_file_for_focus(result, rel_paths)
    _render_next_action(findings)

    if elapsed_ms:
        console.print()
        console.print(f"  [dim]({elapsed_ms / 1000:.1f}s)[/dim]")


def _render_single_file(
    rel_path: Path,
    findings: list[Any],
    result: Any,
    ruleset_map: Any,
) -> None:
    file_atoms = _atoms_for_file(ruleset_map, rel_path)
    score = _focus_score(findings, len(file_atoms), result)
    bar = _bar(score)
    console.print(f"  [bold]{rel_path}[/bold]")
    color = "green" if score >= 7.0 else "yellow" if score >= 4.0 else "red"
    console.print(f"  Score: [{color} bold]{score:.1f}[/{color} bold] / 10  [dim]{bar}[/dim]")
    summary = _atom_summary(file_atoms)
    if summary:
        console.print(f"  [dim]{summary}[/dim]")


def _render_multi_file(
    rel_paths: list[Path],
    findings: list[Any],
    result: Any,
    ruleset_map: Any,
) -> None:
    per_file: dict[str, list[Any]] = {}
    for f in findings:
        per_file.setdefault(f.file, []).append(f)
    name_w = max((len(str(p)) for p in rel_paths), default=20)
    for rel_path in rel_paths:
        key = str(rel_path)
        file_findings = per_file.get(key, [])
        file_atoms = _atoms_for_file(ruleset_map, rel_path)
        score = _focus_score(file_findings, len(file_atoms), result)
        color = "green" if score >= 7.0 else "yellow" if score >= 4.0 else "red"
        count = len(file_findings)
        console.print(
            f"  [bold]{key:<{name_w}}[/bold]  {count:>3} findings   Score: [{color} bold]{score:.1f}[/{color} bold]"
        )


def _render_findings_by_rule(findings: list[Any]) -> None:
    if not findings:
        console.print("\n  [green]✓[/green]  No findings.")
        return
    by_rule = _group_by_rule(findings)
    tw = get_term_width()
    console.print()
    console.print(f"  [bold]Findings by rule ({len(findings)}):[/bold]")
    rule_w = max((len(r) for r in by_rule), default=12)
    for rule_id in _order_rules(by_rule):
        items = by_rule[rule_id]
        severity = _worst_severity(items)
        label = _RULE_SEVERITY_LABEL.get(severity, severity)
        message = _shorten(items[0].message, tw - rule_w - 24)
        console.print(f"    [bold]{rule_id:<{rule_w}}[/bold] (x{len(items)})  {label}  {message}")
        lines = [f.line for f in items if f.line]
        if lines:
            console.print(f"      [dim]L{', L'.join(str(line) for line in sorted(set(lines))[:12])}[/dim]")


def _render_cross_file_for_focus(result: Any, rel_paths: list[Path]) -> None:
    str_paths = {str(p) for p in rel_paths}
    pairs = [cf for cf in (result.cross_file or ()) if cf.file_1 in str_paths or cf.file_2 in str_paths]
    if not pairs:
        return
    n_conflicts = sum(1 for cf in pairs if cf.finding_type == "conflict")
    n_reps = sum(1 for cf in pairs if cf.finding_type == "repetition")
    bits = []
    if n_conflicts:
        bits.append(f"{n_conflicts} conflict" + ("s" if n_conflicts > 1 else ""))
    if n_reps:
        bits.append(f"{n_reps} repetition" + ("s" if n_reps > 1 else ""))
    console.print()
    console.print(f"  Cross-file: {', '.join(bits)} involving this focus.")
    console.print("  [dim]Run `ails check` for the full graph.[/dim]")


def _render_next_action(findings: list[Any]) -> None:
    if not findings:
        return
    by_rule = _group_by_rule(findings)
    ranked = sorted(
        by_rule.items(),
        key=lambda kv: (_RULE_SEVERITY_RANK.get(_worst_severity(kv[1]), 3), -len(kv[1])),
    )
    if not ranked:
        return
    rule_id, items = ranked[0]
    severity = _worst_severity(items)
    severity_word = "error" if severity == "error" else "warning" if severity == "warning" else "finding"
    console.print()
    console.print(
        f"  [bold]Next:[/bold] fix [bold]{rule_id}[/bold] (x{len(items)}) — highest-frequency {severity_word}."
    )


def _atoms_for_file(ruleset_map: Any, rel_path: Path) -> list[Any]:
    if ruleset_map is None:
        return []
    key = str(rel_path)
    return [a for a in getattr(ruleset_map, "atoms", ()) if a.file_path == key]


def _atom_summary(atoms: list[Any]) -> str:
    if not atoms:
        return ""
    charge_counts = Counter(a.charge for a in atoms)
    directives = charge_counts.get("DIRECTIVE", 0) + charge_counts.get("IMPERATIVE", 0)
    constraints = charge_counts.get("CONSTRAINT", 0)
    ambiguous = charge_counts.get("AMBIGUOUS", 0)
    n_prose = charge_counts.get("NEUTRAL", 0)
    total = max(len(atoms), 1)
    prose_pct = round(100 * n_prose / total)
    parts = []
    if directives:
        parts.append(f"{directives} directive")
    if constraints:
        parts.append(f"{constraints} constraint")
    if ambiguous:
        parts.append(f"{ambiguous} ambiguous")
    parts.append(f"{prose_pct}% prose")
    return " · ".join(parts)


def _focus_score(findings: list[Any], n_atoms: int, result: Any) -> float:
    if not findings:
        return 10.0
    severity_counts = Counter(f.severity for f in findings)
    errors = severity_counts.get("error", 0)
    warnings = severity_counts.get("warning", 0)
    infos = severity_counts.get("info", 0)

    # Reuse compute_score's shape: band base + severity penalty / atom denom.
    has_quality = result.quality is not None and bool(getattr(result.quality, "compliance_band", ""))
    base = 6.0
    if has_quality:
        band = result.quality.compliance_band
        base = 8.5 if band == "HIGH" else 5.5 if band == "MODERATE" else 3.0
    denom = max(n_atoms, errors + warnings + infos, 1)
    penalty = min(4.0, (errors / denom) * 30) + min(2.0, (warnings / denom) * 2)
    return float(round(max(0.0, min(10.0, base - penalty)), 1))


def _bar(score: float) -> str:
    bar_width = min(20, get_term_width() - 26)
    filled = round(bar_width * score / 10)
    return "▓" * filled + "░" * (bar_width - filled)


def _group_by_rule(findings: list[Any]) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for f in findings:
        out.setdefault(f.rule, []).append(f)
    return out


def _worst_severity(items: list[Any]) -> str:
    return str(min(items, key=lambda f: _RULE_SEVERITY_RANK.get(f.severity, 3)).severity)


def _order_rules(by_rule: dict[str, list[Any]]) -> list[str]:
    return sorted(
        by_rule,
        key=lambda r: (_RULE_SEVERITY_RANK.get(_worst_severity(by_rule[r]), 3), -len(by_rule[r]), r),
    )


def _shorten(text: str, width: int) -> str:
    if width <= 8:
        return text
    snippet = text.split(".")[0].split("—")[0].strip()
    if len(snippet) <= width:
        return snippet
    return snippet[: width - 1] + "…"


def print_listing_result(
    result: Any,
    capability: str,
    agent: str,
    candidate_paths: list[Path],
    project_root: Path,
    ruleset_map: Any = None,
) -> None:
    """Render listing mode: capability + per-target scores.

    Output when the operator runs `ails check skill` (no name):
      Reporails — skills (<agent>, N found)
        <name>  <path>  <score>
        …
      Run: ails check <capability> <name> to focus on one.
    """
    rels = [_to_rel(p, project_root) for p in candidate_paths]
    name_extractor = _name_extractor_for_capability(capability)

    console.print()
    console.print(f"[bold]Reporails[/bold] — {capability} ([dim]{agent}[/dim], {len(rels)} found)")
    console.print()

    if not rels:
        console.print(f"  [dim]No {capability} files found for agent {agent}.[/dim]")
        return

    per_file = _findings_per_file(result.findings)
    rows = []
    for path in rels:
        key = str(path)
        file_findings = per_file.get(key, [])
        atoms = _atoms_for_file(ruleset_map, path)
        score = _focus_score(file_findings, len(atoms), result)
        rows.append((name_extractor(path), key, score))

    name_w = max((len(name) for name, _, _ in rows), default=12)
    path_w = max((len(p) for _, p, _ in rows), default=20)
    for name, key, score in sorted(rows, key=lambda r: r[0]):
        color = "green" if score >= 7.0 else "yellow" if score >= 4.0 else "red"
        console.print(
            f"  [bold]{name:<{name_w}}[/bold]  [dim]{key:<{path_w}}[/dim]  [{color}]{score:.1f}[/{color}] / 10"
        )

    console.print()
    console.print(f"  [dim]Run:[/dim] ails check {capability} <name>")


def _findings_per_file(findings: Any) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = {}
    for f in findings:
        out.setdefault(f.file, []).append(f)
    return out


def _name_extractor_for_capability(capability: str) -> Callable[[Path], str]:
    parent_dir_caps = {"skills", "nested_context", "child_instruction"}
    if capability in parent_dir_caps:
        return lambda p: p.parent.name
    return lambda p: p.stem


def filter_result_to_focus(result: Any, focus_paths: set[Path], project_root: Path) -> Any:
    """Return a new CombinedResult containing only findings + cross-file pairs in the focus.

    Used by JSON / GitHub / focus text rendering so the envelope reflects
    just the targeted file(s) and the score/Top-rules block can be
    recomputed from the focused findings.
    """
    from dataclasses import replace as _replace

    from reporails_cli.core.platform.runtime.merger import CombinedStats

    rel_keys = {str(_to_rel(p, project_root)) for p in focus_paths}
    filtered_findings = tuple(f for f in result.findings if f.file in rel_keys)
    filtered_cross = tuple(cf for cf in result.cross_file if cf.file_1 in rel_keys or cf.file_2 in rel_keys)
    severity_counts = Counter(f.severity for f in filtered_findings)
    stats = CombinedStats(
        total_findings=len(filtered_findings),
        errors=severity_counts.get("error", 0),
        warnings=severity_counts.get("warning", 0),
        infos=severity_counts.get("info", 0),
        cross_file_conflicts=sum(1 for c in filtered_cross if c.finding_type == "conflict"),
        cross_file_repetitions=sum(1 for c in filtered_cross if c.finding_type == "repetition"),
        m_probe_count=result.stats.m_probe_count,
        client_check_count=result.stats.client_check_count,
        server_diagnostic_count=result.stats.server_diagnostic_count,
    )
    return _replace(result, findings=filtered_findings, cross_file=filtered_cross, stats=stats)


def _to_rel(path: Path, project_root: Path) -> Path:
    """Return path relative to project_root WITHOUT resolving symlinks.

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
