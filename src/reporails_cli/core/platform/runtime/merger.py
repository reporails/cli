"""Result merger — combines local findings with server diagnostics.

Deduplicates when server and local checks fire on the same (file, line, rule),
keeping the server version (richer fix text from server diagnostics).
All file paths are normalized to project-relative before dedup and output.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from reporails_cli.core.platform.dto.diagnostics import (
    CrossFileFinding,
    FileAnalysis,
    FunnelError,
    LocalTier,
    Notice,
    QualityResult,
    RemediationWorkflow,
    RulesetReport,
)
from reporails_cli.core.platform.dto.models import Level, LocalFinding
from reporails_cli.core.platform.dto.results import HookEntry

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def normalize_finding_path(file_path: str, project_root: Path | None = None) -> str:
    """Normalize a finding's file path to project-relative.

    Handles absolute paths, relative paths, and external paths (~/.claude/...).
    Ensures all three sources (m_probe, client_check, server) produce the same
    path for the same file, so dedup and display grouping work correctly.

    Priority: project-relative > home-relative > as-is.
    """
    p = Path(file_path)

    # Without project_root, return paths as-is (no resolution)
    if project_root is None:
        return p.as_posix()

    # Resolve to absolute for comparison
    resolved = project_root / p if not p.is_absolute() else p

    # Project-relative first — paths within the project get short relative form
    if project_root is not None:
        try:
            return resolved.relative_to(project_root).as_posix()
        except ValueError:
            pass  # Not within project — fall through

    # External paths (outside project) — shorten with ~/
    home = Path.home()
    if resolved.is_absolute():
        try:
            return "~/" + resolved.relative_to(home).as_posix()
        except ValueError:
            pass

    # Already relative or fallback
    return p.as_posix()


@dataclass(frozen=True)
class FindingItem:
    """A single finding in the combined output, from any source."""

    file: str
    line: int
    severity: str  # "error" | "warning" | "info"
    rule: str  # diagnostic rule identifier or rule_id
    message: str
    fix: str = ""
    source: str = "local"  # "m_probe" | "client_check" | "server"
    impact_tier: str = ""  # the grade the reply gives this finding; "" when it gives none, and none is shown
    signature: str = ""  # matched text — same secret flagged by two rules shares this, so it counts once
    check_id: str = ""  # the local check that produced it; "" for server findings
    convention: bool = (
        False  # a documentation convention the file does not follow: listed apart from findings to act on
    )
    # The instruction's place in its file, when the finding is on one; never part of a finding's identity.
    pi: int | None = field(default=None, compare=False)
    # A per-file overlap finding's partner file, its line and shared percentage, when the reply names them.
    partner_file: str | None = field(default=None, compare=False)
    partner_line: int | None = field(default=None, compare=False)
    overlap_pct: int | None = field(default=None, compare=False)


@dataclass(frozen=True)
class CombinedStats:
    """Aggregate statistics for the combined result."""

    total_findings: int = 0
    errors: int = 0
    warnings: int = 0
    infos: int = 0
    cross_file_repetitions: int = 0
    cross_file_overlaps: int = 0  # distinct file pairs whose instructions cover the same topics
    m_probe_count: int = 0
    client_check_count: int = 0
    server_diagnostic_count: int = 0
    # The agents whose rules ran; lets the summary name the agent even when no ruleset map
    # exists (no model on disk). Set by the assemble spine, empty for a hand-built result.
    agents: tuple[str, ...] = ()


@dataclass(frozen=True)
class CombinedResult:
    """Merged local + server findings — the output of the new pipeline."""

    findings: tuple[FindingItem, ...] = ()
    cross_file: tuple[CrossFileFinding, ...] = ()
    quality: QualityResult | None = None
    per_file_analysis: tuple[FileAnalysis, ...] = ()
    stats: CombinedStats = field(default_factory=CombinedStats)
    offline: bool = True
    hints: tuple[Any, ...] = ()  # tuple[Hint, ...] from tier gating
    cross_file_coordinates: tuple[Any, ...] = ()  # tuple[CrossFileCoordinate, ...] free tier
    level: Level = Level.L0
    tier: str = ""  # Tier label propagated from LintResult ("free", "pro", "anonymous"); empty when offline
    # The composable remediation HOW; `None` offline, on the anon tier, or
    # from a pre-0.6.0 server. Carried through so JSON / MCP consumers can render it.
    workflow: RemediationWorkflow | None = None
    # The messages the server sent with its reply, for every output surface; empty offline.
    notices: tuple[Notice, ...] = ()
    # The diagnostics outcome when the request was rejected, timed out, or never
    # reached the service (a `FunnelError`); `None` when a response arrived normally
    # or no request was made. Carries the reason so JSON / github output can name it
    # (`offline` alone does not). Not populated by `merge_results` itself —
    # the caller attaches it once it has both the merged result and the funnel
    # outcome (see `interfaces/cli/check_orchestration.py::_dispatch_output`).
    server_error: FunnelError | None = None
    # The hooks found in the project's agent hook configs, set by the assemble spine from the
    # features it already computes for the level; empty for a hand-built result.
    hooks: tuple[HookEntry, ...] = ()


def _collect_server_diagnostics(
    server_report: RulesetReport,
    norm_fn: object,
) -> tuple[list[FindingItem], set[tuple[str, int, str]]]:
    """Extract server diagnostics as FindingItems and build dedup key set.

    A finding the reply sends without words reads as its bundled rule's title and carries no fix:
    a fix is for a paid account, and the rule's guidance is `ails explain <rule>`.

    A line can hold several instructions, and the server flags each one: two vague
    instructions on one line arrive as two findings that read the same. They are one
    thing to fix on that line, so the repeat is dropped; the same rule with different
    text on one line (an overlap naming two partner files) stays two findings.
    """
    items: list[FindingItem] = []
    server_keys: set[tuple[str, int, str]] = set()
    seen: set[tuple[str, int, str, str, str, str, int | None, str | None]] = set()
    from reporails_cli.core.lint.rule_pages import rule_title

    for fa in server_report.per_file:
        for diag in fa.diagnostics:
            if not diag.message:
                diag = replace(diag, message=rule_title(diag.rule))
            norm_file = norm_fn(diag.file)  # type: ignore[operator]
            server_keys.add((norm_file, diag.line, diag.rule))
            same = (
                norm_file,
                diag.line,
                diag.severity,
                diag.rule,
                diag.message,
                diag.fix,
                diag.partner_line,
                diag.partner_file,
            )
            if same in seen:
                continue
            seen.add(same)
            items.append(
                FindingItem(
                    file=norm_file,
                    line=diag.line,
                    severity=diag.severity,
                    rule=diag.rule,
                    message=diag.message,
                    fix=diag.fix,
                    source="server",
                    impact_tier=getattr(diag, "impact_tier", ""),
                    pi=getattr(diag, "pi", None),
                    partner_file=diag.partner_file,
                    partner_line=diag.partner_line,
                    overlap_pct=diag.overlap_pct,
                )
            )
    return items, server_keys


def _merge_local_findings(
    local_findings: list[LocalFinding],
    server_keys: set[tuple[str, int, str]],
    source: str,
    norm_fn: object,
) -> tuple[list[FindingItem], int]:
    """Convert local findings to FindingItems, deduplicating against server keys."""
    items: list[FindingItem] = []
    reported: set[tuple[str, int, str, str, str, str]] = set()
    for finding in local_findings:
        norm_file = norm_fn(finding.file)  # type: ignore[operator]
        key = (norm_file, finding.line, finding.rule)
        # An identical finding reached through two passes over the same file is one finding.
        identity = (norm_file, finding.line, finding.rule, finding.check_id, finding.message, finding.signature)
        if identity in reported:
            continue
        reported.add(identity)
        if key not in server_keys:
            items.append(
                FindingItem(
                    file=norm_file,
                    line=finding.line,
                    severity=finding.severity,
                    rule=finding.rule,
                    message=finding.message,
                    fix=finding.fix,
                    source=source,
                    signature=finding.signature,
                    check_id=finding.check_id,
                )
            )
    return items, len(items)


# The general credential rule and the subagent credential rule, in the order a tie
# keeps them: on equal severity the subagent rule's finding is the one reported.
_SAME_SECRET_RULES = ("CORE:G:0009", "CORE:G:0002")


def _same_secret_rank(item: FindingItem) -> tuple[int, int]:
    """Sort key for the finding kept: more severe first, then the subagent rule."""
    return _SEVERITY_ORDER.get(item.severity, 9), _SAME_SECRET_RULES.index(item.rule)


def _dedup_same_secret(items: tuple[FindingItem, ...]) -> list[FindingItem]:
    """Keep one finding when both credential rules flagged the same text at the same spot.

    A secret in a subagent definition is reported by the general credential rule and
    the subagent credential rule. When the two share a file, line, and matched text
    they describe one secret, so keep the more severe finding (the subagent rule's on
    a tie) and drop the other. Findings from any other rule, and findings with no
    matched text, are all kept.
    """
    best: dict[tuple[str, int, str], int] = {}
    keep: list[FindingItem] = []
    for item in items:
        if item.rule not in _SAME_SECRET_RULES or not item.signature:
            keep.append(item)
            continue
        key = (item.file, item.line, item.signature)
        if key not in best:
            best[key] = len(keep)
            keep.append(item)
        elif _same_secret_rank(item) < _same_secret_rank(keep[best[key]]):
            keep[best[key]] = item
    return keep


def _severity_counts(findings: Sequence[FindingItem]) -> dict[str, Any]:
    """The total and per-severity finding counts, keyed by their `CombinedStats` field."""
    return {
        "total_findings": len(findings),
        "errors": sum(1 for f in findings if f.severity == "error"),
        "warnings": sum(1 for f in findings if f.severity == "warning"),
        "infos": sum(1 for f in findings if f.severity == "info"),
    }


def rebuild_severity_stats(stats: CombinedStats, findings: Sequence[FindingItem]) -> CombinedStats:
    """Recompute the total and per-severity counters over `findings`; source counts are kept."""
    return replace(stats, **_severity_counts(findings))


def drop_findings(result: CombinedResult, kept: Sequence[FindingItem]) -> CombinedResult:
    """The result holding only `kept`, its counters repaired.

    A dropped finding is the same detection reported another way, not a second one, so its
    local source count drops with it.
    """
    if len(kept) == len(result.findings):
        return result
    dropped = Counter(f.source for f in result.findings) - Counter(f.source for f in kept)
    stats = replace(
        rebuild_severity_stats(result.stats, kept),
        m_probe_count=result.stats.m_probe_count - dropped["m_probe"],
        client_check_count=result.stats.client_check_count - dropped["client_check"],
    )
    return replace(result, findings=tuple(kept), stats=stats)


def collapse_same_secret(result: CombinedResult) -> CombinedResult:
    """Report a secret flagged by both credential rules on one line once.

    Meant to run after inline suppressions, so ignoring either rule on a line still
    leaves the other rule's finding reported.
    """
    return drop_findings(result, _dedup_same_secret(result.findings))


def _served_tiers(
    workflow: Any, project_root: Path | None
) -> tuple[dict[tuple[str, str, int], str], dict[tuple[str, str], str]]:
    """The tiers a workflow serves, by (file, rule, line) and, for a line-0 row, by (file, rule)."""
    from reporails_cli.core.platform.dto.diagnostics import walk_findings

    exact: dict[tuple[str, str, int], str] = {}
    whole_file: dict[tuple[str, str], str] = {}
    for location in workflow.locations:
        for served in walk_findings(location.findings):
            if not served.impact_tier:
                continue
            file = normalize_finding_path(served.file, project_root)
            if served.line == 0:
                whole_file.setdefault((file, served.rule), served.impact_tier)
            else:
                exact.setdefault((file, served.rule, served.line), served.impact_tier)
    return exact, whole_file


def stamp_served_tiers(result: CombinedResult, project_root: Path | None = None) -> CombinedResult:
    """Give each local finding the tier its workflow row carries, so the file list and the workflow agree.

    A finding is matched on its normalized file, rule and line, walking the workflow's owners and
    members. A served finding at line 0 stands for its whole file: it matches the same rule at
    any line. A finding that already has a tier, a served row without one, and a finding the
    workflow does not serve are left as they are.
    """
    if result.workflow is None:
        return result
    exact, whole_file = _served_tiers(result.workflow, project_root)
    stamped = tuple(
        replace(f, impact_tier=tier)
        if not f.impact_tier and (tier := exact.get((f.file, f.rule, f.line)) or whole_file.get((f.file, f.rule)))
        else f
        for f in result.findings
    )
    return replace(result, findings=stamped)


def stamp_conventions(result: CombinedResult, check_ids: frozenset[str]) -> CombinedResult:
    """Mark the findings whose check only asks that the file document something.

    Such a finding names a convention the file does not follow ("Missing testing
    documentation"); a renderer may list the group as one counted line.
    """
    if not any(f.check_id in check_ids for f in result.findings):
        return result
    return replace(
        result,
        findings=tuple(replace(f, convention=True) if f.check_id in check_ids else f for f in result.findings),
    )


def stamp_local_tiers(
    result: CombinedResult, rows: Sequence[LocalTier], project_root: Path | None = None
) -> CombinedResult:
    """Give each local finding the grade the reply's row at its coordinates carries.

    A finding is matched on its normalized file, rule and line. A row at line 0 stands for its
    whole file: it grades the same rule's finding at any line, as the diagnostics request names
    a whole-file finding at line 0. A finding that already has a grade, and a finding no row
    names, are left as they are: it shows no grade.
    """
    exact: dict[tuple[str, str, int], str] = {}
    whole_file: dict[tuple[str, str], str] = {}
    for row in rows:
        if not row.impact_tier:
            continue
        file = normalize_finding_path(row.file, project_root)
        if row.line == 0:
            whole_file.setdefault((file, row.rule), row.impact_tier)
        else:
            exact.setdefault((file, row.rule, row.line), row.impact_tier)
    if not exact and not whole_file:
        return result
    stamped = tuple(
        replace(f, impact_tier=tier)
        if not f.impact_tier and (tier := exact.get((f.file, f.rule, f.line)) or whole_file.get((f.file, f.rule)))
        else f
        for f in result.findings
    )
    return replace(result, findings=stamped)


def count_cross_file_repetitions(
    cross_file: tuple[CrossFileFinding, ...],
    cross_file_coordinates: tuple[Any, ...] = (),
) -> int:
    """Count cross-file repetitions from whichever form the run carries.

    A run holds the repetitions either as detailed rows (one per pair of
    lines) or, when only the aggregate form is available, as coordinates
    carrying a per-file-pair ``count``. The detailed rows win when they carry
    any repetition; otherwise the coordinate counts are summed, so the number
    in ``stats`` is the number every renderer shows regardless of which form
    arrived.
    """
    rows = sum(1 for cf in cross_file if cf.finding_type == "repetition")
    return rows or sum(c.count for c in cross_file_coordinates if c.finding_type == "repetition")


def _unordered(file_1: str, file_2: str) -> tuple[str, str]:
    return (file_1, file_2) if file_1 <= file_2 else (file_2, file_1)


def overlapping_pairs(
    cross_file: tuple[CrossFileFinding, ...],
    cross_file_coordinates: tuple[Any, ...] = (),
) -> list[tuple[str, str]]:
    """The file pairs that overlap in topic, most shared instructions first.

    Detailed rows carry one entry per shared instruction; coordinates carry one
    entry per file pair with a ``count``. Both reduce to the same unordered file
    pairs, weighted by how many instructions each shares. As with repetitions,
    the detailed rows win when they carry any overlap.
    """
    weight: Counter[tuple[str, str]] = Counter()
    for cf in cross_file:
        if cf.finding_type == "overlap":
            weight[_unordered(cf.file_1, cf.file_2)] += 1
    if not weight:
        for c in cross_file_coordinates:
            if c.finding_type == "overlap":
                weight[_unordered(c.file_1, c.file_2)] += c.count
    return sorted(weight, key=lambda pair: (-weight[pair], pair))


def count_cross_file_overlaps(
    cross_file: tuple[CrossFileFinding, ...],
    cross_file_coordinates: tuple[Any, ...] = (),
) -> int:
    """Count the distinct file pairs that overlap in topic, from whichever form the run carries."""
    return len(overlapping_pairs(cross_file, cross_file_coordinates))


def _compute_stats(
    items: list[FindingItem],
    cross_file: tuple[CrossFileFinding, ...],
    m_probe_count: int,
    client_count: int,
    cross_file_coordinates: tuple[Any, ...] = (),
) -> CombinedStats:
    """Compute aggregate statistics from merged findings."""
    return CombinedStats(
        **_severity_counts(items),
        cross_file_repetitions=count_cross_file_repetitions(cross_file, cross_file_coordinates),
        cross_file_overlaps=count_cross_file_overlaps(cross_file, cross_file_coordinates),
        m_probe_count=m_probe_count,
        client_check_count=client_count,
        server_diagnostic_count=len(items) - m_probe_count - client_count,
    )


def _merged_items(
    m_probe_findings: list[LocalFinding],
    client_check_findings: list[LocalFinding],
    server_report: RulesetReport | None,
    norm_fn: Any,
) -> tuple[list[FindingItem], int, int]:
    """Every finding as one sorted list, with the M-probe and client-check counts.

    A local finding the server also reports at the same (file, line, rule) is dropped.
    """
    items: list[FindingItem] = []
    server_keys: set[tuple[str, int, str]] = set()
    if server_report is not None:
        items, server_keys = _collect_server_diagnostics(server_report, norm_fn)
    m_items, m_count = _merge_local_findings(m_probe_findings, server_keys, "m_probe", norm_fn)
    c_items, c_count = _merge_local_findings(client_check_findings, server_keys, "client_check", norm_fn)
    items.extend(m_items)
    items.extend(c_items)
    items.sort(key=lambda f: (f.file, _SEVERITY_ORDER.get(f.severity, 9), f.line))
    return items, m_count, c_count


def merge_results(
    m_probe_findings: list[LocalFinding],
    client_check_findings: list[LocalFinding],
    server_report: RulesetReport | None,
    hints: tuple[Any, ...] = (),
    cross_file_coordinates: tuple[Any, ...] = (),
    project_root: Path | None = None,
    level: Level = Level.L0,
    tier: str = "",
) -> CombinedResult:
    """Merge M-probe findings, client checks, and server diagnostics.

    When server_report is None, returns local findings only with offline=True.
    When present, deduplicates: server diagnostic at same (file, line, rule)
    replaces the local finding. All paths normalized to project-relative.

    `tier` carries the upstream `LintResult.tier` label through the pipeline so
    JSON / MCP consumers can render tier-aware presentation without re-reading
    `AILS_TIER`. Empty string when offline / no server call.

    Drops `conflict`-typed cross-file entries: both the `cross_file` findings
    and the `cross_file_coordinates` lose that type here (`repetition` and
    `overlap` pass), the single point every caller (CLI check, MCP) funnels
    through, so no downstream renderer needs its own filter.
    """

    def _norm(fp: str) -> str:
        return normalize_finding_path(fp, project_root)

    items, m_count, c_count = _merged_items(m_probe_findings, client_check_findings, server_report, _norm)
    cross_file = tuple(
        replace(cf, file_1=_norm(cf.file_1), file_2=_norm(cf.file_2))
        for cf in (server_report.cross_file if server_report else ())
        if cf.finding_type != "conflict"
    )
    cross_file_coordinates = tuple(
        replace(c, file_1=_norm(c.file_1), file_2=_norm(c.file_2))
        for c in cross_file_coordinates
        if c.finding_type != "conflict"
    )
    return CombinedResult(
        findings=tuple(items),
        cross_file=cross_file,
        quality=server_report.quality if server_report else None,
        per_file_analysis=server_report.per_file if server_report else (),
        stats=_compute_stats(items, cross_file, m_count, c_count, cross_file_coordinates),
        offline=server_report is None,
        hints=hints,
        cross_file_coordinates=cross_file_coordinates,
        level=level,
        tier=tier,
    )
