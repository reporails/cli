"""Canonical JSON serialization for check results."""

from __future__ import annotations

from dataclasses import asdict
from enum import Enum
from pathlib import Path

from reporails_cli.core.mapper.bio_graphs import multislot_available
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue
from reporails_cli.core.platform.dto.diagnostics import (
    CLIENT_CHECK_KINDS,
    DEFAULT_RETRY_AFTER_S,
    FindingItem,
    FunnelError,
    Hint,
    LocationFinding,
    LocationRelation,
    Notice,
    RemediationWorkflow,
    WorkflowLocation,
)
from reporails_cli.core.platform.dto.models import CATEGORY_CODES, Level
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.runtime.merger import CombinedResult, Omissions, normalize_finding_path
from reporails_cli.formatters.text.funnel_cta import plain_cta
from reporails_cli.formatters.text.scorecard import compute_surface_scores
from reporails_cli.formatters.triage import classify_regime, resolve_leverage, tally_rules


def _category_for_rule(rule_id: str) -> str:
    """Derive the category label for a rule ID via `CATEGORY_CODES`.

    Returns the lowercase Category value (`"structure"`, `"direction"`, etc.)
    when the rule ID's second segment matches a known code, or an empty
    string when the shape is unrecognized. The MCP / JSON consumer reads
    this to group findings by category for prioritization.
    """

    parts = rule_id.split(":")
    if len(parts) < 2:
        return ""
    category = CATEGORY_CODES.get(parts[1])
    return category.value if category else ""


def _regime_by_file(result: CombinedResult, project_root: Path) -> dict[str, JsonObject]:
    """Build a file-keyed map of the per-file triage tier token.

    Keyed by project-relative path; empty for offline runs.
    """

    out: dict[str, JsonObject] = {}
    for fa in result.per_file_analysis:
        regime = classify_regime(fa.stats)
        if regime is not None:
            # Key by the same project-relative form the `files` dict uses
            # (findings are already normalized; server `per_file` is absolute).
            out[normalize_finding_path(fa.file, project_root)] = {
                "triage_tier": regime.tier.value,
            }
    return out


def _pro_summary(hints: tuple[Hint, ...]) -> JsonObject:
    """Aggregate pro-tier hint counts into the JSON `pro` block."""
    return {
        "count": sum(h.count for h in hints),
        "errors": sum(h.error_count for h in hints),
        "warnings": sum(h.warning_count for h in hints),
    }


def _file_entry(findings: list[JsonValue], regime: JsonObject | None) -> JsonObject:
    """Build one per-file JSON entry, attaching `regime` when available (additive)."""
    entry: JsonObject = {"findings": findings, "count": len(findings)}
    if regime is not None:
        entry["regime"] = regime
    return entry


def _format_workflow(wf: RemediationWorkflow, project_root: Path) -> JsonObject:
    """Serialize the remediation location index for agent consumption.

    Each location is a harness element (the root main file, a skill dir, an agent file, a
    rule file, a memory element, hooks), ordered one round per kind, then by importance, carrying
    every finding of that element plus the relation findings (cross-file overlap /
    repetition) folded onto it. Paths (`files`, `element` when it names one, and each
    finding's / relation's `file` / `partner_file`) are relativized to project-relative (or
    `~/` for external surfaces) via the finding path-normalizer, so they read like the
    findings. Each finding carries its `op` and `expect` coordinates (their file paths
    relativized the same way) and its own `impact_tier` ("gate_mover" |
    "conditional" | "cosmetic" | "") — distinct from the location's own `importance` — so a
    caller can weigh findings within one location. Each finding also carries `members`, the
    findings it owns, in the same shape and treatment (`[]` when it owns none). `listed` names
    every firing rule that takes no location, with its reason code and how many rows it covers.
    """

    def _rel(path: str) -> str:
        return normalize_finding_path(path, project_root) if path else path

    def _expect(expect: JsonObject) -> JsonObject:
        return {
            key: [_rel(v[0]), *v[1:]] if isinstance(v, list) and v and isinstance(v[0], str) else v
            for key, v in expect.items()
        }

    def _finding(lf: LocationFinding) -> JsonObject:
        file = _rel(lf.file)
        return {
            "rule": lf.rule,
            "file": file,
            "line": lf.line,
            "pi": lf.pi,
            "op": lf.op,
            "expect": _expect(lf.expect),
            "impact_tier": lf.impact_tier,
            "members": [_finding(m) for m in lf.members],
        }

    def _relation(lr: LocationRelation) -> JsonObject:
        return {
            "rule": lr.rule,
            "file": _rel(lr.file),
            "line": lr.line,
            "partner_file": _rel(lr.partner_file),
            "partner_line": lr.partner_line,
            "op": lr.op,
            "expect": _expect(lr.expect),
        }

    def _location(loc: WorkflowLocation) -> JsonObject:
        return {
            "order": loc.order,
            "element": _rel(loc.element),
            "kind": loc.kind,
            "loading": loc.loading,
            "files": [_rel(f) for f in loc.files],
            "importance": loc.importance,
            "findings": [_finding(f) for f in loc.findings],
            "relations": [_relation(r) for r in loc.relations],
        }

    out: JsonObject = {
        "summary": wf.summary,
        "locations": [_location(loc) for loc in wf.locations],
    }
    if wf.listed:
        out["listed"] = [{"rule": e.rule, "reason": e.reason, "count": e.count} for e in wf.listed]
    return out


def format_notices(notices: tuple[Notice, ...]) -> list[JsonValue]:
    """Notices as the JSON documents carry them."""
    return [{"id": n.id, "level": n.level, "text": n.text, "url": n.url, "kind": n.kind} for n in notices]


def format_server_error(server_error: FunnelError | None) -> JsonObject | None:
    """Format a `FunnelError` outcome (rejection / timeout / network failure) for JSON output.

    `None` when a response arrived normally or no request was made, so a machine
    consumer can tell a designed offline run (`offline: true`, `server_error: null`)
    apart from an outage or rejection (`server_error` populated). `message` reuses `plain_cta` — the single markup-free
    serializer also used by the MCP `funnel` envelope
    (`interfaces/mcp/tools.py::_attach_funnel`) — so a machine consumer never sees the
    terminal CTA's `[link=...][bold]...[/bold][/link]` tags.
    """

    if server_error is None:
        return None
    return {
        "status": server_error.status,
        "error": server_error.error,
        "message": plain_cta(server_error),
        "tier": server_error.tier,
        "upgrade_url": server_error.upgrade_url,
        "retryable": server_error.retryable,
        "retry_after": (server_error.reset_in or DEFAULT_RETRY_AFTER_S) if server_error.retryable else None,
    }


def empty_result_payload(
    project_root: Path | None = None, excluded: tuple[tuple[str, ...], tuple[str, ...]] = ((), ())
) -> JsonObject:
    """The standard envelope for a run that found nothing to check.

    A project with no instruction files is an ordinary result over an empty finding
    set, so it formats through `format_combined_result` like any other — same
    top-level keys, `files: {}`, zeroed `stats`, `quality: null`, `level: "L0"`.
    Emitting a smaller, differently-shaped payload instead made every machine
    consumer branch on two incompatible envelopes for the same command. `excluded` is the
    `(folders, file globs)` the run left out, so a run they emptied still names them.
    """

    dirs, files = excluded
    left_out = CombinedResult(omissions=Omissions(excluded_dirs=dirs, excluded_files=files))
    return format_combined_result(left_out, project_root=project_root)


# `format_combined_result`'s `ruleset_map` when the caller says nothing about mapping;
# an explicit `None` means the run tried to map its files and could not.
class _NotStated(Enum):
    """The one marker, `_MAP_NOT_STATED`, that says the caller gave no `ruleset_map`."""

    MAP_NOT_STATED = "map_not_stated"


_MAP_NOT_STATED = _NotStated.MAP_NOT_STATED


def _finding_entry(f: FindingItem, project_root: Path) -> JsonObject:
    """One finding as its per-file JSON entry.

    `leverage` is additive (raw `severity` is unchanged — the machine baseline); it appears only
    on a finding the reply graded. `rule` is the canonical `<NS>:<CAT>:<SLOT>` id (same as text
    output); a check that is not one of the rule's own (`format`, `bold`) is named under `label` for baseline
    stability. `convention` marks a finding that only names a documentation convention the file
    does not follow, so a reader can collapse the group the way the text output does. A per-file
    overlap finding names the file it overlaps (`partner_file`, relative to the project), its line
    and the share that overlaps, when the reply names them.
    """

    entry: JsonObject = {
        "line": f.line,
        "severity": f.severity,
        "rule": f.rule,
        "category": _category_for_rule(f.rule),
        "message": f.message,
    }
    grade = resolve_leverage(f)
    if grade is not None:
        entry["leverage"] = grade.value
    if f.check_id in CLIENT_CHECK_KINDS:
        entry["label"] = f.check_id
    if f.fix:
        entry["fix"] = f.fix
    if f.convention:
        entry["convention"] = True
    if f.partner_file:
        entry["partner_file"] = normalize_finding_path(f.partner_file, project_root)
    if f.partner_line is not None:
        entry["partner_line"] = f.partner_line
    if f.overlap_pct is not None:
        entry["overlap_pct"] = f.overlap_pct
    return entry


def _cross_file_blocks(result: CombinedResult) -> JsonObject:
    """The `cross_file` and `cross_file_coordinates` entries of a combined result, each only when it has rows."""
    out: JsonObject = {}
    if result.cross_file:
        out["cross_file"] = [
            {
                "file_1": cf.file_1,
                "file_2": cf.file_2,
                "line_1": cf.line_1,
                "line_2": cf.line_2,
                "type": cf.finding_type,
            }
            for cf in result.cross_file
        ]
    if result.cross_file_coordinates:
        out["cross_file_coordinates"] = [
            {"file_1": c.file_1, "file_2": c.file_2, "type": c.finding_type, "count": c.count}
            for c in result.cross_file_coordinates
        ]
    return out


def _surface_health(
    result: CombinedResult, ruleset_map: RulesetMap | None, root: Path, file_type_by_path: dict[str, str] | None
) -> list[JsonValue]:
    """The per-surface score rows of a combined result."""

    surfaces = compute_surface_scores(
        result, ruleset_map=ruleset_map, project_root=root, file_type_by_path=file_type_by_path
    )
    return [
        {
            "name": s.name,
            "score": s.score,
            "file_count": s.file_count,
            "finding_count": s.finding_count,
            "category_breakdown": dict(s.category_breakdown),
        }
        for s in surfaces
    ]


def format_combined_result(
    result: CombinedResult,
    ruleset_map: RulesetMap | _NotStated | None = _MAP_NOT_STATED,
    project_root: Path | None = None,
    file_type_by_path: dict[str, str] | None = None,
) -> JsonObject:
    """Format CombinedResult as JSON dict.

    Args:
        result: CombinedResult from merger
        ruleset_map: Optional RulesetMap for accurate file counts; an explicit `None` marks
            a run whose files could not be mapped (`content_checks_skipped` is then true)
        project_root: Root to relativize regime keys against (defaults to cwd)
        file_type_by_path: Generic-scan file types, so surface_health routes @-imports
            to the Imported surface consistently with the text view

    Returns:
        Dict with findings, stats, compliance, tier, category info.
    """

    # Group findings by file for agent consumption — agents work file-by-file.
    root = project_root or Path.cwd()
    by_file: dict[str, list[JsonValue]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(_finding_entry(f, root))

    regime_by_file = _regime_by_file(result, root)

    # A project with no instruction files (level L0) has nothing to map: that is an empty run,
    # not a failed one.
    map_failed = ruleset_map is None and result.level != Level.L0
    mapped = None if isinstance(ruleset_map, _NotStated) else ruleset_map

    data: JsonObject = {
        "offline": result.offline,
        "server_error": format_server_error(result.reply.server_error),
        "tier": result.reply.tier,
        "notices": format_notices(result.reply.notices),
        "not_evaluated": [{"rule": rule, "file": file} for rule, file in result.omissions.not_evaluated],
        "excluded": {
            "dirs": list(result.omissions.excluded_dirs),
            "files": list(result.omissions.excluded_files),
            "imported_text_counted": result.omissions.excluded_imported,
        },
        "quality": (
            float(result.quality.display_score)
            if result.quality is not None and result.quality.display_score is not None
            else None
        ),
        "level": result.level.value,
        # True when this run did not run the full content checks: the files could not be
        # mapped, or the bundled models were unavailable. A machine
        # consumer (CI, a coding agent) would otherwise read a smaller finding count
        # from a degraded run as a cleaner project than a full run produced.
        "content_checks_skipped": map_failed or not multislot_available(),
        "files": {
            fp: _file_entry(findings, regime_by_file.get(fp))
            for fp, findings in sorted(by_file.items(), key=lambda x: -len(x[1]))
        },
        "stats": {k: v for k, v in asdict(result.stats).items() if k != "agents"},  # `agents` is text-summary only
    }
    data.update(_cross_file_blocks(result))
    if result.hints:
        data["pro"] = _pro_summary(result.hints)
    surfaces = _surface_health(result, mapped, project_root or Path.cwd(), file_type_by_path)
    if surfaces:
        data["surface_health"] = surfaces
    data["top_rules"] = _aggregate_top_rules(result.findings)
    # The remediation location index — present only when the paid server emitted it;
    # absent (anon / offline / older server) it is simply omitted. Rendered whenever the
    # server sent one, even with no locations and nothing listed — that is a real, clean
    # paid result ("nothing to rewrite"), not the absence of the paid feature.
    workflow = result.reply.workflow
    if workflow is not None:
        data["workflow"] = _format_workflow(workflow, project_root or Path.cwd())
    return data


_TOP_RULES_SHOWN = 10


def _aggregate_top_rules(findings: tuple[FindingItem, ...]) -> list[JsonValue]:
    """Group findings by rule and return the top ten by count.

    Each entry: `{"rule": "<id>", "count": <int>, "severity": "<worst>", "errors": <int>,
    "warnings": <int>}`. `severity` is the worst (error > warning > info) seen for that rule,
    sitting beside the rule's *total* count — a rule with 1 error and 69 warnings reads
    `severity: "error"` at `count: 70`, which an agent reading only those two fields
    over-reports as "70 errors". `errors` and `warnings` are that rule's own per-severity
    counts, so a consumer never has to infer them from the worst-severity label.
    """

    return [
        {
            "rule": t.rule,
            "count": t.count,
            "severity": t.severity,
            "errors": t.by_severity.get("error", 0),
            "warnings": t.by_severity.get("warning", 0),
        }
        for t in tally_rules(findings)[:_TOP_RULES_SHOWN]
    ]
