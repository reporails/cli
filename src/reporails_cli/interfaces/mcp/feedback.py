"""`validate(path=<file>)`'s `feedback` block: the file's own remaining findings after a
rewrite, cross-checked against the stored whole-project `validate`'s own workflow.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from reporails_cli.core.platform.dto.diagnostics import walk_findings

# An agent iterating a single file wants its remaining findings, not the whole file
# re-enumerated; 15 keeps the reply small while still naming every finding a realistic
# single-file rewrite pass would want to see in one look.
_FEEDBACK_LIMIT = 15


def _project_workflow_rule_files(scan_root: Path) -> set[tuple[str, str]] | None:
    """Every `(rule, file)` pair anywhere in the STORED whole-project `validate`'s own workflow
    for `scan_root`, keyed the same way the original project-wide `validate(path=<project>)`
    call stored it. `None` when no whole-project run is on record, so a caller with nothing to
    cross-check against leaves its candidates unfiltered.

    A `validate(path=<file>)` re-run scopes discovery to one file in isolation, which can
    surface a whole-file content-expectation finding (missing headings, missing an explicit
    prohibition) the file never draws in real project context — carried `impact_tier:
    gate_mover` with an unfilled empty `message`. The project's own stored workflow is ground
    truth for what actually counts; a `(rule, file)` pair absent from it names that artifact."""
    from reporails_cli.interfaces.mcp import server

    state = server._validate_states.get(server._state_key(str(scan_root), ()))
    if state is None or not state.full_payload:
        return None
    workflow = state.full_payload.get("workflow")
    if not isinstance(workflow, dict):
        return None
    pairs: set[tuple[str, str]] = set()
    for loc in workflow.get("locations") or ():
        if not isinstance(loc, dict):
            continue
        for f in walk_findings(loc.get("findings") or ()):
            if isinstance(f, dict):
                pairs.add((str(f.get("rule") or ""), str(f.get("file") or "")))
    return pairs


def _rules_fired_before(scan_root: Path, rel: str) -> set[str] | None:
    """Every rule that fired on the file `rel` in the STORED whole-project `validate` reply,
    whether in its workflow or in its plain per-file findings. `None` when no whole-project
    reply is on record."""
    from reporails_cli.interfaces.mcp import server

    state = server._validate_states.get(server._state_key(str(scan_root), ()))
    if state is None or not state.full_payload:
        return None
    stored = state.full_payload
    workflow_raw, per_file_raw = _raw_file_findings(stored, rel)
    return {str(f.get("rule") or "") for f in workflow_raw + per_file_raw}


def _shaped(f: dict[str, Any], remedy_key: str) -> dict[str, Any]:
    """One finding as a `feedback` entry; a plain per-file finding carries its fix as `fix`
    and has no `impact_tier`."""
    return {
        "rule": f.get("rule", ""),
        "line": f.get("line"),
        "message": f.get("message", ""),
        "remedy": f.get(remedy_key, ""),
        "impact_tier": f.get("impact_tier", ""),
    }


def _raw_file_findings(payload: dict[str, Any], rel: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """`(workflow findings, plain per-file findings)` of the file `rel` in `payload`."""
    file_entry = (payload.get("files") or {}).get(rel) or {}
    per_file = [f for f in (file_entry.get("findings") or ()) if isinstance(f, dict)]
    workflow = payload.get("workflow")
    from_workflow: list[dict[str, Any]] = []
    for loc in (workflow.get("locations") or ()) if isinstance(workflow, dict) else ():
        if isinstance(loc, dict):
            from_workflow.extend(
                f for f in walk_findings(loc.get("findings") or ()) if isinstance(f, dict) and f.get("file") == rel
            )
    return from_workflow, per_file


def _new_kind_findings(
    workflow_raw: list[dict[str, Any]], per_file_raw: list[dict[str, Any]], fired_before: set[str]
) -> list[dict[str, Any]]:
    """The findings whose rule fired nowhere on the file in the stored whole-project reply
    (`fired_before`), error severity first, then by `impact_tier`. A finding with no message that is not an error
    is a single-file-scope artifact and is left out; an error is never left out."""
    from reporails_cli.interfaces.mcp.remedy_brief import _sorted_findings

    error_rules = {str(f.get("rule") or "") for f in per_file_raw if f.get("severity") == "error"}
    found: list[dict[str, Any]] = []
    seen: set[tuple[str, Any, str]] = set()
    for c in [_shaped(f, "remedy") for f in workflow_raw] + [_shaped(f, "fix") for f in per_file_raw]:
        key = (str(c["rule"]), c["line"], str(c["message"]))
        if str(c["rule"]) in fired_before or key in seen or (not c["message"] and str(c["rule"]) not in error_rules):
            continue
        seen.add(key)
        found.append(c)
    return sorted(_sorted_findings(found), key=lambda c: str(c["rule"]) not in error_rules)


def file_feedback(payload: dict[str, Any], target: Path, scan_root: Path) -> list[dict[str, Any]]:
    """The `feedback` list for `validate(path=<file>)` on a snapshotted file: `target`'s own
    remaining findings from THIS single-file run, weakest-first (`impact_tier`: gate_mover ->
    conditional -> cosmetic -> ""), at most `_FEEDBACK_LIMIT`.

    Prefers the paid `workflow`'s own findings for `target` (already shaped `{rule, file, line,
    pi, message, remedy, impact_tier}` — `pi`/`file` dropped, the rest carried through) when any
    location names one; falls back to `target`'s plain per-file findings (`fix` as `remedy`,
    `impact_tier` `""`) when the workflow is absent or none of its findings land on this file.
    Either way, a candidate whose `(rule, file)` pair is absent from the STORED whole-project
    workflow (`_project_workflow_rule_files`) is dropped — a single-file-scope artifact the
    project diagnosis never counts — unless no whole-project run is on record to cross-check
    against, in which case nothing is dropped.

    A finding is a new kind only when its rule fired nowhere on this file in that stored reply
    (neither in its workflow nor in its per-file findings); such a finding is one the rewrite
    itself introduced: it is kept (when it has a message, or is an error) and listed
    ahead of the rest, error severity first, so the cap never pushes it out. Empty when the
    run found nothing either way.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path
    from reporails_cli.interfaces.mcp.remedy_brief import _sorted_findings

    rel = normalize_finding_path(str(target), scan_root)
    known_pairs = _project_workflow_rule_files(scan_root)

    def _counted(rule: Any) -> bool:
        return known_pairs is None or (str(rule or ""), rel) in known_pairs

    workflow_raw, per_file_raw = _raw_file_findings(payload, rel)
    workflow_findings = [_shaped(f, "remedy") for f in workflow_raw if _counted(f.get("rule"))]
    per_file = [_shaped(f, "fix") for f in per_file_raw if _counted(f.get("rule"))]
    kept = _sorted_findings(workflow_findings or per_file)
    fired_before = _rules_fired_before(scan_root, rel)
    if fired_before is None:
        return kept[:_FEEDBACK_LIMIT]
    new_kind = _new_kind_findings(workflow_raw, per_file_raw, fired_before)
    kept = [f for f in kept if str(f["rule"]) not in {str(n["rule"]) for n in new_kind}]
    return (new_kind + kept)[:_FEEDBACK_LIMIT]
