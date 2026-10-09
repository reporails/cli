"""The remediation workflow as the client reads it off the response.

Tolerant throughout: an absent, null or wrong-shaped key degrades to no workflow, no
location, or an empty field, never an error.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.platform.dto.diagnostics import (
    ListedFinding,
    LocationFinding,
    LocationRelation,
    RemediationWorkflow,
    WorkflowLocation,
)


def _as_int(value: Any, default: int) -> int:
    """Coerce a wire scalar to int, falling back on null / non-numeric — never raising."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _opt_int(value: Any) -> int | None:
    """Coerce a wire scalar to int, or `None` when it is null / non-numeric (`pi`)."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _strs(raw: Any) -> tuple[str, ...]:
    """A list of strings as a tuple; empty for anything else."""
    if isinstance(raw, list):
        return tuple(x for x in raw if isinstance(x, str))
    return ()


def _expect(raw: Any) -> dict[str, Any]:
    """The `expect` coordinates of a finding or relation; empty for anything but a dict."""
    return dict(raw) if isinstance(raw, dict) else {}


def _finding(d: Any) -> LocationFinding | None:
    """One `findings[]` entry, with its `members` read the same way; `None` when it is not a dict."""
    if not isinstance(d, dict):
        return None
    raw_members = d.get("members")
    members = (
        tuple(m for m in (_finding(x) for x in raw_members) if m is not None) if isinstance(raw_members, list) else ()
    )
    return LocationFinding(
        rule=str(d.get("rule") or ""),
        file=str(d.get("file") or ""),
        line=_as_int(d.get("line"), 0),
        pi=_opt_int(d.get("pi")),
        op=str(d.get("op") or ""),
        expect=_expect(d.get("expect")),
        impact_tier=str(d.get("impact_tier") or ""),
        members=members,
    )


def _relation(d: Any) -> LocationRelation | None:
    """One `relations[]` entry; `None` when it is not a dict."""
    if not isinstance(d, dict):
        return None
    return LocationRelation(
        rule=str(d.get("rule") or ""),
        file=str(d.get("file") or ""),
        line=_as_int(d.get("line"), 0),
        partner_file=str(d.get("partner_file") or ""),
        partner_line=_as_int(d.get("partner_line"), 0),
        op=str(d.get("op") or ""),
        expect=_expect(d.get("expect")),
    )


def _location(d: Any, order_fallback: int) -> WorkflowLocation | None:
    """One `locations[]` entry; `None` when it is not a dict. A malformed finding/relation
    row is skipped, never crashes the whole location."""
    if not isinstance(d, dict):
        return None
    raw_findings = d.get("findings")
    findings = (
        tuple(f for f in (_finding(x) for x in raw_findings) if f is not None) if isinstance(raw_findings, list) else ()
    )
    raw_relations = d.get("relations")
    relations = (
        tuple(r for r in (_relation(x) for x in raw_relations) if r is not None)
        if isinstance(raw_relations, list)
        else ()
    )
    return WorkflowLocation(
        order=_as_int(d.get("order"), order_fallback),
        element=str(d.get("element") or ""),
        kind=str(d.get("kind") or ""),
        loading=str(d.get("loading") or ""),
        files=_strs(d.get("files")),
        importance=str(d.get("importance") or ""),
        findings=findings,
        relations=relations,
    )


def _listed(d: Any) -> ListedFinding | None:
    """One `listed[]` entry; `None` when it is not a dict."""
    if not isinstance(d, dict):
        return None
    return ListedFinding(
        rule=str(d.get("rule") or ""),
        reason=str(d.get("reason") or ""),
        count=_as_int(d.get("count"), 0),
    )


def deserialize_workflow(data: dict[str, Any]) -> RemediationWorkflow | None:
    """Deserialize the optional remediation workflow.

    Tolerant: returns `None` when the key is absent, so such a response degrades
    to no workflow rather than erroring.
    """
    wf = data.get("workflow")
    if not isinstance(wf, dict):
        return None
    raw_locations = wf.get("locations")
    locations: list[WorkflowLocation] = []
    for loc in raw_locations if isinstance(raw_locations, list) else ():
        parsed = _location(loc, len(locations) + 1)
        if parsed is not None:
            locations.append(parsed)
    raw_listed = wf.get("listed")
    listed = tuple(
        e for e in (_listed(x) for x in (raw_listed if isinstance(raw_listed, list) else ())) if e is not None
    )
    return RemediationWorkflow(
        locations=tuple(locations),
        listed=listed,
        summary=str(wf.get("summary", "")),
    )
