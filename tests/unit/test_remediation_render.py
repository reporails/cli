"""Remediation-workflow render — the remediation location index deserializes tolerantly and
reaches JSON.

The server withholds the `workflow` for the anon tier and pre-0.6.0 servers never emit
it, so the client must degrade to `None` on an absent/malformed key rather than error,
and the JSON envelope must carry it only when present.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters.workflow_wire import deserialize_workflow
from reporails_cli.core.platform.dto.diagnostics import (
    ListedFinding,
    LocationFinding,
    LocationRelation,
    RemediationWorkflow,
    WorkflowLocation,
)
from reporails_cli.core.platform.runtime.merger import CombinedResult, CombinedStats, FindingItem
from reporails_cli.formatters.json import format_combined_result


def _result(**overrides: object) -> CombinedResult:
    defaults: dict[str, object] = {
        "findings": (),
        "cross_file": (),
        "quality": None,
        "per_file_analysis": (),
        "stats": CombinedStats(),
        "offline": True,
        "hints": (),
        "cross_file_coordinates": (),
    }
    defaults.update(overrides)
    return CombinedResult(**defaults)  # type: ignore[arg-type]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_absent_key_is_none() -> None:
    assert deserialize_workflow({"tier": "pro"}) is None


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_non_dict_workflow_is_none() -> None:
    assert deserialize_workflow({"workflow": "nope"}) is None


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_present_workflow_round_trips() -> None:
    wf = deserialize_workflow(
        {
            "workflow": {
                "summary": "s",
                "escape": "e",
                "locations": [
                    {
                        "order": 1,
                        "element": "the `orient` skill",
                        "kind": "skills",
                        "loading": "on_invocation",
                        "files": ["SKILL.md"],
                        "importance": "gate_mover",
                        "findings": [
                            {
                                "rule": "CORE:C:0042",
                                "file": "SKILL.md",
                                "line": 12,
                                "pi": 4,
                                "message": "m",
                                "remedy": "r",
                            }
                        ],
                    }
                ],
            }
        }
    )
    assert isinstance(wf, RemediationWorkflow)
    assert wf.summary == "s" and wf.escape == "e"
    assert len(wf.locations) == 1
    loc = wf.locations[0]
    assert loc.order == 1 and loc.importance == "gate_mover"
    assert loc.element == "the `orient` skill" and loc.kind == "skills" and loc.loading == "on_invocation"
    assert loc.files == ("SKILL.md",)
    assert len(loc.findings) == 1
    f = loc.findings[0]
    assert (f.rule, f.file, f.line, f.pi, f.message, f.remedy) == ("CORE:C:0042", "SKILL.md", 12, 4, "m", "r")


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_malformed_location_is_skipped() -> None:
    wf = deserialize_workflow({"workflow": {"locations": ["bad", {"order": 2, "kind": "main"}]}})
    assert wf is not None
    assert len(wf.locations) == 1 and wf.locations[0].order == 2 and wf.locations[0].kind == "main"


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_null_locations_degrades_not_crashes() -> None:
    # A present-but-null `locations` (malformed/older server) must degrade, not TypeError.
    wf = deserialize_workflow({"workflow": {"locations": None, "summary": "s"}})
    assert wf is not None and wf.locations == ()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_null_scalar_fields_tolerated() -> None:
    # Null `order` / `pi` must fall back to their defaults, not crash on int(None).
    wf = deserialize_workflow(
        {"workflow": {"locations": [{"order": None, "kind": None, "findings": [{"line": None, "pi": None}]}]}}
    )
    assert wf is not None and len(wf.locations) == 1
    loc = wf.locations[0]
    assert loc.order == 1 and loc.kind == ""
    assert loc.findings[0].line == 0 and loc.findings[0].pi is None


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_malformed_finding_and_relation_rows_are_skipped() -> None:
    wf = deserialize_workflow(
        {
            "workflow": {
                "locations": [
                    {"order": 1, "kind": "main", "findings": ["bad", {"rule": "CORE:C:0042"}], "relations": ["bad"]}
                ]
            }
        }
    )
    assert wf is not None
    (loc,) = wf.locations
    assert len(loc.findings) == 1 and loc.findings[0].rule == "CORE:C:0042"
    assert loc.relations == ()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_reads_relations_and_listed() -> None:
    wf = deserialize_workflow(
        {
            "workflow": {
                "locations": [
                    {
                        "order": 1,
                        "kind": "skills",
                        "relations": [
                            {
                                "rule": "CORE:C:0044",
                                "file": "SKILL.md",
                                "line": 22,
                                "partner_file": "CLAUDE.md",
                                "partner_line": 30,
                                "message": "m",
                                "remedy": "r",
                            }
                        ],
                    }
                ],
                "listed": [{"rule": "CORE:S:0039", "reason": "cosmetic", "count": 4}],
            }
        }
    )
    assert wf is not None
    rel = wf.locations[0].relations[0]
    assert (rel.rule, rel.file, rel.line, rel.partner_file, rel.partner_line) == (
        "CORE:C:0044",
        "SKILL.md",
        22,
        "CLAUDE.md",
        30,
    )
    assert wf.listed == (ListedFinding(rule="CORE:S:0039", reason="cosmetic", count=4),)


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_reads_finding_impact_tier() -> None:
    wf = deserialize_workflow(
        {
            "workflow": {
                "locations": [
                    {
                        "order": 1,
                        "kind": "main",
                        "findings": [
                            {"rule": "CORE:C:0042", "file": "CLAUDE.md", "line": 3, "impact_tier": "gate_mover"}
                        ],
                    }
                ]
            }
        }
    )
    assert wf is not None
    assert wf.locations[0].findings[0].impact_tier == "gate_mover"


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_defaults_finding_impact_tier_to_empty_when_absent() -> None:
    wf = deserialize_workflow(
        {"workflow": {"locations": [{"order": 1, "kind": "main", "findings": [{"rule": "CORE:C:0042"}]}]}}
    )
    assert wf is not None
    assert wf.locations[0].findings[0].impact_tier == ""


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_reads_listed_why() -> None:
    wf = deserialize_workflow(
        {
            "workflow": {
                "listed": [
                    {"rule": "CORE:S:0039", "reason": "cosmetic", "count": 4, "why": "A stray dash reads as noise."}
                ]
            }
        }
    )
    assert wf is not None
    assert wf.listed[0].why == "A stray dash reads as noise."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_deserialize_defaults_listed_why_to_empty_when_absent() -> None:
    wf = deserialize_workflow({"workflow": {"listed": [{"rule": "CORE:S:0039", "reason": "cosmetic", "count": 4}]}})
    assert wf is not None
    assert wf.listed[0].why == ""


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_workflow_present_in_json() -> None:
    wf = RemediationWorkflow(
        locations=(
            WorkflowLocation(
                order=1,
                element="CLAUDE.md",
                kind="main",
                loading="session_start",
                files=("CLAUDE.md",),
                importance="gate_mover",
                findings=(
                    LocationFinding(
                        rule="CORE:C:0042", file="CLAUDE.md", line=5, pi=1, message="Vague.", remedy="Name it."
                    ),
                ),
            ),
        ),
        escape="esc",
        summary="sum",
    )
    data = format_combined_result(_result(workflow=wf))
    loc = data["workflow"]["locations"][0]
    assert data["workflow"]["summary"] == "sum" and data["workflow"]["escape"] == "esc"
    assert loc["order"] == 1 and "tier" not in loc and loc["kind"] == "main"
    assert loc["files"] == ["CLAUDE.md"]
    assert loc["findings"] == [
        {
            "rule": "CORE:C:0042",
            "file": "CLAUDE.md",
            "line": 5,
            "pi": 1,
            "message": "Vague.",
            "remedy": "Name it.",
            "impact_tier": "",
            "members": [],
        }
    ]
    assert loc["relations"] == []


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_normalizes_absolute_location_paths() -> None:
    # The server builds paths in the map's absolute coordinates; the JSON must show them
    # project-relative, consistent with the per-finding locations (and no home leak).
    wf = RemediationWorkflow(
        locations=(
            WorkflowLocation(
                order=1,
                element="/home/u/proj/.claude/rules/style.md",
                kind="rule",
                loading="on_demand",
                files=("/home/u/proj/.claude/rules/style.md",),
                findings=(
                    LocationFinding(
                        rule="CORE:D:0002",
                        file="/home/u/proj/.claude/rules/style.md",
                        line=5,
                        pi=None,
                        message="m",
                        remedy="",
                    ),
                ),
            ),
        ),
        summary="s",
    )
    loc = format_combined_result(_result(workflow=wf), project_root=Path("/home/u/proj"))["workflow"]["locations"][0]
    assert loc["element"] == ".claude/rules/style.md"
    assert loc["files"] == [".claude/rules/style.md"]
    assert loc["findings"][0]["file"] == ".claude/rules/style.md"
    assert loc["findings"][0]["pi"] is None


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_carries_finding_impact_tier() -> None:
    wf = RemediationWorkflow(
        locations=(
            WorkflowLocation(
                order=1,
                element="CLAUDE.md",
                kind="main",
                loading="session_start",
                files=("CLAUDE.md",),
                findings=(
                    LocationFinding(
                        rule="CORE:C:0042",
                        file="CLAUDE.md",
                        line=5,
                        pi=1,
                        message="Vague.",
                        remedy="Name it.",
                        impact_tier="gate_mover",
                    ),
                ),
            ),
        ),
        summary="s",
    )
    data = format_combined_result(_result(workflow=wf))
    assert data["workflow"]["locations"][0]["findings"][0]["impact_tier"] == "gate_mover"


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_carries_listed_why() -> None:
    wf = RemediationWorkflow(
        listed=(ListedFinding(rule="CORE:S:0039", reason="cosmetic", count=2, why="A stray dash reads as noise."),),
        summary="s",
    )
    data = format_combined_result(_result(workflow=wf))
    assert data["workflow"]["listed"] == [
        {"rule": "CORE:S:0039", "reason": "cosmetic", "count": 2, "why": "A stray dash reads as noise."}
    ]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_workflow_omitted_when_absent() -> None:
    data = format_combined_result(_result(workflow=None))
    assert "workflow" not in data


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_empty_workflow_still_renders() -> None:
    """A clean paid project (no locations, nothing listed) is a real workflow result —
    "nothing to rewrite" — not the absence of the paid feature. Before the fix this read
    exactly like the anon/offline case (no `workflow` key at all), so a paid clean project's
    own client read "no workflow" and told the user heal needs a paid account."""
    data = format_combined_result(_result(workflow=RemediationWorkflow(locations=(), listed=(), summary="none")))
    assert data["workflow"]["locations"] == []
    assert data["workflow"]["summary"] == "none"
    assert "listed" not in data["workflow"]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_workflow_present_via_listed_alone() -> None:
    # No locations but a non-empty `listed` still counts as a workflow to render.
    wf = RemediationWorkflow(listed=(ListedFinding(rule="CORE:S:0039", reason="cosmetic", count=2),), summary="s")
    data = format_combined_result(_result(workflow=wf))
    assert data["workflow"]["locations"] == []
    assert data["workflow"]["listed"] == [{"rule": "CORE:S:0039", "reason": "cosmetic", "count": 2, "why": ""}]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_carries_relations_with_relative_paths() -> None:
    wf = RemediationWorkflow(
        locations=(
            WorkflowLocation(
                order=2,
                element="the `deploy` skill",
                kind="skills",
                loading="on_invocation",
                files=("/proj/.claude/skills/deploy/SKILL.md",),
                relations=(
                    LocationRelation(
                        rule="CORE:C:0044",
                        file="/proj/.claude/skills/deploy/SKILL.md",
                        line=22,
                        partner_file="/proj/CLAUDE.md",
                        partner_line=30,
                        message="m",
                        remedy="r",
                    ),
                ),
            ),
        ),
        summary="s",
    )
    loc = format_combined_result(_result(workflow=wf), project_root=Path("/proj"))["workflow"]["locations"][0]
    assert loc["relations"] == [
        {
            "rule": "CORE:C:0044",
            "file": ".claude/skills/deploy/SKILL.md",
            "line": 22,
            "partner_file": "CLAUDE.md",
            "partner_line": 30,
            "message": "m",
            "remedy": "r",
        }
    ]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_fills_an_empty_finding_message_from_the_client_s_own_finding() -> None:
    # A server-side finding with no message of its own (a local-check-derived defect) is filled
    # from the cli's own finding at the same (file, line, rule) when one exists.
    wf = RemediationWorkflow(
        locations=(
            WorkflowLocation(
                order=1,
                element="CLAUDE.md",
                kind="main",
                loading="session_start",
                files=("CLAUDE.md",),
                findings=(
                    LocationFinding(rule="CORE:S:0056", file="CLAUDE.md", line=7, pi=None, message="", remedy=""),
                ),
            ),
        ),
        summary="s",
    )
    client_finding = FindingItem(file="CLAUDE.md", line=7, severity="error", rule="CORE:S:0056", message="Broken link.")
    data = format_combined_result(_result(workflow=wf, findings=(client_finding,)))
    assert data["workflow"]["locations"][0]["findings"][0]["message"] == "Broken link."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_render_leaves_an_unfilled_empty_message_empty_when_no_client_finding_matches() -> None:
    wf = RemediationWorkflow(
        locations=(
            WorkflowLocation(
                order=1,
                element="CLAUDE.md",
                kind="main",
                loading="session_start",
                files=("CLAUDE.md",),
                findings=(
                    LocationFinding(rule="CORE:S:0056", file="CLAUDE.md", line=7, pi=None, message="", remedy=""),
                ),
            ),
        ),
        summary="s",
    )
    data = format_combined_result(_result(workflow=wf))
    assert data["workflow"]["locations"][0]["findings"][0]["message"] == ""
