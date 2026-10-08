"""A workflow finding that owns other findings: parsed, nested in JSON and the brief, and suppressed per member."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.core.lint.suppression import apply_suppressions
from reporails_cli.core.platform.adapters.workflow_wire import deserialize_workflow
from reporails_cli.core.platform.dto.diagnostics import (
    LocationFinding,
    RemediationWorkflow,
    walk_findings,
)
from reporails_cli.core.platform.runtime.merger import CombinedResult, CombinedStats, FindingItem
from reporails_cli.formatters.json import format_combined_result
from reporails_cli.formatters.text.rule_meta import rule_aliases
from reporails_cli.interfaces.mcp import remedy_brief, tools

pytestmark = [pytest.mark.unit, pytest.mark.subsys_diagnostic]

E4 = "CORE:E:0004"
C42 = "CORE:C:0042"
C51 = "CORE:C:0051"
C58 = "CORE:C:0058"


def _wire(
    rule: str,
    pi: int | None,
    members: list[dict[str, Any]] | None = None,
    file: str = "CLAUDE.md",
    tier: str = "gate_mover",
    line: int = 7,
) -> dict:
    d: dict[str, Any] = {
        "rule": rule,
        "file": file,
        "line": line,
        "pi": pi,
        "message": f"{rule} m",
        "remedy": "r",
        "impact_tier": tier,
    }
    if members is not None:
        d["members"] = members
    return d


def _packed_wire(file: str = "CLAUDE.md") -> dict[str, Any]:
    inner = [_wire(C42, 3, [], file), _wire(E4, 3, [], file)]
    members = [_wire(E4, 1, [], file), _wire(E4, 2, [], file), _wire(C51, 3, inner, file)]
    return _wire(C58, None, members, file)


def _loc_wire(findings: list[dict[str, Any]], file: str = "CLAUDE.md") -> dict[str, Any]:
    return {"order": 1, "element": file, "kind": "main", "loading": "always", "files": [file], "findings": findings}


def _packed_workflow() -> RemediationWorkflow:
    wf = deserialize_workflow({"workflow": {"locations": [_loc_wire([_packed_wire()])]}})
    assert wf is not None
    return wf


def _shape(f: LocationFinding) -> Any:
    return (f.rule, f.pi, [_shape(m) for m in f.members]) if f.members else (f.rule, f.pi)


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_parse_reads_members_two_levels_deep_in_order() -> None:
    (owner,) = _packed_workflow().locations[0].findings
    assert _shape(owner) == (
        C58,
        None,
        [(E4, 1), (E4, 2), (C51, 3, [(C42, 3), (E4, 3)])],
    )
    assert [f.rule for f in walk_findings([owner])] == [C58, E4, E4, C51, C42, E4]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_parse_without_members_reads_as_before() -> None:
    wf = deserialize_workflow({"workflow": {"locations": [_loc_wire([_wire(E4, 1)])]}})
    assert wf is not None
    assert wf.locations[0].findings[0].members == ()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_parse_skips_a_malformed_member_and_a_malformed_members_value() -> None:
    wf = deserialize_workflow(
        {
            "workflow": {
                "locations": [_loc_wire([_wire(C58, None, ["bad", _wire(E4, 1)]), {**_wire(E4, 2), "members": 5}])]
            }
        }
    )
    assert wf is not None
    owner, plain = wf.locations[0].findings
    assert [m.rule for m in owner.members] == [E4]
    assert plain.members == ()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_json_nests_members_with_relative_paths_and_a_filled_message() -> None:
    root = Path("/home/u/proj")
    wire = _packed_wire("/home/u/proj/CLAUDE.md")
    wire["members"][0]["message"] = ""
    wf = deserialize_workflow({"workflow": {"locations": [_loc_wire([wire], "/home/u/proj/CLAUDE.md")]}})
    local = FindingItem(file="CLAUDE.md", line=7, severity="warning", rule=E4, message="from the client")
    result = CombinedResult(
        findings=(local,), cross_file=(), quality=None, per_file_analysis=(), stats=CombinedStats(), workflow=wf
    )
    (row,) = format_combined_result(result, project_root=root)["workflow"]["locations"][0]["findings"]
    assert row["file"] == "CLAUDE.md"
    assert [m["rule"] for m in row["members"]] == [E4, E4, C51]
    assert row["members"][0]["message"] == "from the client"
    assert row["members"][0]["members"] == []
    nested = row["members"][2]["members"]
    assert [m["rule"] for m in nested] == [C42, E4]
    assert {m["file"] for m in nested} == {"CLAUDE.md"}


# ---- suppression ---------------------------------------------------------------------------------


def _project(tmp_path: Path, silenced: tuple[str, ...]) -> Path:
    directive = "".join(f" <!-- ails-disable-line {r} -->" for r in silenced)
    (tmp_path / "CLAUDE.md").write_text("# T\n" + "x\n" * 5 + f"Packed sentence.{directive}\n", encoding="utf-8")
    return tmp_path


def _suppressed(tmp_path: Path, *silenced: str, workflow: RemediationWorkflow | None = None) -> RemediationWorkflow:
    root = _project(tmp_path, silenced)
    result = CombinedResult(findings=(), workflow=workflow or _packed_workflow())
    out = apply_suppressions(result, project_root=root, alias_fn=rule_aliases)
    assert out.workflow is not None
    return out.workflow


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_silencing_a_plain_member_rule_replaces_the_instruction_owner_left_with_one(tmp_path: Path) -> None:
    (owner,) = _suppressed(tmp_path, E4).locations[0].findings
    assert _shape(owner) == (C58, None, [(C42, 3)])


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_silencing_the_sentence_owner_releases_its_members_as_sorted_rows(tmp_path: Path) -> None:
    rows = _suppressed(tmp_path, C58).locations[0].findings
    assert [(f.rule, f.pi) for f in rows] == [(E4, 1), (E4, 2), (C51, 3)]
    assert [m.rule for m in rows[2].members] == [C42, E4]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_silencing_an_instruction_owner_hands_its_members_to_the_sentence_owner(tmp_path: Path) -> None:
    (owner,) = _suppressed(tmp_path, C51).locations[0].findings
    assert [(m.rule, m.pi) for m in owner.members] == [(E4, 1), (E4, 2), (C42, 3), (E4, 3)]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_silencing_every_member_rule_leaves_the_sentence_owner_alone(tmp_path: Path) -> None:
    (owner,) = _suppressed(tmp_path, E4, C42, C51).locations[0].findings
    assert owner.rule == C58 and owner.members == ()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_an_instruction_owner_with_every_member_silenced_is_dropped_with_its_location(tmp_path: Path) -> None:
    owner = _wire(C51, 3, [_wire(C42, 3), _wire(E4, 3)])
    other = _loc_wire([_wire(C42, 7, [], "other.md")], "other.md")
    other["order"] = 2
    wf = deserialize_workflow({"workflow": {"locations": [_loc_wire([owner]), other]}})
    (tmp_path / "other.md").write_text("a\n", encoding="utf-8")
    out = _suppressed(tmp_path, C42, E4, workflow=wf)
    assert [(loc.order, loc.element) for loc in out.locations] == [(1, "other.md")]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_an_instruction_owner_served_with_one_member_stands_when_another_row_is_silenced(tmp_path: Path) -> None:
    owner = _wire(C51, 3, [_wire(C42, 3)])
    wf = deserialize_workflow({"workflow": {"locations": [_loc_wire([owner, _wire(E4, 1, [])])]}})
    (kept,) = _suppressed(tmp_path, E4, workflow=wf).locations[0].findings
    assert _shape(kept) == (C51, 3, [(C42, 3)])


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_nothing_silenced_leaves_the_workflow_untouched(tmp_path: Path) -> None:
    wf = _packed_workflow()
    assert _suppressed(tmp_path, "CORE:X:0001", workflow=wf) is wf


# ---- remedy brief --------------------------------------------------------------------------------


def _atom(abs_file: Path) -> Any:
    return SimpleNamespace(
        line=7,
        position_index=3,
        text="Packed sentence.",
        charge_value=1,
        named_tokens=[],
        embedding_int8=None,
        unformatted_code=[],
        kind="excitation",
        role="",
        file_path=str(abs_file),
        format="prose",
        heading_context="",
        scope_conditional=False,
        plain_text="Packed sentence.",
        modality="direct",
    )


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_the_brief_carries_nested_members_and_targets_their_rules(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    abs_file = tmp_path / "CLAUDE.md"
    abs_file.write_text("# T\n" + "x\n" * 5 + "Packed sentence.\n")
    fake_map = SimpleNamespace(atoms=(_atom(abs_file),), files=())
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, fake_map, None))
    location = {**_loc_wire([_packed_wire()]), "importance": "gate_mover", "relations": []}

    first = remedy_brief.remedy_brief_tool(location, tmp_path)
    replies = [
        remedy_brief.remedy_brief_tool(location, tmp_path, part=n) for n in range(1, first.get("total_parts", 1) + 1)
    ]
    reply = {
        "findings": [f for r in replies for f in r["findings"]],
        "files": [f for r in replies for f in r["files"]],
    }

    (owner,) = reply["findings"]
    assert owner["rule"] == C58
    assert [m["rule"] for m in owner["members"]] == [E4, E4, C51]
    assert [m["rule"] for m in owner["members"][2]["members"]] == [C42, E4]
    (instruction,) = reply["files"][0]["instructions"]
    assert set(instruction["targets"]) == {C58, E4, C51, C42}


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_the_mcp_index_counts_owners_and_members_as_findings() -> None:
    from reporails_cli.formatters.mcp import _workflow_index

    index = _workflow_index({"locations": [_loc_wire([_packed_wire()])]})
    assert index["locations"][0]["finding_count"] == 6


def _tiered_rows() -> list[dict[str, Any]]:
    owner = _wire(C58, None, [_wire(C42, 1, tier="gate_mover", line=9)], tier="conditional", line=9)
    plain = _wire(C42, 2, tier="conditional", line=3)
    return [plain, owner]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_conditional_owner_holding_a_gate_mover_member_sorts_first_after_suppression(tmp_path: Path) -> None:
    rows = [*_tiered_rows(), _wire(E4, 9, tier="cosmetic", line=7)]
    wf = deserialize_workflow({"workflow": {"locations": [_loc_wire(rows)]}})
    out = _suppressed(tmp_path, E4, workflow=wf).locations[0].findings
    assert [(f.rule, f.line) for f in out] == [(C58, 9), (C42, 3)]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_the_brief_sorts_a_conditional_owner_with_a_gate_mover_member_before_a_plain_conditional() -> None:
    ordered = remedy_brief._sorted_findings(_tiered_rows())
    assert [f["rule"] for f in ordered] == [C58, C42]
