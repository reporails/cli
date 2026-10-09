"""The remediation workflow stays consistent with the findings the user is shown.

A finding removed after the reply arrived (silenced by a directive, or dropped on a surface its
rule does not apply to) leaves the workflow's locations, its summary and its listed counts in
agreement with the findings that remain.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.core.lint.suppression import apply_suppressions, apply_surface_mutations
from reporails_cli.core.platform.adapters.workflow_wire import deserialize_workflow
from reporails_cli.core.platform.dto.diagnostics import RemediationWorkflow
from reporails_cli.core.platform.runtime.merger import CombinedResult, CombinedStats, FindingItem
from reporails_cli.formatters.text.rule_meta import rule_aliases

E4 = "CORE:E:0004"
D3 = "CORE:D:0003"


def _row(rule: str, file: str, line: int = 2) -> dict[str, Any]:
    return {
        "rule": rule,
        "file": file,
        "line": line,
        "pi": 0,
        "message": "m",
        "remedy": "r",
        "impact_tier": "gate_mover",
        "members": [],
    }


def _loc(order: int, kind: str, file: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "order": order,
        "element": file,
        "kind": kind,
        "loading": "always",
        "files": [file],
        "findings": rows,
    }


def _workflow(locations: list[dict[str, Any]], listed: list[dict[str, Any]] | None = None) -> RemediationWorkflow:
    wf = deserialize_workflow({"workflow": {"summary": "stale", "locations": locations, "listed": listed or []}})
    assert wf is not None
    return wf


def _item(rule: str, file: str, line: int = 2, source: str = "server") -> FindingItem:
    return FindingItem(file=file, line=line, severity="warning", rule=rule, message="m", source=source, pi=0)


def _result(items: list[FindingItem], workflow: RemediationWorkflow) -> CombinedResult:
    return CombinedResult(findings=tuple(items), stats=CombinedStats(total_findings=len(items)), workflow=workflow)


def _project(tmp_path: Path, silenced: dict[str, str]) -> Path:
    for name, rule in silenced.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(f"# T\nA line. <!-- ails-disable-line {rule} -->\n", encoding="utf-8")
    return tmp_path


def _listed_entry(rule: str, count: int) -> dict[str, Any]:
    return {"rule": rule, "reason": "no_remedy", "count": count, "why": ""}


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_silencing_a_whole_location_leaves_the_summary_naming_the_locations_kept(tmp_path: Path) -> None:
    wf = _workflow(
        [_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md")]), _loc(2, "skills", "a.md", [_row(D3, "a.md")])]
    )
    root = _project(tmp_path, {"CLAUDE.md": E4})
    (root / "a.md").write_text("# T\nA line.\n", encoding="utf-8")
    result = _result([_item(E4, "CLAUDE.md"), _item(D3, "a.md")], wf)

    out = apply_suppressions(result, project_root=root, alias_fn=rule_aliases)

    assert [loc.order for loc in out.workflow.locations] == [1]
    assert out.workflow.summary == "1 location to rewrite, by kind: 1 skills."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_silencing_every_location_says_there_is_nothing_to_rewrite(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md")])], [_listed_entry("CORE:C:0035", 1)])
    root = _project(tmp_path, {"CLAUDE.md": E4})

    out = apply_suppressions(_result([_item(E4, "CLAUDE.md")], wf), project_root=root, alias_fn=rule_aliases)

    assert out.workflow.locations == ()
    assert out.workflow.summary == "Nothing to rewrite — every finding is listed with the reason it takes none."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_silencing_every_finding_says_no_remediation_is_needed(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md")])])
    root = _project(tmp_path, {"CLAUDE.md": E4})

    out = apply_suppressions(_result([_item(E4, "CLAUDE.md")], wf), project_root=root, alias_fn=rule_aliases)

    assert out.workflow.summary == "No remediation needed — the surface carries no findings."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_silenced_finding_with_the_rule_still_firing_keeps_the_served_listed_count(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md", 5)])], [_listed_entry(D3, 2)])
    root = _project(tmp_path, {"CLAUDE.md": D3})
    items = [_item(E4, "CLAUDE.md", 5), _item(D3, "CLAUDE.md", 2), _item(D3, "other.md", 2)]

    out = apply_suppressions(_result(items, wf), project_root=root, alias_fn=rule_aliases)

    assert [(e.rule, e.count) for e in out.workflow.listed] == [(D3, 2)]
    assert len(out.workflow.locations) == 1


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_listed_rule_left_with_no_finding_is_removed(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md", 5)])], [_listed_entry(D3, 1)])
    root = _project(tmp_path, {"CLAUDE.md": D3})

    out = apply_suppressions(
        _result([_item(E4, "CLAUDE.md", 5), _item(D3, "CLAUDE.md", 2)], wf), project_root=root, alias_fn=rule_aliases
    )

    assert out.workflow.listed == ()
    assert out.workflow.summary == "1 location to rewrite, by kind: 1 main."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_silenced_finding_a_location_serves_leaves_listed_alone(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(D3, "CLAUDE.md")])], [_listed_entry(D3, 1)])
    root = _project(tmp_path, {"CLAUDE.md": D3})
    items = [_item(D3, "CLAUDE.md", 2), _item(D3, "other.md", 2)]

    out = apply_suppressions(_result(items, wf), project_root=root, alias_fn=rule_aliases)

    assert [(e.rule, e.count) for e in out.workflow.listed] == [(D3, 1)]


def _memory_rules() -> dict[str, Any]:
    return {D3: SimpleNamespace(surface_mutations={"memory": {"applies": False}})}


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_finding_dropped_on_the_memory_surface_leaves_its_location_and_summary(tmp_path: Path) -> None:
    mem = ".claude/agent-memory/reviewer/MEMORY.md"
    wf = _workflow(
        [_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md")]), _loc(2, "subagent_memory", mem, [_row(D3, mem)])]
    )
    items = [_item(E4, "CLAUDE.md"), _item(D3, mem)]

    out = apply_surface_mutations(_result(items, wf), _memory_rules(), project_root=tmp_path)

    assert [f.rule for f in out.findings] == [E4]
    assert [(loc.order, loc.kind) for loc in out.workflow.locations] == [(1, "main")]
    assert out.workflow.summary == "1 location to rewrite, by kind: 1 main."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_finding_dropped_on_the_memory_surface_keeps_the_served_listed_count_while_the_rule_fires(
    tmp_path: Path,
) -> None:
    mem = ".claude/agent-memory/reviewer/MEMORY.md"
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md")])], [_listed_entry(D3, 2)])
    items = [_item(E4, "CLAUDE.md"), _item(D3, "CLAUDE.md", 3), _item(D3, mem)]

    out = apply_surface_mutations(_result(items, wf), _memory_rules(), project_root=tmp_path)

    assert [(e.rule, e.count) for e in out.workflow.listed] == [(D3, 2)]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_rule_dropped_everywhere_on_the_memory_surface_is_no_longer_listed(tmp_path: Path) -> None:
    mem = ".claude/agent-memory/reviewer/MEMORY.md"
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md")])], [_listed_entry(D3, 2)])
    items = [_item(E4, "CLAUDE.md"), _item(D3, mem, 2), _item(D3, mem, 3)]

    out = apply_surface_mutations(_result(items, wf), _memory_rules(), project_root=tmp_path)

    assert out.workflow.listed == ()


def _two_line_project(tmp_path: Path, silenced_lines: tuple[bool, bool]) -> Path:
    tag = f" <!-- ails-disable-line {D3} -->"
    lines = [f"A line.{tag if silenced_lines[0] else ''}", f"Another line.{tag if silenced_lines[1] else ''}"]
    (tmp_path / "CLAUDE.md").write_text("# T\n" + "\n".join(lines) + "\n", encoding="utf-8")
    return tmp_path


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_overlap_rows_all_silenced_remove_the_listed_rule(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md", 9)])], [_listed_entry(D3, 4)])
    root = _two_line_project(tmp_path, (True, True))
    items = [_item(E4, "CLAUDE.md", 9), _item(D3, "CLAUDE.md", 2), _item(D3, "CLAUDE.md", 3)]

    out = apply_suppressions(_result(items, wf), project_root=root, alias_fn=rule_aliases)

    assert out.workflow.listed == ()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_overlap_rows_partly_silenced_keep_the_served_listed_count(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md", 9)])], [_listed_entry(D3, 4)])
    root = _two_line_project(tmp_path, (True, False))
    items = [_item(E4, "CLAUDE.md", 9), _item(D3, "CLAUDE.md", 2), _item(D3, "CLAUDE.md", 3)]

    out = apply_suppressions(_result(items, wf), project_root=root, alias_fn=rule_aliases)

    assert [(e.rule, e.count) for e in out.workflow.listed] == [(D3, 4)]


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_two_rows_merged_into_one_finding_and_silenced_remove_the_listed_rule(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(E4, "CLAUDE.md", 9)])], [_listed_entry(D3, 2)])
    root = _two_line_project(tmp_path, (True, False))
    items = [_item(E4, "CLAUDE.md", 9), _item(D3, "CLAUDE.md", 2)]

    out = apply_suppressions(_result(items, wf), project_root=root, alias_fn=rule_aliases)

    assert out.workflow.listed == ()


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_workflow_with_no_locations_follows_a_silenced_finding(tmp_path: Path) -> None:
    wf = _workflow([], [_listed_entry(D3, 1), _listed_entry("CORE:C:0035", 1)])
    root = _project(tmp_path, {"CLAUDE.md": D3})

    out = apply_suppressions(_result([_item(D3, "CLAUDE.md", 2)], wf), project_root=root, alias_fn=rule_aliases)

    assert [e.rule for e in out.workflow.listed] == ["CORE:C:0035"]
    assert out.workflow.summary == "Nothing to rewrite — every finding is listed with the reason it takes none."


@pytest.mark.unit
@pytest.mark.subsys_diagnostic
def test_a_surface_that_drops_nothing_leaves_the_workflow_untouched(tmp_path: Path) -> None:
    wf = _workflow([_loc(1, "main", "CLAUDE.md", [_row(D3, "CLAUDE.md")])], [_listed_entry(D3, 1)])
    result = _result([_item(D3, "CLAUDE.md")], wf)

    assert apply_surface_mutations(result, _memory_rules(), project_root=tmp_path) is result
