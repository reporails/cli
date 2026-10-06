"""A directive inside an imported file silences its own line only; suppressed findings leave the workflow too."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.suppression import apply_suppressions, build_index, suppressed_lines
from reporails_cli.core.platform.dto.diagnostics import (
    LocationFinding,
    LocationRelation,
    RemediationWorkflow,
    WorkflowLocation,
)
from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem, merge_results
from reporails_cli.formatters.text.display_constants import rule_aliases

STYLE = "# Style\n\nKeep diffs small.{a}\n\nUse tabs.{b}\n\nPrefer clarity.{c}\n"


def _directive(rule: str) -> str:
    return f" <!-- ails-disable-line {rule} -->"


def _project(tmp_path: Path, a: str = "", b: str = "", c: str = "", import_line_suffix: str = "") -> Path:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "style.md").write_text(STYLE.format(a=a, b=b, c=c), encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text(f"# Project\n\n@docs/style.md{import_line_suffix}\n", encoding="utf-8")
    return tmp_path


# The three imported instructions as the service reports them: all on the import line (3), by position index.
PLACES = {
    ("CLAUDE.md", 1): ("docs/style.md", 3),
    ("CLAUDE.md", 2): ("docs/style.md", 5),
    ("CLAUDE.md", 3): ("docs/style.md", 7),
}


def _findings() -> tuple[FindingItem, ...]:
    return tuple(
        FindingItem("CLAUDE.md", 3, "warning", rule, f"{rule} on {pi}", source="server", pi=pi)
        for rule in ("CORE:C:0042", "CORE:E:0004")
        for pi in (1, 2, 3)
    )


def _survivors(result: CombinedResult) -> set[tuple[str, int | None]]:
    return {(f.rule, f.pi) for f in result.findings}


def _apply(root: Path, result: CombinedResult) -> CombinedResult:
    return apply_suppressions(result, project_root=root, alias_fn=rule_aliases, imported=PLACES)


def _combined(**kw: object) -> CombinedResult:
    return CombinedResult(findings=_findings(), **kw)  # type: ignore[arg-type]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_two_directives_in_one_imported_file_each_silence_their_own_line(tmp_path: Path) -> None:
    root = _project(tmp_path, a=_directive("CORE:C:0042"), c=_directive("CORE:E:0004"))
    out = _apply(root, _combined())
    assert _survivors(out) == {
        ("CORE:C:0042", 2),
        ("CORE:C:0042", 3),
        ("CORE:E:0004", 1),
        ("CORE:E:0004", 2),
    }


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_one_directive_in_an_imported_file_silences_one_instruction(tmp_path: Path) -> None:
    root = _project(tmp_path, a=_directive("CORE:C:0042"))
    out = _apply(root, _combined())
    assert ("CORE:C:0042", 1) not in _survivors(out)
    assert len(out.findings) == 5


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_two_rules_on_two_lines_of_one_import_both_stay_in_force(tmp_path: Path) -> None:
    root = _project(tmp_path, a=_directive("CORE:C:0042"), b=_directive("CORE:C:0042"))
    out = _apply(root, _combined())
    assert {pi for rule, pi in _survivors(out) if rule == "CORE:C:0042"} == {3}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_directive_on_the_import_line_silences_the_rule_for_everything_imported(tmp_path: Path) -> None:
    root = _project(tmp_path, import_line_suffix=_directive("CORE:C:0042"))
    out = _apply(root, _combined())
    assert {rule for rule, _ in _survivors(out)} == {"CORE:E:0004"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_directive_on_an_ordinary_line_is_unchanged(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(
        "# T\nDo it.  <!-- ails-disable-line CORE:C:0049 -->\nAgain.\n", encoding="utf-8"
    )
    findings = [
        FindingItem("CLAUDE.md", 2, "warning", "CORE:C:0049", "x"),
        FindingItem("CLAUDE.md", 3, "warning", "CORE:C:0049", "x"),
    ]
    out = apply_suppressions(CombinedResult(findings=tuple(findings)), project_root=tmp_path, alias_fn=rule_aliases)
    assert [f.line for f in out.findings] == [3]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_directive_in_a_twice_nested_import_silences_its_own_line(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "deep.md").write_text(
        f"# Deep\n\nFirst rule.\n\nSecond rule.{_directive('CORE:C:0042')}\n", encoding="utf-8"
    )
    (tmp_path / "sub" / "mid.md").write_text("# Mid\n\n@deep.md\n", encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("# Project\n\n@sub/mid.md\n", encoding="utf-8")
    places = {("CLAUDE.md", 1): ("sub/deep.md", 3), ("CLAUDE.md", 2): ("sub/deep.md", 5)}
    findings = tuple(FindingItem("CLAUDE.md", 3, "warning", "CORE:C:0042", "x", pi=pi) for pi in (1, 2))
    out = apply_suppressions(
        CombinedResult(findings=findings), project_root=tmp_path, alias_fn=rule_aliases, imported=places
    )
    assert [f.pi for f in out.findings] == [1]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_alias_names_in_an_imported_directive_silence_the_finding(tmp_path: Path) -> None:
    root = _project(tmp_path, a=_directive("CORE:C:0042"))
    findings = (FindingItem("CLAUDE.md", 3, "warning", "CORE:C:0042", "x", pi=1),)
    out = apply_suppressions(
        CombinedResult(findings=findings), project_root=root, alias_fn=lambda r: {r, "CORE:C:0042"}, imported=PLACES
    )
    assert out.findings == ()


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_heal_still_treats_the_import_line_as_annotated(tmp_path: Path) -> None:
    root = _project(tmp_path, a=_directive("CORE:C:0042"), c=_directive("CORE:E:0004"))
    assert suppressed_lines(["CLAUDE.md"], root) == {"CLAUDE.md": {3}}
    assert build_index(["CLAUDE.md"], root).imported == {
        ("CLAUDE.md", "docs/style.md", 3): {"CORE:C:0042"},
        ("CLAUDE.md", "docs/style.md", 7): {"CORE:E:0004"},
    }


def _loc(order: int, file: str, *rules: tuple[str, int, int | None], relations: tuple[LocationRelation, ...] = ()):
    return WorkflowLocation(
        order=order,
        element=file,
        kind="main",
        loading="always",
        files=(file,),
        findings=tuple(LocationFinding(r, file, line, pi, "m", "r") for r, line, pi in rules),
        relations=relations,
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_suppressed_finding_leaves_the_workflow_and_emptied_location_is_dropped(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(
        "# T\nDo it.  <!-- ails-disable-line CORE:C:0042 -->\nOther.\n", encoding="utf-8"
    )
    (tmp_path / "b.md").write_text("# B\nKeep.\n", encoding="utf-8")
    workflow = RemediationWorkflow(
        locations=(
            _loc(1, "CLAUDE.md", ("CORE:C:0042", 2, None), ("CORE:E:0004", 3, None)),
            _loc(2, "b.md", ("CORE:E:0004", 2, None)),
        ),
        summary="served",
    )
    only = _loc(3, "c.md", ("CORE:C:0042", 9, None))
    (tmp_path / "c.md").write_text("x\n" * 8 + "Do it. <!-- ails-disable-line CORE:C:0042 -->\n", encoding="utf-8")
    workflow = RemediationWorkflow(locations=(*workflow.locations, only), summary="served")
    result = CombinedResult(findings=(), workflow=workflow)
    out = apply_suppressions(result, project_root=tmp_path, alias_fn=rule_aliases)
    assert out.workflow is not None
    assert [(loc.order, loc.element) for loc in out.workflow.locations] == [(1, "CLAUDE.md"), (2, "b.md")]
    assert [f.rule for f in out.workflow.locations[0].findings] == ["CORE:E:0004"]
    assert out.workflow.summary == "2 locations to rewrite, by kind: 2 main."


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_location_with_only_a_relation_left_is_kept(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text("# T\nDo it.  <!-- ails-disable-line CORE:C:0042 -->\n", encoding="utf-8")
    rel = LocationRelation("CORE:E:0001", "CLAUDE.md", 2, "o.md", 1, "m", "r")
    workflow = RemediationWorkflow(locations=(_loc(1, "CLAUDE.md", ("CORE:C:0042", 2, None), relations=(rel,)),))
    out = apply_suppressions(
        CombinedResult(findings=(), workflow=workflow), project_root=tmp_path, alias_fn=rule_aliases
    )
    assert out.workflow is not None
    assert out.workflow.locations[0].findings == ()
    assert out.workflow.locations[0].relations == (rel,)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_suppressed_imported_finding_leaves_the_workflow(tmp_path: Path) -> None:
    root = _project(tmp_path, a=_directive("CORE:C:0042"))
    workflow = RemediationWorkflow(locations=(_loc(1, "CLAUDE.md", ("CORE:C:0042", 3, 1), ("CORE:C:0042", 3, 2)),))
    out = apply_suppressions(
        CombinedResult(findings=(), workflow=workflow), project_root=root, alias_fn=rule_aliases, imported=PLACES
    )
    assert out.workflow is not None
    assert [f.pi for f in out.workflow.locations[0].findings] == [2]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_merge_keeps_a_servers_position_index_on_its_finding() -> None:
    from reporails_cli.core.platform.dto.diagnostics import Diagnostic, FileAnalysis, RulesetReport

    diag = Diagnostic("CLAUDE.md", 3, "warning", "CORE:C:0042", "m", pi=2)
    report = RulesetReport(per_file=(FileAnalysis(file="CLAUDE.md", diagnostics=(diag,)),))
    result = merge_results([], [], report)
    assert [f.pi for f in result.findings] == [2]


def _no_position_project(tmp_path: Path, style: str) -> Path:
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "style.md").write_text(style, encoding="utf-8")
    (tmp_path / "CLAUDE.md").write_text("# Project\n\n@docs/style.md\n", encoding="utf-8")
    return tmp_path


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_finding_without_position_on_import_line_is_silenced_by_imported_directive(tmp_path: Path) -> None:
    root = _no_position_project(tmp_path, f"# Style\n\nNever push to main directly.{_directive('CORE:E:0006')}\n")
    findings = (FindingItem("CLAUDE.md", 3, "warning", "CORE:E:0006", "x"),)
    out = apply_suppressions(CombinedResult(findings=findings), project_root=root, alias_fn=rule_aliases)
    assert out.findings == ()


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_directives_under_one_import_merge_for_findings_without_position(tmp_path: Path) -> None:
    style = (
        f"# Style\n\nNever push to main directly.{_directive('CORE:E:0006')}\n\n"
        f"Never force push.{_directive('CORE:E:0001')}\n"
    )
    root = _no_position_project(tmp_path, style)
    findings = (
        FindingItem("CLAUDE.md", 3, "warning", "CORE:E:0006", "x"),
        FindingItem("CLAUDE.md", 3, "warning", "CORE:E:0001", "x"),
        FindingItem("CLAUDE.md", 3, "warning", "CORE:C:0042", "x", pi=1),
        FindingItem("CLAUDE.md", 3, "warning", "CORE:E:0006", "x", pi=2),
    )
    places = {("CLAUDE.md", 1): ("docs/style.md", 3), ("CLAUDE.md", 2): ("docs/style.md", 5)}
    out = apply_suppressions(
        CombinedResult(findings=findings), project_root=root, alias_fn=rule_aliases, imported=places
    )
    assert [(f.rule, f.pi) for f in out.findings] == [("CORE:C:0042", 1), ("CORE:E:0006", 2)]
