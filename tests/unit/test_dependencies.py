"""A finding is dropped where a rule it depends on already reports."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.policy.dependencies import drop_dependent_findings

pytestmark = [pytest.mark.unit, pytest.mark.subsys_lint]


def _f(rule: str, file: str = "a.md", line: int = 1, check: str = "c") -> LocalFinding:
    return LocalFinding(file, line, "warning", rule, "m", check_id=check)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_finding_on_the_same_file_as_its_dependency_is_dropped():
    kept = drop_dependent_findings([_f("R:1"), _f("D:1")], {"R:1": frozenset({"D:1"})}, frozenset())
    assert [f.rule for f in kept] == ["D:1"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_per_file_finding_stays_when_the_dependency_reports_on_another_file():
    findings = [_f("R:1", "a.md"), _f("D:1", "b.md")]
    kept = drop_dependent_findings(findings, {"R:1": frozenset({"D:1"})}, frozenset())
    assert kept == findings


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_whole_run_finding_is_dropped_when_the_dependency_reports_anywhere():
    findings = [_f("R:1", "a.md", check="whole"), _f("D:1", "b.md")]
    kept = drop_dependent_findings(findings, {"R:1": frozenset({"D:1"})}, frozenset({"whole"}))
    assert [f.rule for f in kept] == ["D:1"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_chain_drops_every_dependent_and_keeps_the_root():
    findings = [_f("A:1"), _f("B:1"), _f("C:1")]
    deps = {"A:1": frozenset({"B:1"}), "B:1": frozenset({"C:1"})}
    assert [f.rule for f in drop_dependent_findings(findings, deps, frozenset())] == ["C:1"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_rule_without_dependencies_is_untouched_and_order_is_kept():
    findings = [_f("X:1", line=9), _f("D:1", line=2), _f("R:1", line=5), _f("Y:1", line=1)]
    kept = drop_dependent_findings(findings, {"R:1": frozenset({"D:1"})}, frozenset())
    assert [f.rule for f in kept] == ["X:1", "D:1", "Y:1"]
