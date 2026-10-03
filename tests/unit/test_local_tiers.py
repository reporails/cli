"""Unit tests for the grade a client-reported finding takes from the reply."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.adapters.api_client import _deserialize_lint_result
from reporails_cli.core.platform.dto.diagnostics import LocalTier
from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem, stamp_local_tiers


def _f(file: str, rule: str, line: int = 1, tier: str = "") -> FindingItem:
    return FindingItem(file=file, line=line, severity="error", rule=rule, message="m", impact_tier=tier)


def _row(file: str, rule: str, line: int, tier: str) -> LocalTier:
    return LocalTier(file=file, rule=rule, line=line, impact_tier=tier)


class TestStampLocalTiers:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_a_row_grade_lands_on_the_finding_at_its_file_rule_and_line(self) -> None:
        result = CombinedResult(findings=(_f("a.md", "CORE:C:0011", 4), _f("a.md", "CORE:C:0011", 9)))
        out = stamp_local_tiers(result, (_row("a.md", "CORE:C:0011", 9, "conditional"),), None)
        assert [f.impact_tier for f in out.findings] == ["", "conditional"]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_a_whole_file_row_grades_the_same_rule_at_any_line(self) -> None:
        result = CombinedResult(findings=(_f("a.md", "CORE:C:0011", 1), _f("a.md", "CORE:C:0034", 1)))
        out = stamp_local_tiers(result, (_row("a.md", "CORE:C:0011", 0, "cosmetic"),), None)
        assert [f.impact_tier for f in out.findings] == ["cosmetic", ""]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_a_finding_without_a_row_keeps_no_grade(self) -> None:
        result = CombinedResult(findings=(_f("a.md", "CORE:C:0011"), _f("b.md", "CORE:C:0034")))
        out = stamp_local_tiers(result, (_row("a.md", "CORE:C:0042", 1, "gate_mover"),), None)
        assert [f.impact_tier for f in out.findings] == ["", ""]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_rows_stamps_nothing(self) -> None:
        result = CombinedResult(findings=(_f("a.md", "CORE:C:0011"),))
        assert stamp_local_tiers(result, (), None).findings == result.findings

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_a_finding_that_already_has_a_grade_keeps_it(self) -> None:
        result = CombinedResult(findings=(_f("a.md", "CORE:C:0011", tier="cosmetic"),))
        out = stamp_local_tiers(result, (_row("a.md", "CORE:C:0011", 1, "gate_mover"),), None)
        assert out.findings[0].impact_tier == "cosmetic"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_an_absolute_row_path_matches_a_relative_finding(self, tmp_path) -> None:
        result = CombinedResult(findings=(_f("CLAUDE.md", "CORE:C:0011"),))
        rows = (_row(str(tmp_path / "CLAUDE.md"), "CORE:C:0011", 1, "conditional"),)
        out = stamp_local_tiers(result, rows, tmp_path)
        assert out.findings[0].impact_tier == "conditional"


class TestReadLocalTiers:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_rows_are_read_from_the_report(self) -> None:
        data = {
            "report": {"local_tiers": [{"file": "a.md", "rule": "CORE:C:0011", "line": 3, "impact_tier": "cosmetic"}]}
        }
        rows = _deserialize_lint_result(data).report.local_tiers
        assert rows == (LocalTier(file="a.md", rule="CORE:C:0011", line=3, impact_tier="cosmetic"),)

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize("report", [{}, {"local_tiers": None}, {"local_tiers": "x"}, {"local_tiers": []}])
    def test_a_missing_null_or_empty_list_is_no_rows(self, report: dict) -> None:
        assert _deserialize_lint_result({"report": report}).report.local_tiers == ()

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_a_malformed_row_is_skipped_and_the_rest_are_kept(self) -> None:
        good = {"file": "a.md", "rule": "CORE:C:0011", "line": 3, "impact_tier": "conditional"}
        rows = [
            "junk",
            None,
            {"file": "a.md", "rule": "CORE:C:0011", "line": "x", "impact_tier": "conditional"},
            {"file": "a.md", "rule": "CORE:C:0011", "line": 3},
            {"rule": "CORE:C:0011", "line": 3, "impact_tier": "conditional"},
            good,
        ]
        out = _deserialize_lint_result({"report": {"local_tiers": rows}}).report.local_tiers
        assert out == (LocalTier(file="a.md", rule="CORE:C:0011", line=3, impact_tier="conditional"),)
