"""Tests for formatters/json.py — JSON output format."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.adapters.api_client import CrossFileCoordinate, Hint
from reporails_cli.core.platform.runtime.merger import CombinedResult, CombinedStats
from reporails_cli.formatters.json import format_combined_result


def _result(**overrides: object) -> CombinedResult:
    defaults: dict[str, object] = {
        "findings": (),
        "cross_file": (),
        "quality": None,
        "per_file_analysis": (),
        "stats": CombinedStats(total_findings=0, errors=0, warnings=0, infos=0),
        "offline": True,
        "hints": (),
        "cross_file_coordinates": (),
    }
    defaults.update(overrides)
    return CombinedResult(**defaults)  # type: ignore[arg-type]


class TestProSection:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_pro_section_present_with_hints(self) -> None:
        hints = (
            Hint(
                file="a.md", diagnostic_type="CORE:C:0044", count=5, summary="5 topics", error_count=2, warning_count=3
            ),
            Hint(
                file="b.md", diagnostic_type="CORE:C:0047", count=3, summary="3 buried", error_count=0, warning_count=3
            ),
        )
        data = format_combined_result(_result(hints=hints))
        assert "pro" in data
        assert data["pro"]["count"] == 8
        assert data["pro"]["errors"] == 2
        assert data["pro"]["warnings"] == 6

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_pro_section_without_hints(self) -> None:
        data = format_combined_result(_result())
        assert "pro" not in data


class TestCrossFileCoordinatesSection:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_coordinates_serialized(self) -> None:
        coords = (
            CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="conflict", count=2),
            CrossFileCoordinate(file_1="c.md", file_2="d.md", finding_type="repetition", count=1),
        )
        data = format_combined_result(_result(cross_file_coordinates=coords))
        assert "cross_file_coordinates" in data
        assert len(data["cross_file_coordinates"]) == 2
        assert data["cross_file_coordinates"][0]["type"] == "conflict"
        assert data["cross_file_coordinates"][0]["count"] == 2

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_no_coordinates_section_when_empty(self) -> None:
        data = format_combined_result(_result())
        assert "cross_file_coordinates" not in data


class TestTierExposure:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_tier_present_at_top_level(self) -> None:
        data = format_combined_result(_result(tier="pro"))
        assert data["tier"] == "pro"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_tier_empty_when_offline(self) -> None:
        data = format_combined_result(_result())
        assert data["tier"] == ""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_tier_pass_through_for_anonymous(self) -> None:
        data = format_combined_result(_result(tier="anonymous"))
        assert data["tier"] == "anonymous"


class TestPerFindingCategory:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize(
        "rule_id,expected",
        [
            ("CORE:S:0001", "structure"),
            ("CORE:D:0002", "direction"),
            ("CORE:C:0053", "coherence"),
            ("CORE:E:0004", "efficiency"),
            ("CORE:M:0001", "maintenance"),
            ("CORE:G:0001", "governance"),
            ("CLAUDE:S:0012", "structure"),
        ],
    )
    def test_category_derived_from_rule_id(self, rule_id: str, expected: str) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (FindingItem(file="a.md", line=1, severity="error", rule=rule_id, message="x"),)
        data = format_combined_result(_result(findings=findings))
        entry = data["files"]["a.md"]["findings"][0]
        assert entry["category"] == expected

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_category_empty_for_bare_token_rule_id(self) -> None:
        """Bare-token rule ids (issue #31 D) yield empty category, not a crash."""
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (FindingItem(file="a.md", line=1, severity="warning", rule="format", message="x"),)
        data = format_combined_result(_result(findings=findings))
        assert data["files"]["a.md"]["findings"][0]["category"] == ""


class TestSurfaceCategoryBreakdown:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_breakdown_sums_to_finding_count_for_well_formed_rules(self) -> None:
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(file="CLAUDE.md", line=1, severity="error", rule="CORE:C:0001", message="x"),
            FindingItem(file="CLAUDE.md", line=2, severity="warning", rule="CORE:C:0002", message="x"),
            FindingItem(file="CLAUDE.md", line=3, severity="error", rule="CORE:S:0001", message="x"),
        )
        data = format_combined_result(_result(findings=findings))
        sh = data["surface_health"][0]
        breakdown = sh["category_breakdown"]
        assert sum(breakdown.values()) == sh["finding_count"]
        assert breakdown == {"coherence": 2, "structure": 1}

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_breakdown_excludes_bare_token_rule_ids(self) -> None:
        """Bare-token rule ids (issue #31 D) drop out of the breakdown, leaving sum < finding_count."""
        from reporails_cli.core.platform.runtime.merger import FindingItem

        findings = (
            FindingItem(file="CLAUDE.md", line=1, severity="error", rule="CORE:C:0001", message="x"),
            FindingItem(file="CLAUDE.md", line=2, severity="warning", rule="format", message="x"),
        )
        data = format_combined_result(_result(findings=findings))
        sh = data["surface_health"][0]
        assert sh["finding_count"] == 2
        assert sum(sh["category_breakdown"].values()) == 1
        assert sh["category_breakdown"] == {"coherence": 1}
