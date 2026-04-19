"""Tests for formatters/json.py — JSON output format."""

from __future__ import annotations

from reporails_cli.core.api_client import CrossFileCoordinate, Hint
from reporails_cli.core.merger import CombinedResult, CombinedStats
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

    def test_no_pro_section_without_hints(self) -> None:
        data = format_combined_result(_result())
        assert "pro" not in data


class TestCrossFileCoordinatesSection:
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

    def test_no_coordinates_section_when_empty(self) -> None:
        data = format_combined_result(_result())
        assert "cross_file_coordinates" not in data
