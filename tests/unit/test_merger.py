"""Tests for core/merger.py — result merging."""

from __future__ import annotations

import pytest

from reporails_cli.core.api_client import (
    CrossFileCoordinate,
    Diagnostic,
    FileAnalysis,
    Hint,
    QualityResult,
    RulesetReport,
)
from reporails_cli.core.merger import merge_results
from reporails_cli.core.models import LocalFinding


@pytest.fixture
def m_findings() -> list[LocalFinding]:
    return [
        LocalFinding("CLAUDE.md", 10, "warning", "CORE:S:0005", "Missing section", source="m_probe"),
        LocalFinding("CLAUDE.md", 20, "error", "CORE:S:0001", "No root file", source="m_probe"),
    ]


@pytest.fixture
def client_findings() -> list[LocalFinding]:
    return [
        LocalFinding("CLAUDE.md", 30, "warning", "ordering", "Constraint before directive", source="client_check"),
    ]


class TestMergeResults:
    def test_offline_returns_all_local(
        self, m_findings: list[LocalFinding], client_findings: list[LocalFinding]
    ) -> None:
        result = merge_results(m_findings, client_findings, None)
        assert result.offline is True
        assert result.quality is None
        assert len(result.findings) == 3
        assert result.stats.m_probe_count == 2
        assert result.stats.client_check_count == 1
        assert result.stats.server_diagnostic_count == 0

    def test_empty_inputs(self) -> None:
        result = merge_results([], [], None)
        assert result.offline is True
        assert len(result.findings) == 0
        assert result.stats.total_findings == 0

    def test_sorting_by_file_severity_line(self, m_findings: list[LocalFinding]) -> None:
        result = merge_results(m_findings, [], None)
        # error should come before warning (both in same file)
        assert result.findings[0].severity == "error"
        assert result.findings[1].severity == "warning"

    def test_stats_counted_correctly(self, m_findings: list[LocalFinding], client_findings: list[LocalFinding]) -> None:
        result = merge_results(m_findings, client_findings, None)
        assert result.stats.errors == 1
        assert result.stats.warnings == 2
        assert result.stats.infos == 0
        assert result.stats.total_findings == 3

    def test_server_deduplicates_matching_local(self) -> None:
        local = [LocalFinding("CLAUDE.md", 10, "warning", "ordering", "local msg", source="client_check")]
        server = RulesetReport(
            per_file=(
                FileAnalysis(
                    file="CLAUDE.md",
                    diagnostics=(Diagnostic("CLAUDE.md", 10, "warning", "ordering", "server msg", "fix"),),
                ),
            ),
            quality=QualityResult(compliance_band="MODERATE"),
        )
        result = merge_results([], local, server)
        assert result.offline is False
        # Server version kept, local deduplicated
        assert len(result.findings) == 1
        assert result.findings[0].source == "server"
        assert result.findings[0].message == "server msg"

    @pytest.mark.parametrize("server_report", [None, RulesetReport()])
    def test_offline_flag(self, server_report: RulesetReport | None) -> None:
        result = merge_results([], [], server_report)
        assert result.offline == (server_report is None)

    def test_hints_pass_through(self) -> None:
        hints = (
            Hint(
                file="CLAUDE.md",
                diagnostic_type="CORE:C:0044",
                count=3,
                summary="3 topics",
                error_count=1,
                warning_count=2,
            ),
            Hint(file="rules.md", diagnostic_type="CORE:C:0047", count=5, summary="5 buried"),
        )
        result = merge_results([], [], RulesetReport(), hints=hints)
        assert len(result.hints) == 2
        assert result.hints[0].count == 3
        assert result.hints[1].diagnostic_type == "CORE:C:0047"

    def test_cross_file_coordinates_pass_through(self) -> None:
        coords = (
            CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="conflict", count=2),
            CrossFileCoordinate(file_1="c.md", file_2="d.md", finding_type="repetition", count=1),
        )
        result = merge_results([], [], RulesetReport(), cross_file_coordinates=coords)
        assert len(result.cross_file_coordinates) == 2
        assert result.cross_file_coordinates[0].finding_type == "conflict"
        assert result.cross_file_coordinates[1].count == 1

    def test_empty_coordinates_and_hints_by_default(self) -> None:
        result = merge_results([], [], None)
        assert result.hints == ()
        assert result.cross_file_coordinates == ()
