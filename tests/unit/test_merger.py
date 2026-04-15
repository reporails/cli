"""Tests for core/merger.py — result merging."""

from __future__ import annotations

import pytest

from reporails_cli.core.api_client import (
    Diagnostic,
    FileAnalysis,
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
