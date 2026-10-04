"""Tests for core/merger.py — result merging."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.dto.diagnostics import (
    CrossFileCoordinate,
    CrossFileFinding,
    Diagnostic,
    FileAnalysis,
    Hint,
    QualityResult,
    RulesetReport,
)
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.runtime.merger import collapse_same_secret, merge_results, overlapping_pairs


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
    @pytest.mark.unit
    @pytest.mark.subsys_lint
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

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_empty_inputs(self) -> None:
        result = merge_results([], [], None)
        assert result.offline is True
        assert len(result.findings) == 0
        assert result.stats.total_findings == 0

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_sorting_by_file_severity_line(self, m_findings: list[LocalFinding]) -> None:
        result = merge_results(m_findings, [], None)
        # error should come before warning (both in same file)
        assert result.findings[0].severity == "error"
        assert result.findings[1].severity == "warning"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_stats_counted_correctly(self, m_findings: list[LocalFinding], client_findings: list[LocalFinding]) -> None:
        result = merge_results(m_findings, client_findings, None)
        assert result.stats.errors == 1
        assert result.stats.warnings == 2
        assert result.stats.infos == 0
        assert result.stats.total_findings == 3

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_server_deduplicates_matching_local(self) -> None:
        local = [LocalFinding("CLAUDE.md", 10, "warning", "ordering", "local msg", source="client_check")]
        server = RulesetReport(
            per_file=(
                FileAnalysis(
                    file="CLAUDE.md",
                    diagnostics=(Diagnostic("CLAUDE.md", 10, "warning", "ordering", "server msg", "fix"),),
                ),
            ),
            quality=QualityResult(),
        )
        result = merge_results([], local, server)
        assert result.offline is False
        # Server version kept, local deduplicated
        assert len(result.findings) == 1
        assert result.findings[0].source == "server"
        assert result.findings[0].message == "server msg"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_the_local_heading_check_gives_way_to_the_server_finding_on_the_same_heading(self) -> None:
        # The local heading check and the server report one finding per heading under one rule;
        # a heading gets one. A local finding sharing only the rule id with a different server
        # finding on its line (backticks vs bold, both `CORE:E:0003`) stays.
        heading = LocalFinding("CLAUDE.md", 5, "warning", "CORE:S:0039", "local heading", source="content_query")
        code = LocalFinding("CLAUDE.md", 7, "warning", "format", "use backticks", source="client_check")
        server = RulesetReport(
            per_file=(
                FileAnalysis(
                    file="CLAUDE.md",
                    diagnostics=(
                        Diagnostic("CLAUDE.md", 5, "warning", "CORE:S:0039", "server heading", "Move it"),
                        Diagnostic("CLAUDE.md", 7, "warning", "CORE:E:0003", "bold on a prohibition", "Italics"),
                    ),
                ),
            ),
            quality=QualityResult(),
        )
        result = merge_results([], [heading, code], server)
        assert sorted((f.line, f.message) for f in result.findings) == [
            (5, "server heading"),
            (7, "bold on a prohibition"),
            (7, "use backticks"),
        ]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_offline_every_heading_finding_is_kept_with_the_same_rule(self) -> None:
        first = LocalFinding("CLAUDE.md", 3, "warning", "CORE:S:0039", "heading A", source="content_query")
        other = LocalFinding("CLAUDE.md", 9, "warning", "CORE:S:0039", "heading B", source="content_query")
        result = merge_results([], [first, other], None)
        assert sorted((f.line, f.rule, f.severity) for f in result.findings) == [
            (3, "CORE:S:0039", "warning"),
            (9, "CORE:S:0039", "warning"),
        ]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_identical_server_findings_on_one_line_count_once(self) -> None:
        # Two vague instructions on one line: the server flags each, and the two findings read the same.
        vague = Diagnostic("CLAUDE.md", 17, "warning", "CORE:C:0042", "Vague instruction", "Name it")
        brief = Diagnostic("CLAUDE.md", 17, "warning", "CORE:E:0004", "Too brief (4 words)", "Expand it")
        server = RulesetReport(
            per_file=(FileAnalysis(file="CLAUDE.md", diagnostics=(vague, vague, brief)),),
            quality=QualityResult(),
        )
        result = merge_results([], [], server)
        assert [(f.line, f.rule) for f in result.findings] == [(17, "CORE:C:0042"), (17, "CORE:E:0004")]
        assert result.stats.total_findings == 2
        assert result.stats.server_diagnostic_count == 2

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_same_rule_on_one_line_with_different_text_stays_separate(self) -> None:
        # Two overlap findings on one line name two different partner files: two facts.
        a = Diagnostic("CLAUDE.md", 5, "warning", "CORE:C:0044", "overlaps with a.md", "Keep it here")
        b = Diagnostic("CLAUDE.md", 5, "warning", "CORE:C:0044", "overlaps with b.md", "Keep it here")
        server = RulesetReport(per_file=(FileAnalysis(file="CLAUDE.md", diagnostics=(a, b)),))
        assert len(merge_results([], [], server).findings) == 2

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("server_report", [None, RulesetReport()])
    def test_offline_flag(self, server_report: RulesetReport | None) -> None:
        result = merge_results([], [], server_report)
        assert result.offline == (server_report is None)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_hints_pass_through(self) -> None:
        hints = (
            Hint(
                file="CLAUDE.md",
                diagnostic_type="CORE:C:0044",
                count=3,
                error_count=1,
                warning_count=2,
            ),
            Hint(file="rules.md", diagnostic_type="CORE:C:0047", count=5),
        )
        result = merge_results([], [], RulesetReport(), hints=hints)
        assert len(result.hints) == 2
        assert result.hints[0].count == 3
        assert result.hints[1].diagnostic_type == "CORE:C:0047"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_cross_file_paths_are_project_relative_like_the_findings(self, tmp_path) -> None:
        # The server reports pairs in the map's absolute coordinates; the merged result names
        # files the way its findings do, so an agent reads one path per file.
        a, b = str(tmp_path / ".claude/skills/x/SKILL.md"), str(tmp_path / "tests/CLAUDE.md")
        server = RulesetReport(cross_file=(CrossFileFinding(a, b, 3, 5, "overlap"),))
        coords = (CrossFileCoordinate(file_1=a, file_2=b, finding_type="repetition", count=2),)
        result = merge_results([], [], server, cross_file_coordinates=coords, project_root=tmp_path)
        assert (result.cross_file[0].file_1, result.cross_file[0].file_2) == (
            ".claude/skills/x/SKILL.md",
            "tests/CLAUDE.md",
        )
        assert (result.cross_file_coordinates[0].file_1, result.cross_file_coordinates[0].file_2) == (
            ".claude/skills/x/SKILL.md",
            "tests/CLAUDE.md",
        )

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_cross_file_coordinates_retires_conflict_leg(self) -> None:
        # "conflict" cross-file coordinates are dropped at the
        # merge_results boundary,
        # so only "repetition" survives into the result.
        coords = (
            CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="conflict", count=2),
            CrossFileCoordinate(file_1="c.md", file_2="d.md", finding_type="repetition", count=1),
        )
        result = merge_results([], [], RulesetReport(), cross_file_coordinates=coords)
        assert len(result.cross_file_coordinates) == 1
        assert result.cross_file_coordinates[0].finding_type == "repetition"
        assert result.cross_file_coordinates[0].count == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_cross_file_findings_retires_conflict_leg(self) -> None:
        # Same for the detailed findings: server_report.cross_file carries
        # both types; only "repetition" survives into the result and the stats.
        findings = (
            CrossFileFinding(file_1="a.md", file_2="b.md", line_1=1, line_2=2, finding_type="conflict"),
            CrossFileFinding(file_1="c.md", file_2="d.md", line_1=3, line_2=4, finding_type="repetition"),
        )
        result = merge_results([], [], RulesetReport(cross_file=findings))
        assert len(result.cross_file) == 1
        assert result.cross_file[0].finding_type == "repetition"
        assert result.stats.cross_file_repetitions == 1
        assert not hasattr(result.stats, "cross_file_conflicts")

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_stats_count_repetitions_from_coordinates_when_detail_absent(self) -> None:
        # Aggregated form only (file pair + type + count, no lines): the count
        # still has to land in `stats`, so the text scorecard and the JSON
        # envelope report one number.
        coords = (
            CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="repetition", count=3),
            CrossFileCoordinate(file_1="a.md", file_2="c.md", finding_type="repetition", count=2),
        )
        result = merge_results([], [], RulesetReport(), cross_file_coordinates=coords)
        assert result.cross_file == ()
        assert result.stats.cross_file_repetitions == 5

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_detailed_cross_file_list_wins_over_coordinates(self) -> None:
        # When both forms are present the detailed rows are authoritative —
        # the aggregate must not be added on top of them.
        findings = (CrossFileFinding(file_1="a.md", file_2="b.md", line_1=1, line_2=2, finding_type="repetition"),)
        coords = (CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="repetition", count=7),)
        result = merge_results([], [], RulesetReport(cross_file=findings), cross_file_coordinates=coords)
        assert result.stats.cross_file_repetitions == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_stats_count_overlapping_file_pairs_not_rows(self) -> None:
        # One overlap row per shared instruction; the stat counts distinct file
        # pairs, whichever way round a row names them. Overlap rows pass the
        # conflict filter and never inflate the repetition count.
        def _row(f1: str, f2: str, ln: int, kind: str = "overlap") -> CrossFileFinding:
            return CrossFileFinding(file_1=f1, file_2=f2, line_1=ln, line_2=ln, finding_type=kind)

        findings = (
            _row("a.md", "b.md", 1),
            _row("a.md", "b.md", 2),
            _row("b.md", "a.md", 3),
            _row("c.md", "d.md", 4),
            _row("a.md", "b.md", 9, "repetition"),
        )
        result = merge_results([], [], RulesetReport(cross_file=findings))
        assert len(result.cross_file) == 5
        assert result.stats.cross_file_overlaps == 2
        assert result.stats.cross_file_repetitions == 1
        assert overlapping_pairs(result.cross_file) == [("a.md", "b.md"), ("c.md", "d.md")]  # most shared first

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_stats_count_overlapping_pairs_from_coordinates_when_detail_absent(self) -> None:
        coords = (
            CrossFileCoordinate(file_1="c.md", file_2="d.md", finding_type="overlap", count=1),
            CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="overlap", count=4),
            CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="repetition", count=2),
        )
        result = merge_results([], [], RulesetReport(), cross_file_coordinates=coords)
        assert result.stats.cross_file_overlaps == 2
        assert overlapping_pairs((), result.cross_file_coordinates) == [("a.md", "b.md"), ("c.md", "d.md")]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_each_type_falls_back_to_coordinates_on_its_own(self) -> None:
        # Detailed rows that carry only repetitions must not hide overlaps that
        # arrived as coordinates, and vice versa.
        rows = (CrossFileFinding(file_1="a.md", file_2="b.md", line_1=1, line_2=2, finding_type="repetition"),)
        coords = (
            CrossFileCoordinate(file_1="c.md", file_2="d.md", finding_type="overlap", count=3),
            CrossFileCoordinate(file_1="a.md", file_2="b.md", finding_type="repetition", count=7),
        )
        result = merge_results([], [], RulesetReport(cross_file=rows), cross_file_coordinates=coords)
        assert result.stats.cross_file_overlaps == 1
        assert result.stats.cross_file_repetitions == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_empty_coordinates_and_hints_by_default(self) -> None:
        result = merge_results([], [], None)
        assert result.hints == ()
        assert result.cross_file_coordinates == ()


class TestSameSecretDedup:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_one_secret_flagged_by_two_rules_counts_once(self) -> None:
        """A credential in a subagent file trips the generic and the subagent
        rule on one line; the user should see one finding, not two."""
        secret = 'api_key = "sk-live-abc123"'
        findings = [
            LocalFinding(
                ".claude/agents/helper.md",
                3,
                "warning",
                "CORE:G:0002",
                "Credential detected",
                source="m_probe",
                signature=secret,
            ),
            LocalFinding(
                ".claude/agents/helper.md",
                3,
                "error",
                "CORE:G:0009",
                "Credential in subagent definition",
                source="m_probe",
                signature=secret,
            ),
        ]
        result = collapse_same_secret(merge_results(findings, [], None))
        assert result.stats.total_findings == 1
        # The higher-severity, subagent-scoped finding is the one kept.
        kept = result.findings[0]
        assert kept.rule == "CORE:G:0009"
        assert kept.severity == "error"
        # The dropped duplicate is the same secret, so it is not counted as a second detection.
        assert result.stats.m_probe_count == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_equal_severity_keeps_the_subagent_finding(self) -> None:
        """When both credential findings carry the same severity, the subagent rule's
        finding is the one reported, whichever arrived first."""
        secret = 'api_key = "sk-live-abc123"'
        findings = [
            LocalFinding(".claude/agents/helper.md", 3, "error", "CORE:G:0002", "Credential", signature=secret),
            LocalFinding(".claude/agents/helper.md", 3, "error", "CORE:G:0009", "Credential", signature=secret),
        ]
        result = collapse_same_secret(merge_results(findings, [], None))
        assert [f.rule for f in result.findings] == ["CORE:G:0009"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_two_distinct_matches_on_one_line_both_survive(self) -> None:
        """The two credential rules matching different secrets on the same line are
        distinct detections and must both be reported."""
        findings = [
            LocalFinding("CLAUDE.md", 5, "warning", "CORE:G:0002", "Credential", source="m_probe", signature="key-a"),
            LocalFinding("CLAUDE.md", 5, "error", "CORE:G:0009", "Credential", source="m_probe", signature="key-b"),
        ]
        result = collapse_same_secret(merge_results(findings, [], None))
        assert result.stats.total_findings == 2

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_findings_without_a_signature_are_never_collapsed(self) -> None:
        """Credential findings with no matched text are not known to be the same
        secret, so two of them on one line are both reported."""
        findings = [
            LocalFinding("CLAUDE.md", 7, "warning", "CORE:G:0002", "Credential", source="m_probe"),
            LocalFinding("CLAUDE.md", 7, "error", "CORE:G:0009", "Credential", source="m_probe"),
        ]
        result = collapse_same_secret(merge_results(findings, [], None))
        assert result.stats.total_findings == 2
