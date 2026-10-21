"""Unit tests for the Summary block's reading order and vocabulary.

The block answers three questions in order — what is my state (Quality), what
do I do now (Fix now), how big is the rest (Findings) — in one vocabulary
that never contradicts the file cards above it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import pytest
from rich.text import Text

from reporails_cli.core.platform.dto.diagnostics import FindingItem
from reporails_cli.core.platform.dto.models import Level
from reporails_cli.core.platform.runtime.merger import CombinedStats, Omissions, ServerReply
from reporails_cli.formatters.text import item_scorecard, scorecard
from reporails_cli.formatters.text.health import SurfaceHealth
from reporails_cli.formatters.text.scorecard import (
    ScopeInfo,
    ScorecardDetail,
    _render_surface_health,
    _render_verdict_block,
    _surface_cell,
    print_scorecard,
)


@dataclass
class _Quality:
    display_score: float | None = 7.4


@dataclass
class _Hint:
    count: int = 0
    error_count: int = 0
    warning_count: int = 0


@dataclass
class _Result:
    findings: tuple = ()
    stats: CombinedStats = field(default_factory=CombinedStats)
    quality: _Quality | None = None
    hints: tuple = ()
    per_file_analysis: tuple = ()
    reply: ServerReply = field(default_factory=ServerReply)
    omissions: Omissions = field(default_factory=Omissions)
    level: Level = Level.L0


def _f(rule: str, severity: str = "warning", tier: str = "", line: int = 1) -> FindingItem:
    return FindingItem(file="CLAUDE.md", line=line, severity=severity, rule=rule, message="m", impact_tier=tier)


def _result(findings: list[FindingItem], score: float | None = 7.4, hints: tuple = ()) -> _Result:
    stats = CombinedStats(
        total_findings=len(findings),
        errors=sum(1 for f in findings if f.severity == "error"),
        warnings=sum(1 for f in findings if f.severity == "warning"),
        infos=sum(1 for f in findings if f.severity == "info"),
    )
    return _Result(findings=tuple(findings), stats=stats, quality=_Quality(display_score=score), hints=hints)


def _plain(markup: str) -> str:
    return Text.from_markup(markup).plain


def _verdict(result: _Result, **kw: object) -> str:
    with scorecard.console.capture() as cap:
        _render_verdict_block(result, has_quality=True, elapsed_ms=0, **kw)  # type: ignore[arg-type]
    return cap.get()


_MIXED = [
    _f("CORE:C:0042", "error", "gate_mover", line=3),
    _f("CORE:C:0042", "error", "gate_mover", line=9),
    _f("CORE:C:0011", "error", "cosmetic"),
    _f("CORE:C:0044", "warning", "conditional"),
    _f("CORE:E:0004", "warning", "cosmetic"),
    _f("CORE:E:0003", "info", "cosmetic"),
]


class TestFindingsLine:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_leads_with_one_total(self) -> None:
        out = _verdict(_result(_MIXED))
        assert "Findings  6 total" in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_retired_vocabulary_is_gone(self) -> None:
        out = _verdict(_result(_MIXED))
        for word in ("cosmetic", "move your score", "conditional", "by severity", "collapsed", "likely", "maybe"):
            assert word not in out, word

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_verbose_hint_offered_only_when_not_already_verbose(self) -> None:
        assert "-v to list every one" in _verdict(_result(_MIXED))
        assert "-v" not in _verdict(_result(_MIXED), verbose=True)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_large_counts_are_grouped(self) -> None:
        findings = [_f("CORE:E:0004", "warning", "cosmetic", line=i) for i in range(1350)]
        out = _verdict(_result(findings))
        assert "1,350 total" in out


class TestFixNowLine:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_names_error_count_and_the_most_frequent_error_rule(self) -> None:
        out = _verdict(_result(_MIXED))
        assert "Fix now   3 errors. Start with CORE:C:0042 (2 errors)." in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_single_error_rule_carries_no_count(self) -> None:
        out = _verdict(_result([_f("CORE:C:0011", "error", "cosmetic")]))
        assert "Fix now   1 error. Start with CORE:C:0011." in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_omitted_without_listed_errors(self) -> None:
        out = _verdict(_result([_f("CORE:C:0042", "warning", "gate_mover"), _f("CORE:E:0003", "info", "cosmetic")]))
        assert "Fix now" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_free_tier_states_the_gated_error_count(self) -> None:
        out = _verdict(_result(_MIXED), hint_errors=43)
        assert "Fix now   3 errors (43 more in Pro). Start with CORE:C:0042 (2 errors)." in out


class TestFixNowTieBreak:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_equal_counts_start_with_the_stronger_graded_rule(self) -> None:
        out = _verdict(_result([_f("CORE:C:0011", "error", "cosmetic"), _f("CORE:C:0042", "error", "gate_mover")]))
        assert "Start with CORE:C:0042." in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_equal_grades_start_with_the_more_severe_rule(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from reporails_cli.formatters.text import verdict

        monkeypatch.setattr(verdict, "rule_severity", {"CORE:C:0011": "low", "CORE:C:0042": "critical"}.get)
        out = _verdict(_result([_f("CORE:C:0011", "error"), _f("CORE:C:0042", "error")]))
        assert "Start with CORE:C:0042." in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_count_still_leads_the_grade(self) -> None:
        errors = [_f("CORE:C:0011", "error", "cosmetic", line=1), _f("CORE:C:0011", "error", "cosmetic", line=2)]
        out = _verdict(_result([*errors, _f("CORE:C:0042", "error", "gate_mover")]))
        assert "Start with CORE:C:0011 (2 errors)." in out


class TestProLineNumber:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    @pytest.mark.parametrize(
        ("count", "errors", "warnings", "expected"),
        [
            (1, 0, 1, "+ 1 Pro diagnostic (1 warning)"),
            (3, 1, 2, "+ 3 Pro diagnostics (1 error · 2 warnings)"),
        ],
    )
    def test_nouns_agree_with_their_counts(self, count: int, errors: int, warnings: int, expected: str) -> None:
        result = _result([], hints=(_Hint(count=count, error_count=errors, warning_count=warnings),))
        with scorecard.console.capture() as cap:
            scorecard._render_results_summary(result, errors, warnings)
        assert expected in _plain(cap.get())


class TestCaption:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_closing_caption_after_the_findings_line(self) -> None:
        out = _verdict(_result(_MIXED, score=3.4))
        assert "barely moves the score" not in out
        assert "worth fixing" not in out


class TestSurfaceAndItemRows:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_surface_row_reads_findings_then_errors(self) -> None:
        cell = _plain(
            _surface_cell(
                SurfaceHealth(name="Main", score=3.4, file_count=1, finding_count=27, item_count=1, errors=10)
            )
        )
        assert "27 findings · 10 errors" in cell
        for word in ("move", "cosmetic"):
            assert word not in cell, word
        assert re.search(r"\berr\b", cell) is None

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_surface_row_singular_and_error_free(self) -> None:
        one = _plain(
            _surface_cell(SurfaceHealth(name="Main", score=8.0, file_count=1, finding_count=1, item_count=1, errors=1))
        )
        assert "1 finding · 1 error" in one
        clean = _plain(
            _surface_cell(SurfaceHealth(name="Main", score=8.0, file_count=1, finding_count=5, item_count=1))
        )
        assert "5 findings" in clean
        assert "error" not in clean

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_item_row_reads_findings_then_errors_without_parentheses(self) -> None:
        cell = _plain(
            item_scorecard._item_cell(
                SurfaceHealth(name="qa", score=5.4, file_count=1, finding_count=35, item_count=1, errors=2), 8
            )
        )
        assert "35 findings · 2 errors" in cell
        assert "(" not in cell
        assert "cosmetic" not in cell


@pytest.mark.parametrize("width", [80, 100, 140])
class TestFitsTerminal:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_summary_lines_fit_the_terminal(self, monkeypatch: pytest.MonkeyPatch, width: int) -> None:
        """Every Summary line fits; nothing soft-wraps mid-sentence."""
        findings = [_f("CORE:E:0004", "warning", "cosmetic", line=i) for i in range(1215)]
        findings += [_f("CORE:C:0042", "error", "gate_mover", line=i) for i in range(53)]
        findings += [_f("CORE:C:0044", "warning", "conditional", line=i) for i in range(91)]
        result = _result(findings, hints=(_Hint(count=447, error_count=43, warning_count=404),))
        rows = [
            ("Main", 3.4, 1, 27, 10),
            ("Nested", 8.1, 2, 16, 2),
            ("Skills", 7.0, 15, 502, 15),
            ("Agents", 8.0, 14, 707, 14),
            ("Memory", 7.0, 29, 204, 12),
        ]
        surfaces = [
            SurfaceHealth(name=n, score=s, file_count=fc, finding_count=fi, item_count=fc, errors=e)
            for n, s, fc, fi, e in rows
        ]
        monkeypatch.setattr(scorecard, "get_term_width", lambda: width)
        scorecard.console.width = width
        try:
            with scorecard.console.capture() as cap:
                print_scorecard(
                    result,
                    True,
                    tier="free",
                    scope=ScopeInfo(type_str="61 files"),
                    detail=ScorecardDetail(surface_health=surfaces),
                )
        finally:
            scorecard.console.width = None
        lines = cap.get().splitlines()
        assert all(len(ln) <= width for ln in lines), [ln for ln in lines if len(ln) > width]
        labelled = [ln for ln in lines if ln.startswith(("  Quality", "  Fix now", "  Findings"))]
        assert len(labelled) == 3, lines
        # A soft-wrapped sentence leaves an unindented fragment on the next line.
        assert not any(ln and not ln.startswith(" ") for ln in lines), lines

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_surface_rows_pair_only_when_a_pair_fits(self, monkeypatch: pytest.MonkeyPatch, width: int) -> None:
        surfaces = [
            SurfaceHealth(name=n, score=7.0, file_count=15, finding_count=502, item_count=15, errors=15)
            for n in ("Main", "Nested", "Skills", "Agents", "Memory")
        ]
        monkeypatch.setattr(scorecard, "get_term_width", lambda: width)
        scorecard.console.width = width
        try:
            with scorecard.console.capture() as cap:
                _render_surface_health(surfaces)
        finally:
            scorecard.console.width = None
        lines = [ln for ln in cap.get().splitlines() if ln.strip()]
        assert all(len(ln) <= width for ln in lines)
        assert len(lines) == (3 if width >= 130 else 5), lines


class TestExcludedLine:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_names_folders_and_globs_under_quality_in_the_label_column(self) -> None:
        result = _result(_MIXED)
        result.omissions = Omissions(excluded_dirs=("agents", "docs"), excluded_files=("*.generated.md",))
        scorecard.console.width = 200
        try:
            lines = _verdict(result).splitlines()
        finally:
            scorecard.console.width = None
        assert (
            lines[1].rstrip() == "  Excluded  agents/, docs/, *.generated.md — not checked; the score covers the rest"
        )
        assert lines[0].startswith("  Quality")

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_files_only_and_dirs_only(self) -> None:
        only_files = _result(_MIXED)
        only_files.omissions = Omissions(excluded_files=("a.md",))
        assert "Excluded  a.md — not checked" in _verdict(only_files)
        only_dirs = _result(_MIXED)
        only_dirs.omissions = Omissions(excluded_dirs=("agents",))
        assert "Excluded  agents/ — not checked" in _verdict(only_dirs)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_unscored_runs_name_them_without_the_score_clause(self) -> None:
        for quality in (None, _Quality(display_score=None)):
            result = _result(_MIXED)
            result.quality = quality
            result.omissions = Omissions(excluded_dirs=("agents",))
            text = _verdict(result)
            assert "Excluded  agents/ — not checked" in text
            assert "the score covers the rest" not in text

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_absent_when_nothing_was_user_excluded(self) -> None:
        assert "Excluded" not in _verdict(_result(_MIXED))

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_a_long_list_wraps_under_its_value(self) -> None:
        result = _result(_MIXED)
        result.omissions = Omissions(excluded_dirs=tuple(f"folder-number-{n}" for n in range(6)))
        scorecard.console.width = 60
        try:
            lines = _verdict(result).splitlines()
        finally:
            scorecard.console.width = None
        start = next(i for i, ln in enumerate(lines) if ln.startswith("  Excluded"))
        assert lines[start + 1].startswith(" " * 12)


class TestExcludedLineOnEveryTextPath:
    @staticmethod
    def _no_findings(capsys: pytest.CaptureFixture[str], **fields: object) -> str:
        from reporails_cli.core.platform.runtime.merger import CombinedResult
        from reporails_cli.formatters.text import display

        result = CombinedResult(**{"quality": None, **fields})  # type: ignore[arg-type]
        display.print_text_result(result, elapsed_ms=0, ascii_mode=True, verbose=False)
        return capsys.readouterr().out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_findings_run_names_what_was_left_out(self, capsys: pytest.CaptureFixture[str]) -> None:
        out = self._no_findings(
            capsys, omissions=Omissions(excluded_dirs=("docs",), excluded_files=("*.generated.md",))
        )
        assert "No findings." in out
        assert "Excluded  docs/, *.generated.md — not checked" in out
        assert "imported text" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_findings_run_prints_no_score_so_the_line_drops_the_score_clause(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        out = self._no_findings(
            capsys, omissions=Omissions(excluded_dirs=("docs",)), quality=_Quality(display_score=7.4)
        )
        assert "No findings." in out
        assert "Excluded  docs/ — not checked" in out
        assert "the score covers the rest" not in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_findings_run_with_imported_text_counted(self, capsys: pytest.CaptureFixture[str]) -> None:
        out = self._no_findings(capsys, omissions=Omissions(excluded_dirs=("docs",), excluded_imported=True))
        assert "; imported text in checked files still counts" in out

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_findings_run_with_nothing_left_out_has_no_line(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert "Excluded" not in self._no_findings(capsys)

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    @pytest.mark.parametrize(("excluded", "shown"), [((("docs",), ("*.md",)), True), (((), ()), False)])
    def test_emptied_run_prints_the_record_only_when_present(
        self, capsys: pytest.CaptureFixture[str], excluded: tuple, shown: bool
    ) -> None:
        from types import SimpleNamespace

        from reporails_cli.interfaces.cli.check_notices import _print_excluded_record

        _print_excluded_record(SimpleNamespace(render=SimpleNamespace(excluded=excluded)))  # type: ignore[arg-type]
        out = capsys.readouterr().out
        assert ("Excluded  docs/, *.md — not checked" in out) is shown
        assert "score covers" not in out
