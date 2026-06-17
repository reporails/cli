"""Renderer-contract tests for the CLI score path.

The score is the api's verdict. The CLI is a pure renderer: every displayed score
(whole-project, per-surface, per-file) is an api scalar returned verbatim. These
tests pin that contract — the CLI computes no score of its own, so a CLI-side
severity re-bucket cannot move any displayed number.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from reporails_cli.core.platform.adapters.api_client import FileAnalysis, QualityResult
from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem
from reporails_cli.formatters.text.item_scorecard import compute_item_scores
from reporails_cli.formatters.text.score import leverage_basis, score_color
from reporails_cli.formatters.text.scorecard import compute_score, compute_surface_scores


def _finding(rule: str, severity: str = "warning", impact_tier: str = "") -> FindingItem:
    return FindingItem(file="CLAUDE.md", line=5, severity=severity, rule=rule, message="msg", impact_tier=impact_tier)


@dataclass
class _FileRecord:
    path: str


@dataclass
class _RulesetMap:
    files: tuple[_FileRecord, ...]


class TestScoreColor:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    @pytest.mark.parametrize(
        ("score", "color"),
        [(10.0, "green"), (7.0, "green"), (6.9, "yellow"), (4.0, "yellow"), (3.9, "red"), (0.0, "red")],
    )
    def test_thresholds(self, score: float, color: str) -> None:
        assert score_color(score) == color


class TestComputeScore:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_returns_api_display_score_verbatim(self) -> None:
        result = CombinedResult(quality=QualityResult(compliance_band="HIGH", display_score=7.3))
        assert compute_score(result, has_quality=True) == 7.3

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_offline_is_zero(self) -> None:
        # No server quality → no api scalar to render.
        assert compute_score(CombinedResult(quality=None), has_quality=False) == 0.0


class TestSurfaceAndItemScores:
    """Surface = mean of per-file display scores; item = the file's display score."""

    def _result(self, *files: tuple[str, float]) -> CombinedResult:
        per_file = tuple(FileAnalysis(file=fp, compliance_band="HIGH", display_score=ds) for fp, ds in files)
        return CombinedResult(per_file_analysis=per_file, quality=QualityResult(compliance_band="HIGH"))

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_surface_score_is_mean_of_per_file_display_scores(self) -> None:
        result = self._result(("CLAUDE.md", 8.0), ("AGENTS.md", 6.0))
        surfaces = compute_surface_scores(result)
        main = next(s for s in surfaces if s.name == "Main")
        assert main.score == 7.0  # mean(8.0, 6.0)

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_item_score_is_file_display_score_verbatim(self) -> None:
        result = self._result(("CLAUDE.md", 8.4))
        ruleset = _RulesetMap(files=(_FileRecord(path="CLAUDE.md"),))
        items = compute_item_scores(result, ruleset_map=ruleset)
        assert [it.score for it in items] == [8.4]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_absolute_server_path_still_lands_on_main_surface(self) -> None:
        # Server per-file paths are absolute; the main surface keys on root-level
        # depth, so without normalization an absolute CLAUDE.md falls out of `main`
        # and the surface reads 0.0. Guard the normalization.
        result = CombinedResult(
            per_file_analysis=(FileAnalysis(file="/proj/CLAUDE.md", compliance_band="HIGH", display_score=9.0),),
            quality=QualityResult(compliance_band="HIGH"),
        )
        surfaces = compute_surface_scores(result, project_root="/proj")
        main = next(s for s in surfaces if s.name == "Main")
        assert main.score == 9.0


_MIXED = (
    _finding("CORE:C:0042", "warning", impact_tier="gate_mover"),
    _finding("CORE:C:0044", "error", impact_tier="gate_mover"),
    _finding("CORE:S:0010", "error"),
    _finding("CORE:E:0003", "warning", impact_tier="conditional"),
    _finding("bold", "warning"),
    _finding("orphan", "info"),
)


def _rebucket(findings: tuple[FindingItem, ...]) -> list[FindingItem]:
    """Cycle every finding's severity (error→warning→info→error)."""
    cycle = {"error": "warning", "warning": "info", "info": "error"}
    return [replace(f, severity=cycle[f.severity]) for f in findings]


class TestReBucketStability:
    """A CLI-side severity re-bucket must not move ANY displayed score — they are
    all api scalars, independent of how the CLI buckets a finding's severity.
    """

    def _result(self, findings: tuple[FindingItem, ...] | list[FindingItem]) -> CombinedResult:
        per_file = (FileAnalysis(file="CLAUDE.md", compliance_band="HIGH", display_score=7.7),)
        return CombinedResult(
            findings=tuple(findings),
            per_file_analysis=per_file,
            quality=QualityResult(compliance_band="HIGH", display_score=7.7),
        )

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_whole_project_score_stable(self) -> None:
        before = compute_score(self._result(_MIXED), has_quality=True)
        after = compute_score(self._result(_rebucket(_MIXED)), has_quality=True)
        assert before == after == 7.7

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_surface_score_stable(self) -> None:
        before = compute_surface_scores(self._result(_MIXED))
        after = compute_surface_scores(self._result(_rebucket(_MIXED)))
        assert [s.score for s in before] == [s.score for s in after]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_item_score_stable(self) -> None:
        ruleset = _RulesetMap(files=(_FileRecord(path="CLAUDE.md"),))
        before = compute_item_scores(self._result(_MIXED), ruleset_map=ruleset)
        after = compute_item_scores(self._result(_rebucket(_MIXED)), ruleset_map=ruleset)
        assert [it.score for it in before] == [it.score for it in after]


class TestUnscoredFiles:
    """A file with no charged atoms arrives with display_score=None — rendered as
    'not scored', excluded from surface/item aggregation (REQ-199 item 2).
    """

    def _result(self, *files: tuple[str, float | None]) -> CombinedResult:
        per_file = tuple(FileAnalysis(file=fp, compliance_band="LOW", display_score=ds) for fp, ds in files)
        return CombinedResult(per_file_analysis=per_file, quality=QualityResult(compliance_band="LOW"))

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_item_score_is_none_for_unscored_file(self) -> None:
        result = self._result(("/proj/.cursorignore", None))
        ruleset = _RulesetMap(files=(_FileRecord(path="/proj/.cursorignore"),))
        items = compute_item_scores(result, ruleset_map=ruleset, project_root="/proj")
        assert [it.score for it in items] == [None]

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_unscored_excluded_from_surface_mean(self) -> None:
        # One scored 8.0 + one unscored on the main surface → mean is 8.0, not dragged.
        result = self._result(("CLAUDE.md", 8.0), ("AGENTS.md", None))
        main = next(s for s in compute_surface_scores(result) if s.name == "Main")
        assert main.score == 8.0

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_item_cell_renders_not_scored(self) -> None:
        from reporails_cli.formatters.text.item_scorecard import _item_cell
        from reporails_cli.formatters.text.scorecard import SurfaceHealth

        cell = _item_cell(SurfaceHealth(name="cursorignore", score=None, file_count=1, finding_count=0), label_w=14)
        assert "not scored" in cell


class TestLeverageBasis:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_counts_split_by_tier(self) -> None:
        findings = [
            _finding("CORE:C:0042", impact_tier="gate_mover"),
            _finding("CORE:E:0003", impact_tier="conditional"),
            _finding("CORE:S:0010"),
            _finding("bold", "info"),
        ]
        assert leverage_basis(findings) == (1, 1, 2)
