"""Unit + acceptance tests for formatters/text/score.py — the shared scorer.

The load-bearing guarantee: the score is gate-distance, driven only by
gate-mover findings, so a severity re-bucket of any non-mover leaves it
unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

import pytest

from reporails_cli.core.platform.adapters.api_client import FileAnalysis, QualityResult
from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem
from reporails_cli.formatters.text.item_scorecard import compute_item_scores
from reporails_cli.formatters.text.score import leverage_basis, score_for
from reporails_cli.formatters.text.scorecard import compute_score, compute_surface_scores


def _finding(rule: str, severity: str = "warning", impact_tier: str = "") -> FindingItem:
    return FindingItem(file="a.md", line=5, severity=severity, rule=rule, message="msg", impact_tier=impact_tier)


class TestScoreFor:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_empty_findings_is_perfect(self) -> None:
        assert score_for("HIGH", [], 100) == 10.0

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_band_dominates_with_no_movers(self) -> None:
        # Only cosmetic + conditional findings → band base stands, no penalty.
        findings = [_finding("CORE:S:0010"), _finding("CORE:E:0003"), _finding("bold", "info")]
        assert score_for("HIGH", findings, 100) == 8.5
        assert score_for("MODERATE", findings, 100) == 5.5
        assert score_for("LOW", findings, 100) == 3.0

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_gate_movers_penalize(self) -> None:
        # Adding gate-movers pulls the score below the band base.
        movers = [_finding("CORE:C:0042") for _ in range(10)]
        scored = score_for("HIGH", movers, 100)
        assert scored < 8.5
        # More movers (same denom) → lower score.
        more = [_finding("CORE:C:0042") for _ in range(20)]
        assert score_for("HIGH", more, 100) < scored

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_offline_path_uses_neutral_base(self) -> None:
        # No band (offline) → neutral base, no movers → base stands.
        assert score_for("", [_finding("CORE:S:0010")], 50) == 6.0

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_live_tier_overrides_rule_table_for_penalty(self) -> None:
        # A rule the table calls cosmetic, but the server tiered gate_mover, penalizes.
        promoted = [_finding("bold", "info", impact_tier="gate_mover") for _ in range(10)]
        assert score_for("HIGH", promoted, 100) < 8.5
        # A table gate-mover the server demoted to cosmetic carries no penalty.
        demoted = [_finding("CORE:C:0042", impact_tier="cosmetic") for _ in range(10)]
        assert score_for("HIGH", demoted, 100) == 8.5


class TestLeverageBasis:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_counts_split_by_tier(self) -> None:
        findings = [
            _finding("CORE:C:0042"),  # gate-mover
            _finding("CORE:E:0003"),  # conditional
            _finding("CORE:S:0010"),  # cosmetic
            _finding("bold", "info"),  # cosmetic
        ]
        assert leverage_basis(findings) == (1, 1, 2)


_MOVERS = ("CORE:C:0042", "CORE:C:0044")
# A mixed bag on one file: two gate-movers kept, the rest re-bucketable non-movers.
_MIXED = (
    _finding("CORE:C:0042", "warning"),  # gate-mover (kept)
    _finding("CORE:C:0044", "error"),  # gate-mover (kept)
    _finding("CORE:S:0010", "error"),  # cosmetic
    _finding("CORE:E:0003", "warning"),  # conditional
    _finding("bold", "warning"),  # cosmetic
    _finding("orphan", "info"),  # cosmetic
)


def _rebucket_non_movers(findings: tuple[FindingItem, ...]) -> list[FindingItem]:
    """Cycle every non-gate-mover finding's severity (error→warning→info→error)."""
    cycle = {"error": "warning", "warning": "info", "info": "error"}
    return [f if f.rule in _MOVERS else replace(f, severity=cycle[f.severity]) for f in findings]


@dataclass
class _FileRecord:
    path: str


@dataclass
class _RulesetMap:
    files: tuple[_FileRecord, ...]


class TestReBucketStability:
    """Acceptance: relabelling every non-gate-mover finding's severity must not
    move ANY of the three scores (whole-project, per-surface, per-file). If it
    does, that surface still leaks the old error/warning binary.

    All findings sit on `CLAUDE.md` (the `main` surface) so a single re-bucket
    exercises every scorer at once.
    """

    def _result(self, findings: tuple[FindingItem, ...] | list[FindingItem]) -> CombinedResult:
        per_file = (FileAnalysis(file="CLAUDE.md", compliance_band="MODERATE", stats={"atoms": 50}),)
        return CombinedResult(
            findings=tuple(replace(f, file="CLAUDE.md") for f in findings),
            per_file_analysis=per_file,
            quality=QualityResult(compliance_band="MODERATE"),
        )

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_whole_project_score_stable_across_non_mover_rebucket(self) -> None:
        before = compute_score(self._result(_MIXED), has_quality=True, n_atoms=50)
        after = compute_score(self._result(_rebucket_non_movers(_MIXED)), has_quality=True, n_atoms=50)
        assert before == after, "whole-project: non-mover re-bucket must not move the score"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_surface_score_stable_across_non_mover_rebucket(self) -> None:
        before = compute_surface_scores(self._result(_MIXED))
        after = compute_surface_scores(self._result(_rebucket_non_movers(_MIXED)))
        assert [s.score for s in before] == [s.score for s in after]
        assert before and before[0].score < 5.5, "expected the gate-movers to penalize the surface base"

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_item_score_stable_across_non_mover_rebucket(self) -> None:
        ruleset = _RulesetMap(files=(_FileRecord(path="CLAUDE.md"),))
        before = compute_item_scores(self._result(_MIXED), ruleset_map=ruleset)
        after = compute_item_scores(self._result(_rebucket_non_movers(_MIXED)), ruleset_map=ruleset)
        assert [it.score for it in before] == [it.score for it in after]
