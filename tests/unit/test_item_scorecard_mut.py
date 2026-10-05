"""Mutation-killing tests for formatters.text.item_scorecard.

Each test reddens when a specific injected operator bug returns (verified by
scripts/mutation_probe.py). See test_score.py for the renderer-contract suite.
item_scorecard has its own module-level `console`; the render tests patch THAT
to capture output.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

import pytest
from rich.console import Console

import reporails_cli.formatters.text.item_scorecard as isc
from reporails_cli.core.platform.dto.diagnostics import FileAnalysis, QualityResult
from reporails_cli.core.platform.runtime.merger import CombinedResult, FindingItem
from reporails_cli.formatters.text.item_scorecard import (
    _display_name_for_path,
    compute_item_scores,
)
from reporails_cli.formatters.text.scorecard import SurfaceHealth, _count_tag


@dataclass
class _FileRecord:
    path: str
    skill: str = ""


@dataclass
class _RulesetMap:
    files: tuple[_FileRecord, ...]


def _finding(severity: str) -> FindingItem:
    return FindingItem(file="CLAUDE.md", line=1, severity=severity, rule="CORE:S:0010", message="m")


# ── Severity counting (L58, L59, L60) ────────────────────────────────


class TestSeverityCounts:
    """Per-item error/warning/info counts come from `== <severity>` filters."""

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_counts_are_per_severity_equality(self) -> None:
        # 1 error, 2 warnings, 4 infos — every count differs from its
        # complement, so `== -> !=` on any line changes the reported count.
        findings = (
            _finding("error"),
            _finding("warning"),
            _finding("warning"),
            _finding("info"),
            _finding("info"),
            _finding("info"),
            _finding("info"),
        )
        result = CombinedResult(
            findings=findings,
            per_file_analysis=(FileAnalysis(file="CLAUDE.md", display_score=5.0, stats={"atoms": 1}),),
            quality=QualityResult(),
        )
        ruleset = _RulesetMap(files=(_FileRecord(path="CLAUDE.md"),))
        item = compute_item_scores(result, ruleset_map=ruleset)[0]

        assert item.errors == 1  # kills L58 == -> !=
        assert item.warnings == 2  # kills L59 == -> !=
        assert item.infos == 4  # kills L60 == -> !=


# ── Item ordering (L82) ──────────────────────────────────────────────


class TestItemOrdering:
    """Worst-first with unscored last, alphabetical tiebreak."""

    def _result(self, *files: tuple[str, float | None]) -> CombinedResult:
        per_file = tuple(FileAnalysis(file=fp, display_score=ds, stats={"atoms": 1}) for fp, ds in files)
        return CombinedResult(per_file_analysis=per_file, quality=QualityResult())

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_unscored_sorts_last(self) -> None:
        # Kills L82 `is -> is not`: `is None` puts scored (False) before
        # unscored (True); `is not None` would flip unscored to the front.
        result = self._result(("scored.md", 5.0), ("blank.md", None))
        ruleset = _RulesetMap(files=(_FileRecord(path="scored.md"), _FileRecord(path="blank.md")))
        items = compute_item_scores(result, ruleset_map=ruleset)

        assert items[0].score == 5.0
        assert items[-1].score is None

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_worst_score_first_not_alphabetical(self) -> None:
        # Kills L82 `or -> and`: `score or 0.0` keeps the score; `score and 0.0`
        # collapses every scored key to 0.0, so ordering would fall back to name.
        # The lower score owns the alphabetically-later name so the two orderings
        # diverge.
        result = self._result(("zzz.md", 2.0), ("aaa.md", 8.0))
        ruleset = _RulesetMap(files=(_FileRecord(path="zzz.md"), _FileRecord(path="aaa.md")))
        items = compute_item_scores(result, ruleset_map=ruleset)

        assert items[0].score == 2.0  # worst first; name-sort would put 8.0 (aaa) first


# ── Display-name derivation (L94) ────────────────────────────────────


class TestDisplayName:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_skill_uses_parent_dir_others_use_stem(self) -> None:
        # Kills L94 `== -> !=`: SKILL.md must resolve to its parent dir name,
        # everything else to its file stem.
        assert _display_name_for_path(".claude/skills/foo/SKILL.md") == "foo"
        assert _display_name_for_path("rules/git.md") == "git"


# ── Breakdown gate (L120) ────────────────────────────────────────────


class TestBreakdownGate:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_breakdown_present_only_with_findings(self) -> None:
        # Kills `== -> !=`: findings==0 returns ""; findings>0 renders the
        # `N findings` tag. The mutant inverts both.
        with_findings = SurfaceHealth(name="x", score=5.0, file_count=1, finding_count=3, item_count=1)
        without = SurfaceHealth(name="x", score=5.0, file_count=1, finding_count=0, item_count=1)

        assert "3 findings" in _count_tag(with_findings)
        assert _count_tag(without) == ""


# ── Band separation in render (L148, L149) ───────────────────────────


def _render(monkeypatch: pytest.MonkeyPatch, items: list[SurfaceHealth]) -> list[str]:
    sio = io.StringIO()
    monkeypatch.setattr(isc, "console", Console(file=sio, width=200, no_color=True, force_terminal=False))
    isc.render_item_health(items)
    return sio.getvalue().split("\n")


def _blank_between(lines: list[str], a: str, b: str) -> bool:
    i1 = next(i for i, ln in enumerate(lines) if a in ln)
    i2 = next(i for i, ln in enumerate(lines) if b in ln)
    return any(lines[k].strip() == "" for k in range(i1 + 1, i2))


class TestBandSeparation:
    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_blank_line_between_different_bands(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Kills L148 `is -> is not` (both scored items would collapse to one
        # "unscored" band, dropping the separator) and L149 `!= -> ==` (blank
        # would print on same-band, not on a band change).
        items = [
            SurfaceHealth(name="alpha", score=2.0, file_count=1, finding_count=0, item_count=1),  # red
            SurfaceHealth(name="beta", score=8.0, file_count=1, finding_count=0, item_count=1),  # green
        ]
        lines = _render(monkeypatch, items)
        assert _blank_between(lines, "alpha", "beta")

    @pytest.mark.unit
    @pytest.mark.subsys_cli_ux
    def test_no_blank_line_within_same_band(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Kills L149 `and -> or`: `or` inserts a spurious separator between two
        # items that share a band (and before the first item).
        items = [
            SurfaceHealth(name="alpha", score=8.0, file_count=1, finding_count=0, item_count=1),  # green
            SurfaceHealth(name="beta", score=9.0, file_count=1, finding_count=0, item_count=1),  # green
        ]
        lines = _render(monkeypatch, items)
        assert not _blank_between(lines, "alpha", "beta")
