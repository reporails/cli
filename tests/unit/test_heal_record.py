"""Which healed files the comparison names: a score that fell a display step, findings that came back."""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.record import regressions
from reporails_cli.core.platform.dto.heal import HealedFile

pytestmark = [pytest.mark.unit, pytest.mark.subsys_heal]


def _healed(score: float | None, **rules: int) -> HealedFile:
    return HealedFile(score, rules, "2026-01-01T00:00:00+00:00")


def test_a_score_that_fell_a_display_step_is_named_with_both_scores() -> None:
    found = regressions({"A.md": _healed(8.4)}, {"A.md": 7.9}, {})

    assert [(r.file, r.score_before, r.score_after, r.rules) for r in found] == [("A.md", 8.4, 7.9, {})]


def test_a_drop_below_the_display_step_and_a_steady_file_stay_quiet() -> None:
    record = {"A.md": _healed(8.44, **{"R:1": 2}), "B.md": _healed(5.0)}

    assert regressions(record, {"A.md": 8.4, "B.md": 6.0}, {"A.md": {"R:1": 2}}) == ()


def test_findings_that_came_back_are_named_with_their_increase() -> None:
    found = regressions({"A.md": _healed(None, **{"R:1": 1, "R:2": 3})}, {}, {"A.md": {"R:1": 3, "R:2": 2, "R:3": 1}})

    assert found[0].rules == {"R:1": 2, "R:3": 1}


def test_a_file_the_run_does_not_mention_is_skipped() -> None:
    assert regressions({"gone.md": _healed(9.0)}, {"other.md": 1.0}, {"other.md": {"R:1": 4}}) == ()
