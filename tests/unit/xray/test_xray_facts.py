"""The headline facts of a session view: each kind fires on a session that shows it and not on one that does not."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.xray import FindingTally, XrayArtifact, XrayFact, XrayTarget
from reporails_cli.core.xray.facts import build_facts
from tests.unit.xray.test_xray_session import _project, _session, _tally, _view

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]


def _facts(tmp_path: Path, version: str, findings: dict[str, FindingTally] | None = None) -> tuple[XrayFact, ...]:
    return _view(_session(tmp_path, version, _project(tmp_path)), findings).verdict.facts


def _of(facts: tuple[XrayFact, ...], kind: str) -> list[XrayFact]:
    return [fact for fact in facts if fact.kind == kind]


def test_file_findings_total_the_tallies_and_point_at_the_file_with_the_most(tmp_path: Path) -> None:
    errors = FindingTally(3, {"error": 2, "warning": 1, "info": 0})
    tallies = {"CLAUDE.md": _tally(3), "sub/CLAUDE.md": errors, ".claude/agents/helper.md": _tally(0)}
    (fact,) = _of(_facts(tmp_path, "2.1.308", tallies), "file_findings")
    assert dict(fact.numbers) == {"findings": 6, "files": 2, "errors": 2}
    assert fact.target == XrayTarget("path", "sub/CLAUDE.md")


def test_file_findings_are_absent_when_every_tally_is_zero_or_none_is_given(tmp_path: Path) -> None:
    assert not _of(_facts(tmp_path, "2.1.308", {"CLAUDE.md": _tally(0)}), "file_findings")
    assert not _of(_facts(tmp_path / "b", "2.1.308"), "file_findings")


def test_compaction_loss_is_one_fact_per_compaction_with_its_turn(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.309-compactions", _project(tmp_path)))
    known = [c for c in view.compactions if c.before is not None and c.after is not None]
    losses = _of(view.verdict.facts, "compaction_loss")
    assert len(known) == len(losses) >= 1
    for compaction, fact in zip(known, losses, strict=True):
        assert compaction.before is not None and compaction.after is not None
        lost = compaction.before - compaction.after
        assert dict(fact.numbers) == {"before": compaction.before, "after": compaction.after, "lost": lost}
        assert fact.target == XrayTarget("turn", compaction.turn)


def test_no_compaction_loss_without_a_compaction(tmp_path: Path) -> None:
    assert not _of(_facts(tmp_path, "2.1.308"), "compaction_loss")


def test_funnel_drop_names_the_kind_whose_used_count_is_below_its_base(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.310-listing", _project(tmp_path)))
    rows = {row.kind: row for row in view.verdict.funnel}
    drops = {fact.artifact_kind: fact for fact in _of(view.verdict.facts, "funnel_drop")}
    for kind, row in rows.items():
        base = row.on_disk if row.advertised is None else row.advertised
        assert (kind in drops) == (row.used is not None and row.used < base)
    assert drops
    for kind, fact in drops.items():
        assert fact.target == XrayTarget("kind", str(kind))
        assert dict(fact.numbers)["used"] == rows[kind].used
        assert ("advertised" in dict(fact.numbers)) == (rows[kind].advertised is not None)


def test_kind_absent_names_each_kind_with_nothing_on_disk(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.308", _project(tmp_path)))
    present = {row.kind for row in view.verdict.funnel}
    absent = _of(view.verdict.facts, "kind_absent")
    assert absent and not any(fact.artifact_kind in present for fact in absent)
    assert {fact.artifact_kind for fact in absent} >= {"rule", "memory"} - present
    assert all(fact.numbers == () and fact.target == XrayTarget("kind", str(fact.artifact_kind)) for fact in absent)


def _memory(path: str, linked: bool | None) -> XrayArtifact:
    return XrayArtifact(path, "memory", "auto", None, path, "user", linked, False, (), None, False, 5, None, 0, None)


def test_memory_unlinked_counts_unlinked_memory_files_and_points_at_the_first_by_path() -> None:
    artifacts = (_memory("m/b.md", False), _memory("m/a.md", False), _memory("m/c.md", True), _memory("m/d.md", None))
    (fact,) = _of(build_facts(artifacts, (), ()), "memory_unlinked")
    assert fact.kind == "memory_unlinked" and fact.artifact_kind == "memory"
    assert dict(fact.numbers) == {"count": 2} and fact.target == XrayTarget("path", "m/a.md")


def test_no_memory_unlinked_when_every_memory_file_is_linked_or_unknown() -> None:
    assert not _of(build_facts((_memory("m/c.md", True), _memory("m/d.md", None)), (), ()), "memory_unlinked")


def test_repeated_instructions_point_at_the_file_with_the_largest_extra(tmp_path: Path) -> None:
    (fact,) = _of(_facts(tmp_path, "2.1.308"), "repeated_instructions")
    assert dict(fact.numbers) == {"files": 2, "contexts": 2, "tokens_est": 33}
    assert fact.target == XrayTarget("path", "CLAUDE.md")


def test_no_repeated_instructions_when_no_file_entered_two_contexts(tmp_path: Path) -> None:
    assert not _of(_facts(tmp_path, "2.1.309-compactions"), "repeated_instructions")


def test_a_fact_serialises_to_kind_artifact_kind_numbers_and_target(tmp_path: Path) -> None:
    facts = json.loads(json.dumps(_view(_session(tmp_path, "2.1.310-listing", _project(tmp_path))).to_json()))["facts"]
    drop = next(fact for fact in facts if fact["kind"] == "funnel_drop")
    assert drop == {
        "kind": "funnel_drop",
        "artifact_kind": "skill",
        "numbers": {"on_disk": 1, "advertised": 1, "loaded": 0, "used": 0},
        "target": {"kind": "kind", "value": "skill"},
    }
