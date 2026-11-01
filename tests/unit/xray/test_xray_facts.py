"""The headline facts of a session view: each kind fires on a session that shows it and not on one that does not."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.xray import FindingTally, SourceEntry, XrayFact, XraySource, XrayTarget
from reporails_cli.core.xray.facts import build_facts
from tests.unit.xray.test_xray_session import _project, _session, _tally, _view

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]


def _facts(tmp_path: Path, version: str, findings: dict[str, FindingTally] | None = None) -> tuple[XrayFact, ...]:
    return _view(_session(tmp_path, version, _project(tmp_path)), findings).verdict.facts


def _of(facts: tuple[XrayFact, ...], kind: str) -> list[XrayFact]:
    return [fact for fact in facts if fact.kind == kind]


def test_kind_absent_names_each_source_kind_of_the_adapter_with_no_source_at_all(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.308", _project(tmp_path)))
    present = {source.kind for source in view.sources}
    kinds = [item.key for item in view.adapter.source_kinds]
    absent = _of(view.verdict.facts, "kind_absent")
    assert [fact.artifact_kind for fact in absent] == [kind for kind in kinds if kind not in present]
    assert {"rule", "mcp", "hook"} <= {fact.artifact_kind for fact in absent}
    assert all(fact.numbers == () and fact.target == XrayTarget("kind", str(fact.artifact_kind)) for fact in absent)


def _memory(path: str, linked: bool | None) -> SourceEntry:
    return SourceEntry(path, "memory", path, path, 5, None, False, None, linked)


def test_memory_unlinked_counts_unlinked_memory_files_and_points_at_the_first_by_path() -> None:
    entries = (_memory("m/b.md", False), _memory("m/a.md", False), _memory("m/c.md", True), _memory("m/d.md", None))
    (fact,) = _of(build_facts(entries, (), (), ()), "memory_unlinked")
    assert fact.kind == "memory_unlinked" and fact.artifact_kind == "memory"
    assert dict(fact.numbers) == {"count": 2} and fact.target == XrayTarget("path", "m/a.md")


def test_no_memory_unlinked_when_every_memory_file_is_linked_or_unknown() -> None:
    entries = (_memory("m/c.md", True), _memory("m/d.md", None))
    assert not _of(build_facts(entries, (), (), ()), "memory_unlinked")


def _source(path: str, tokens: int | None, had_by: tuple[str, ...]) -> XraySource:
    return XraySource(path, "instructions", path, path, tokens, None, "loaded", had_by, False)


def test_repeated_instructions_point_at_the_file_with_the_largest_extra() -> None:
    sources = (
        _source("a.md", 10, ("main", "x")),
        _source("b.md", 100, ("main", "x", "y")),
        _source("c.md", 500, ("main",)),
        _source("d.md", None, ("main", "x")),
    )
    (fact,) = _of(build_facts((), sources, (), ()), "repeated_instructions")
    assert dict(fact.numbers) == {"files": 3, "contexts": 3, "tokens_est": 10 + 200}
    assert fact.target == XrayTarget("path", "b.md")


def test_an_mcp_server_in_two_contexts_is_not_a_repeated_instruction_file() -> None:
    server = XraySource("mcp:n0", "mcp", "n0", None, 40, None, "loaded", ("main", "x"), False)
    assert not _of(build_facts((), (server,), (), ()), "repeated_instructions")


def test_no_repeated_instructions_when_no_file_entered_two_contexts(tmp_path: Path) -> None:
    assert not _of(_facts(tmp_path, "2.1.309-compactions"), "repeated_instructions")


def test_a_view_carries_only_the_fact_kinds_the_page_annotates(tmp_path: Path) -> None:
    findings = {"CLAUDE.md": _tally(3), "sub/CLAUDE.md": FindingTally(3, {"error": 2, "warning": 1, "info": 0})}
    for version in ("2.1.309-compactions", "2.1.310-listing"):
        root = tmp_path / version
        facts = _view(_session(root, version, _project(root)), findings).to_json()["facts"]
        assert isinstance(facts, list)
        kinds = {fact["kind"] for fact in facts if isinstance(fact, dict)}
        assert kinds <= {"memory_unlinked", "repeated_instructions", "kind_absent"}
        assert "kind_absent" in kinds
