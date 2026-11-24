"""What an agent's context held at a reply: the latest one by default, and any earlier one counted from the
compaction before it, with the files that compaction dropped left out."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.xray_build import Frame, WorkflowReading
from reporails_cli.core.platform.dto.xray_graph import XrayInContext
from reporails_cli.core.xray.artifacts import build_artifacts
from reporails_cli.core.xray.cost import load_price_list
from reporails_cli.core.xray.derive import epoch
from reporails_cli.core.xray.graph.build import context_at
from reporails_cli.core.xray.graph.sources import build_sources
from reporails_cli.core.xray.vocabulary import vocabulary_for
from tests.unit.xray.test_xray_composition import _attached, _files
from tests.unit.xray.test_xray_graph import _agent, _graph, _hook_note, _node, at, call, launch, load, rec, reply

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

DROPPED, KEPT = "r.md", "CLAUDE.md"


def _long(root: Path) -> list[EventRecord]:
    """Two files loaded and a reply of 10000 tokens, a compaction that restores only CLAUDE.md, and two replies."""
    claude, rule, _ = _files(root)
    return [
        load(0.1, claude),
        load(0.2, rule),
        reply(1, context=10000),
        call(1.1, "before", "read"),
        rec("post_compact", 2, source="auto"),
        *_attached(2.5, claude),
        reply(3, context=4000),
        call(3.1, "after", "read"),
        reply(4, context=4500),
    ]


def _at(root: Path, records: Sequence[EventRecord], moment: float, agent: str = "main") -> XrayInContext | None:
    frame = Frame(epoch(at(0)) or 0.0, root, {}, {}, {}, False)
    artifacts = build_artifacts(RunContext(), _files(root), {}, root, advertised={})
    return context_at(
        list(records),
        frame,
        build_sources(RunContext(), artifacts, records, frame),
        vocabulary_for("claude", []),
        load_price_list(),
        workflows=WorkflowReading(()),
        agent=agent,
        at=moment,
    )


def _listed(ic: XrayInContext | None) -> set[str]:
    assert ic is not None
    return {row.label for row in ic.rows if row.key == "source"}


def test_the_agents_in_context_is_its_latest_reply_counted_from_the_last_compaction(tmp_path: Path) -> None:
    shown = _agent(_node(_graph(tmp_path, _long(tmp_path), _files(tmp_path)), "main")).in_context
    assert shown is not None and shown.latest and shown.t == 4
    assert shown.total == 4500
    assert _listed(shown) == {KEPT}


def test_a_reply_before_the_compaction_lists_what_was_loaded_by_it_and_its_own_total(tmp_path: Path) -> None:
    earlier = _at(tmp_path, _long(tmp_path), 1.0)
    assert earlier is not None and not earlier.latest and earlier.t == 1
    assert earlier.total == 10000
    assert _listed(earlier) == {DROPPED, KEPT}


def test_a_moment_between_replies_takes_the_last_reply_at_or_before_it(tmp_path: Path) -> None:
    records = _long(tmp_path)
    during = _at(tmp_path, records, 3.1)
    assert during is not None and during.t == 3 and not during.latest
    assert during.total == 4000
    assert _listed(during) == {KEPT}
    assert _at(tmp_path, records, 9) == _agent(_node(_graph(tmp_path, records, _files(tmp_path)), "main")).in_context


def test_a_call_after_a_compaction_leaves_out_the_file_it_dropped_and_a_call_before_it_lists_it(tmp_path: Path) -> None:
    records = _long(tmp_path)
    assert DROPPED in _listed(_at(tmp_path, records, 1.1))
    assert DROPPED not in _listed(_at(tmp_path, records, 3.1))


def test_a_moment_before_the_first_reply_and_an_unknown_agent_hold_no_context(tmp_path: Path) -> None:
    assert _at(tmp_path, _long(tmp_path), 0.5) is None
    assert _at(tmp_path, _long(tmp_path), 1.0, agent="nobody") is None


def test_a_subagent_is_counted_by_its_own_replies(tmp_path: Path) -> None:
    records = [reply(1), call(2, "tuA", "agent"), launch(3, "A", None, "tuA"), reply(4, "A", 2000), reply(6, "A", 3000)]
    ic = _at(tmp_path, records, 5, agent="A")
    assert ic is not None and ic.total == 2000 and not ic.latest


def _rows(ic: XrayInContext | None) -> dict[str, tuple[float | None, str]]:
    assert ic is not None
    return {row.label: (row.t, row.reason) for row in ic.rows if row.key == "source"}


def _reloaded(root: Path) -> list[EventRecord]:
    """Both files loaded at the start, a compaction that drops both, and the dropped one loaded again."""
    claude, rule, _ = _files(root)
    return [
        load(0.1, claude),
        load(0.2, rule),
        reply(1, context=10000),
        rec("post_compact", 2, source="auto"),
        *_attached(2.5, claude),
        load(2.6, rule, memory_type="nested"),
        reply(3, context=4000),
        reply(4, context=4500),
    ]


def test_a_row_reports_the_load_since_the_last_compaction_before_the_reply(tmp_path: Path) -> None:
    records = _reloaded(tmp_path)
    before, after = _rows(_at(tmp_path, records, 1.0)), _rows(_at(tmp_path, records, 3.1))
    assert before[DROPPED][0] == pytest.approx(0.2)
    assert after[DROPPED][0] == pytest.approx(2.6)
    assert after[DROPPED][1] != before[DROPPED][1]
    assert after[KEPT][0] == pytest.approx(2.5)
    assert after[KEPT][1] != before[KEPT][1]


def test_the_latest_list_reports_the_same_loads_as_the_list_at_that_reply(tmp_path: Path) -> None:
    records = _reloaded(tmp_path)
    latest = _agent(_node(_graph(tmp_path, records, _files(tmp_path)), "main")).in_context
    assert _rows(latest) == _rows(_at(tmp_path, records, 4.0))
    assert _rows(latest)[DROPPED][0] == pytest.approx(2.6)


def test_a_source_says_why_in_the_wording_of_the_rows_and_a_dropped_hook_in_the_wording_of_its_firings(
    tmp_path: Path,
) -> None:
    claude, rule, _ = _files(tmp_path)
    records = [
        _hook_note(0.5, "SessionStart:startup", "SessionStart", 120),
        _hook_note(0.6, "SessionStart:startup", "SessionStart", 120),
        load(0.1, claude),
        reply(1, context=10000),
        rec("post_compact", 2, source="auto"),
        *_attached(2.5, claude),
        reply(3, context=4000),
    ]
    graph = _graph(tmp_path, records, [claude, rule])
    latest = _agent(_node(graph, "main")).in_context
    assert latest is not None
    why = {source.label: source.why for source in graph.sources}
    assert why[KEPT] == _rows(latest)[KEPT][1]
    assert why["SessionStart:startup"] == "fired 2 times"
    assert why[DROPPED] is None
