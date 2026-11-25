"""Where the x-ray view puts loads, groups, calls and launches in the segments a compaction cuts an agent's context
into, and which loads it draws as one group."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.events import EventRecord
from reporails_cli.core.platform.dto.xray import Graph
from reporails_cli.core.platform.dto.xray_graph import XrayStation
from reporails_cli.core.platform.dto.xray_sources import ArtifactFile
from reporails_cli.core.xray.graph.agents import MAIN_ID
from tests.unit.xray.test_xray_graph import _file, _graph, _node, call, launch, load, rec, reply

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]


def _main_station(tmp_path: Path, records: list[EventRecord], files: list[ArtifactFile]) -> tuple[XrayStation, Graph]:
    graph = _graph(tmp_path, records, files)
    return next(item for item in graph.stations if item.node == MAIN_ID), graph


@pytest.mark.parametrize(("gap", "grouped"), [(6, True), (20, True), (30, True), (31, False)])
def test_loads_each_within_thirty_seconds_of_the_last_are_one_group_whatever_the_agents_span(
    gap: int, grouped: bool, tmp_path: Path
) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    times = [1, 1 + gap, 1 + 2 * gap]
    records = [reply(0), *[load(t, claude) for t in times], reply(times[-1] + 1)]
    station, _ = _main_station(tmp_path, records, [claude])
    if grouped:
        (group,) = station.groups
        assert (group.count, group.hook, [f.source for f in group.files]) == (3, None, ["CLAUDE.md"])
        assert station.loads == ()
    else:
        assert station.groups == () and len(station.loads) == 3


def test_a_session_start_load_just_before_a_compaction_is_in_the_segment_after_it_and_a_group_never_spans_two(
    tmp_path: Path,
) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    big = _file(tmp_path, "docs/big.md", 8000)
    records = [
        reply(1),
        load(2, claude),
        call(99, "r1", "read", name="Read", path=big.path),
        load(98, claude),
        load(99.5, claude),
        rec("post_compact", 100, source="auto"),
        call(101, "r2", "read", name="Read", path=big.path),
        reply(102),
    ]
    station, _ = _main_station(tmp_path, sorted(records, key=lambda r: r.time), [claude, big])
    (group,) = station.groups
    assert (group.segment, group.count, group.files[0].source) == (1, 2, "CLAUDE.md")
    assert [(x.source, x.segment) for x in station.loads] == [
        ("CLAUDE.md", 0),
        ("docs/big.md", 0),
        ("docs/big.md", 1),
    ]


def test_a_group_keeps_its_id_while_later_loads_join_it(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    first = [reply(0), load(1, claude), load(3, claude), reply(10)]
    second = [reply(0), load(1, claude), load(3, claude), load(6, claude), reply(10)]
    (one,) = _main_station(tmp_path, first, [claude])[0].groups
    (two,) = _main_station(tmp_path, second, [claude])[0].groups
    assert (one.count, two.count) == (2, 3) and one.id == two.id


def test_a_launch_and_a_call_are_in_the_segment_of_the_agent_that_made_them(tmp_path: Path) -> None:
    records = [
        reply(1),
        call(50, "tu1", "agent"),
        launch(51, "A", None, "tu1"),
        reply(52, "A"),
        rec("post_compact", 100, source="auto"),
        call(120, "tu2", "agent"),
        launch(121, "B", None, "tu2"),
        reply(122, "B"),
        call(130, "r1", "read", name="Read"),
        reply(200),
    ]
    graph = _graph(tmp_path, records)
    assert (_node(graph, "A").tree.segment, _node(graph, "B").tree.segment, _node(graph, MAIN_ID).tree.segment) == (
        0,
        1,
        0,
    )
    track = next(item for item in graph.tracks if item.node == MAIN_ID)
    assert {c.use_id: c.segment for c in track.calls} == {"tu1": 0, "tu2": 1, "r1": 1}
