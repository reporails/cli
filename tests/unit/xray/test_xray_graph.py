"""The node graph: the tree of agents, what each was handed and handed back, how each ended, and the facts every
node with a spine carries, built from records shaped as the transcript adapter emits them."""

from __future__ import annotations

import json
from collections.abc import Iterator, Sequence
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from reporails_cli.core.platform.contract.json_value import JsonValue, as_list, as_object
from reporails_cli.core.platform.dto.events import (
    EventKind,
    EventRecord,
    HarnessEntry,
    HarnessKind,
    InstructionLoad,
    ReplyText,
    SkillRun,
    SubagentMeta,
    TokenUsage,
    ToolCategory,
    ToolUse,
)
from reporails_cli.core.platform.dto.xray import (
    AdapterVocabulary,
    Graph,
    XrayBurstSettings,
    XrayCheck,
    XrayGaps,
    XrayNodeKindInfo,
    XraySessionInfo,
    XrayVerdict,
    XrayView,
)
from reporails_cli.core.platform.dto.xray_build import (
    Frame,
    NodeProducer,
    Produced,
    ProducedNode,
    ProducedSpine,
    ProducerContext,
    SourceTable,
)
from reporails_cli.core.platform.dto.xray_composition import XrayComposition
from reporails_cli.core.platform.dto.xray_graph import (
    AgentOutcome,
    LoadEvent,
    NodeKind,
    XrayAgentDetail,
    XrayBack,
    XrayCompaction,
    XrayDown,
    XrayEdge,
    XrayNode,
    XrayUsage,
)
from reporails_cli.core.platform.dto.xray_sources import ArtifactFile, ArtifactKind, FindingTally
from reporails_cli.core.xray.artifacts import build_artifacts
from reporails_cli.core.xray.cost import agent_cost, load_price_list
from reporails_cli.core.xray.derive import epoch
from reporails_cli.core.xray.funnel import build_funnel
from reporails_cli.core.xray.graph.agents import MAIN_ID
from reporails_cli.core.xray.graph.build import build_graph
from reporails_cli.core.xray.graph.bursts import bursts
from reporails_cli.core.xray.graph.port import PRODUCERS, register
from reporails_cli.core.xray.graph.sources import build_sources, ran_sources
from reporails_cli.core.xray.vocabulary import vocabulary_for

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

BASE = datetime(2026, 10, 31, 10, 0, 0, tzinfo=UTC)


def at(seconds: float) -> str:
    """The written time `seconds` after the session's first record."""
    return (BASE + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def rec(event: EventKind, seconds: float, sub: str | None = None, **fields: object) -> EventRecord:
    """A record of the session at `seconds`, of the main agent or of subagent `sub`."""
    return EventRecord(agent="claude", event=event, session_id="s", time=at(seconds), subagent_id=sub, **fields)  # type: ignore[arg-type]


def reply(seconds: float, sub: str | None = None, context: int = 1000) -> EventRecord:
    """A reply whose context is `context` tokens."""
    return rec("assistant_usage", seconds, sub, usage=TokenUsage(f"msg-{sub}-{seconds}", 1, 0, context - 1))


def launch(
    seconds: float,
    sub: str,
    parent: str | None,
    use_id: str,
    *,
    description: str | None = "task",
    brief_chars: int | None = 0,
    stopped: bool = False,
    background: bool = False,
) -> EventRecord:
    """The run record of subagent `sub`, launched by the call `use_id` of `parent`."""
    meta = SubagentMeta(description, parent, use_id, None, brief_chars, stopped, background)
    return rec("subagent_run", seconds, sub, subagent_type="general-purpose", item=meta)


def call(
    seconds: float,
    use_id: str,
    category: ToolCategory,
    sub: str | None = None,
    *,
    name: str = "Tool",
    path: str | None = None,
    server: str | None = None,
    chars: int | None = None,
    fingerprint: str | None = None,
) -> EventRecord:
    """A tool call."""
    return rec("tool_call", seconds, sub, tool=ToolUse(name, use_id, path, server, category, chars, fingerprint))


def result(
    seconds: float, use_id: str, sub: str | None = None, chars: int = 0, error: bool = False, *, ack: bool = False
) -> EventRecord:
    """The result of the call `use_id`; `ack` marks one that only acknowledges a background launch."""
    return rec("tool_result", seconds, sub, tool=ToolUse(use_id=use_id, chars=chars, error=error, launch_ack=ack))


def load(
    seconds: float, file: ArtifactFile | Path, sub: str | None = None, memory_type: str = "Project"
) -> EventRecord:
    """An instruction file loaded."""
    path = file if isinstance(file, Path) else Path(file.path)
    return rec("instruction_load", seconds, sub, item=InstructionLoad(str(path), memory_type))


def harness(seconds: float, kind: HarnessKind, label: str, chars: int, sub: str | None = None) -> EventRecord:
    """A piece of the harness's context."""
    return rec("harness", seconds, sub, item=HarnessEntry(kind, label, None, chars))


def _file(root: Path, name: str, size: int, kind: ArtifactKind = "instructions") -> ArtifactFile:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x" * size)
    return ArtifactFile(str(path), kind, "project", None, name, None, None)


def _graph(
    root: Path,
    records: Sequence[EventRecord],
    files: Sequence[ArtifactFile] = (),
    *,
    advertised: dict[str, bool | None] | None = None,
    findings: dict[str, FindingTally] | None = None,
    runnable: dict[str, str] | None = None,
    vocabulary: AdapterVocabulary | None = None,
    agent_files: dict[str, int] | None = None,
    live: bool = False,
) -> Graph:
    frame = Frame(epoch(at(0)) or 0.0, root, findings or {}, runnable or {}, agent_files or {}, live)
    artifacts = build_artifacts(files, findings or {}, root, advertised=advertised or {})
    vocab = vocabulary or vocabulary_for("claude", [])
    return build_graph(list(records), frame, build_sources(artifacts, records, frame), vocab, load_price_list())


def _node(graph: Graph, node_id: str) -> XrayNode:
    return next(node for node in graph.nodes if node.id == node_id)


def _edge(graph: Graph, child: str) -> XrayEdge:
    return next(edge for edge in graph.edges if edge.child == child)


def _agent(node: XrayNode) -> XrayAgentDetail:
    assert isinstance(node.detail, XrayAgentDetail)
    return node.detail


def _tree_records() -> list[EventRecord]:
    """D is launched by main last but its records come first; A launches B, B launches C; D names a parent that is
    no subagent."""
    return [
        launch(20, "D", "ghost", "tuD"),
        reply(21, "D"),
        reply(1),
        call(5, "tuA", "agent"),
        launch(6, "A", None, "tuA"),
        reply(7, "A"),
        call(8, "tuB", "agent", "A"),
        launch(9, "B", "A", "tuB"),
        reply(10, "B"),
        call(11, "tuC", "agent", "B"),
        launch(12, "C", "B", "tuC"),
        reply(13, "C"),
        call(19, "tuD", "agent"),
        reply(30),
    ]


def test_the_agents_form_a_tree_by_the_launching_subagent_and_a_stranger_hangs_under_main(tmp_path: Path) -> None:
    graph = _graph(tmp_path, _tree_records())
    assert [node.id for node in graph.nodes] == ["main", "A", "B", "C", "D"]
    assert {node.id: (node.tree.parent, node.tree.depth) for node in graph.nodes} == {
        "main": (None, 0),
        "A": ("main", 1),
        "B": ("A", 2),
        "C": ("B", 3),
        "D": ("main", 1),
    }
    assert {node.id: node.tree.descendants for node in graph.nodes} == {"main": 4, "A": 2, "B": 1, "C": 0, "D": 0}
    # Children follow launch order, not the order the records were read in.
    assert _node(graph, "main").tree.children == ("A", "D")
    assert _node(graph, "A").tree.children == ("B",)
    assert [(edge.parent, edge.child) for edge in graph.edges] == [("main", "A"), ("A", "B"), ("B", "C"), ("main", "D")]


def test_launchers_that_lead_back_to_each_other_hang_under_main(tmp_path: Path) -> None:
    graph = _graph(tmp_path, [reply(1), launch(5, "A", "B", "t1"), launch(6, "B", "A", "t2")])
    assert {node.id: (node.tree.parent, node.tree.depth) for node in graph.nodes} == {
        "main": (None, 0),
        "A": ("main", 1),
        "B": ("main", 1),
    }


def test_a_node_is_named_by_its_description_else_its_type_and_a_subagent_with_no_run_record_still_has_a_node(
    tmp_path: Path,
) -> None:
    records = [reply(1), launch(5, "A", None, "t1", description=None), reply(6, "A"), reply(7, "ghost")]
    graph = _graph(tmp_path, records)
    assert _node(graph, "A").name == "general-purpose"
    stray = _node(graph, "ghost")
    assert (stray.name, stray.type, stray.tree.parent) == ("ghost", None, "main")
    assert _agent(stray).down.task_tokens_est is None
    assert _node(graph, "main").name == "main agent"


def test_a_subagent_is_handed_its_task_prompt_and_what_it_started_with_and_hands_back_its_message(
    tmp_path: Path,
) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    records = [
        reply(1),
        call(5, "tuA", "agent"),
        launch(6, "A", None, "tuA", brief_chars=1600),
        load(6.5, claude, "A"),
        harness(6.6, "system_prompt", "system prompt", 800, "A"),
        reply(7, "A"),
        call(100, "hb", "handback", "A", name="SubagentHandback", chars=800),
        reply(101, "A"),
        reply(200),
    ]
    graph = _graph(tmp_path, records, [claude])
    detail = _agent(_node(graph, "A"))
    assert detail.down == XrayDown(400, 300)
    assert [(item.label, item.tokens_est, item.source) for item in detail.given] == [
        ("task prompt", 400, None),
        ("CLAUDE.md", 100, "CLAUDE.md"),
        ("system prompt", 200, None),
    ]
    assert detail.back.tokens_est == 200 and detail.outcome == "returned"
    edge = _edge(graph, "A")
    assert (edge.down, edge.back, edge.out_t, edge.back_t, edge.outcome) == (700, 200, 5.0, 100.0, "returned")


def test_a_foreground_subagent_comes_back_with_the_parents_result_when_it_hands_nothing_back(tmp_path: Path) -> None:
    records = [
        reply(1),
        call(5, "tuD", "agent"),
        launch(6, "D", None, "tuD", brief_chars=40),
        reply(7, "D"),
        result(60, "tuD", chars=400),
        reply(61),
    ]
    graph = _graph(tmp_path, records)
    edge = _edge(graph, "D")
    assert (edge.back, edge.back_t, edge.outcome) == (100, 60.0, "returned")
    assert _agent(_node(graph, "D")).back.tokens_est == 100


@pytest.mark.parametrize(
    ("meta", "extra", "end", "expected"),
    [
        ({}, [call(250, "hb", "handback", "X", chars=40)], 300, "returned"),
        ({}, [result(300, "tuX", chars=80)], 300, "returned"),
        ({}, [result(300, "tuX", chars=80, error=True)], 300, "failed"),
        ({"stopped": True}, [], 300, "stopped"),
        ({}, [], 300, "no_handback"),
        ({}, [], 950, "running"),
        ({"background": True}, [result(6, "tuX", chars=10)], 300, "no_handback"),
        ({"background": True}, [result(6, "tuX", chars=10)], 950, "running"),
    ],
)
def test_a_subagent_ends_returned_failed_stopped_running_or_with_no_handback(
    tmp_path: Path, meta: dict[str, bool], extra: list[EventRecord], end: float, expected: str
) -> None:
    records = [
        reply(1),
        call(5, "tuX", "agent"),
        launch(6, "X", None, "tuX", stopped=meta.get("stopped", False), background=meta.get("background", False)),
        reply(7, "X"),
        reply(end, "X"),
        reply(1000),
        *extra,
    ]
    graph = _graph(tmp_path, records, live=end > 900)
    assert _agent(_node(graph, "X")).outcome == expected
    assert _edge(graph, "X").outcome == expected
    assert _agent(_node(graph, "main")).outcome is None


def _text(seconds: float, sub: str, chars: int, *, synthetic: bool = False) -> EventRecord:
    """The text an assistant row of `sub` carries."""
    return rec("assistant_text", seconds, sub, item=ReplyText(chars, synthetic))


@pytest.mark.parametrize(
    ("meta", "tail", "end", "expected", "back", "back_t"),
    [
        # A final text reply is what the subagent returns to its parent.
        ({}, [_text(250, "X", 90)], 250, "returned", 22, 250.0),
        # The reply counts as the last one, not the first text.
        ({}, [_text(200, "X", 400), _text(250, "X", 90)], 250, "returned", 22, 250.0),
        # A last assistant row that is a tool call is no reply.
        ({}, [_text(200, "X", 400), call(250, "t1", "other", "X")], 250, "no_handback", None, None),
        # Text before a call in the same moment still ends on the call.
        ({}, [_text(250, "X", 400), call(250, "t1", "other", "X")], 250, "no_handback", None, None),
        ({"stopped": True}, [_text(250, "X", 90)], 250, "stopped", None, None),
        # Still within the running window of the session's last record.
        ({}, [_text(950, "X", 90)], 950, "running", None, None),
        # A background launch's acknowledgement is not what came back; the reply is.
        ({"background": True}, [result(6, "tuX", chars=10), _text(250, "X", 90)], 250, "returned", 22, 250.0),
        # A foreground result is what the parent got, whatever the subagent's last text was.
        ({}, [result(260, "tuX", chars=80), _text(250, "X", 400)], 250, "returned", 20, 260.0),
    ],
)
def test_a_subagent_that_ends_on_a_text_reply_returns_it_and_one_that_ends_on_a_call_does_not(
    tmp_path: Path,
    meta: dict[str, bool],
    tail: list[EventRecord],
    end: float,
    expected: str,
    back: int | None,
    back_t: float | None,
) -> None:
    records = [
        reply(1),
        call(5, "tuX", "agent"),
        launch(6, "X", None, "tuX", stopped=meta.get("stopped", False), background=meta.get("background", False)),
        reply(7, "X"),
        reply(end, "X"),
        reply(1000),
        *tail,
    ]
    edge = _edge(_graph(tmp_path, records, live=end > 900), "X")
    assert (edge.outcome, edge.back, edge.back_t) == (expected, back, back_t)


def test_close_calls_to_one_mcp_server_make_one_pill_and_a_far_call_another(tmp_path: Path) -> None:
    records = [reply(0), reply(1000)]
    for number, (seconds, size) in enumerate([(100, 400), (150, 800), (200, 1200), (500, 40)]):
        use_id = f"m{number}"
        records += [
            call(seconds, use_id, "mcp", name="mcp__docs__search", server="docs"),
            result(seconds + 1, use_id, chars=size),
        ]
    graph = _graph(tmp_path, records)
    station = next(item for item in graph.stations if item.node == "main")
    assert [(c.server, c.first, c.last, c.calls, c.back_tokens_est) for c in station.mcp] == [
        ("mcp:docs", 100.0, 200.0, 3, 600),
        ("mcp:docs", 500.0, 500.0, 1, 10),
    ]
    assert [(t.tool, t.category, t.calls) for t in _node(graph, "main").tools] == [("mcp__docs__search", "mcp", 4)]
    # The server's results entered the node's context, so the server counts among its sources.
    assert next(source for source in graph.sources if source.id == "mcp:docs").had_by == ("main",)


def test_mcp_calls_to_two_servers_never_share_a_pill(tmp_path: Path) -> None:
    records = [reply(0), reply(1000), call(100, "a", "mcp", server="docs"), call(101, "b", "mcp", server="wiki")]
    station = next(item for item in _graph(tmp_path, records).stations if item.node == "main")
    assert sorted(c.server for c in station.mcp) == ["mcp:docs", "mcp:wiki"]


def _runs(tmp_path: Path, shape: list[tuple[str, bool]]) -> list[tuple[int, str]]:
    """Shell calls in order, each (fingerprint, failed), a read call between each pair."""
    records: list[EventRecord] = [reply(0)]
    seconds = 10.0
    for number, (fingerprint, failed) in enumerate(shape):
        use_id = f"b{number}"
        records += [
            call(seconds, use_id, "run", name="Bash", fingerprint=fingerprint),
            result(seconds + 1, use_id, error=failed),
            call(seconds + 2, f"r{number}", "read", name="Read"),
        ]
        seconds += 10
    track = next(item for item in _graph(tmp_path, records).tracks if item.node == "main")
    return [(run.count, run.call_id) for run in track.failure_runs]


@pytest.mark.parametrize(
    ("shape", "expected"),
    [
        ([("f", True)] * 3, [(3, "b0")]),
        ([("f", True)] * 2, []),
        ([("f", True), ("f", True), ("f", False), ("f", True), ("f", True)], []),
        ([("f", True), ("f", True), ("g", True), ("g", True)], []),
        ([("f", True)] * 3 + [("f", False)] + [("g", True)] * 4, [(3, "b0"), (4, "b4")]),
    ],
)
def test_three_failing_runs_of_one_command_in_a_row_are_a_failure_run(
    tmp_path: Path, shape: list[tuple[str, bool]], expected: list[tuple[int, str]]
) -> None:
    assert _runs(tmp_path, shape) == expected


def test_the_track_lists_every_call_of_every_category_with_their_label_source_and_failure(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 40)
    records = [
        reply(0),
        call(5, "r1", "read", name="Read", path=claude.path),
        call(6, "e1", "edit", name="Edit", path=str(tmp_path / "src" / "x.py")),
        call(7, "b1", "run", name="Bash", fingerprint="f"),
        result(8, "b1", error=True),
        call(9, "m1", "mcp", name="mcp__a__b", server="a"),
        call(10, "o1", "other", name="TodoWrite"),
    ]
    track = next(item for item in _graph(tmp_path, records, [claude]).tracks if item.node == "main")
    assert [(c.t, c.category, c.tool, c.label, c.source, c.server, c.failed, c.use_id) for c in track.calls] == [
        (5.0, "read", "Read", "Read · CLAUDE.md", "CLAUDE.md", None, False, "r1"),
        (6.0, "edit", "Edit", "Edit · src/x.py", None, None, False, "e1"),
        (7.0, "run", "Bash", "Bash", None, None, True, "b1"),
        (9.0, "mcp", "mcp__a__b", "mcp__a__b", None, "mcp:a", False, "m1"),
        (10.0, "other", "TodoWrite", "TodoWrite", None, None, False, "o1"),
    ]


def test_a_call_lasts_from_the_call_to_its_result_and_without_a_result_has_no_duration_or_size(tmp_path: Path) -> None:
    records = [
        reply(0),
        call(10, "r1", "read", name="Read"),
        result(12.5, "r1", chars=400),
        call(20, "r2", "read", name="Read"),
    ]
    track = next(item for item in _graph(tmp_path, records).tracks if item.node == "main")
    done, open_call = track.calls
    assert (done.duration_s, done.result_tokens_est) == (2.5, 100)
    assert (open_call.duration_s, open_call.result_tokens_est) == (None, None)


def test_a_node_counts_its_calls_per_tool_with_the_failed_ones_most_called_first(tmp_path: Path) -> None:
    records = [reply(0)]
    shape = [("Bash", "run", True), ("Read", "read", False), ("Bash", "run", False), ("Edit", "edit", False)]
    shape.append(("Read", "read", False))
    for number, (name, category, failed) in enumerate(shape):
        use_id = f"c{number}"
        records += [call(5 + number, use_id, category, name=name), result(6 + number, use_id, error=failed)]
    node = _node(_graph(tmp_path, records), "main")
    assert [(t.tool, t.category, t.calls, t.failed) for t in node.tools] == [
        ("Bash", "run", 2, 1),
        ("Read", "read", 2, 0),
        ("Edit", "edit", 1, 0),
    ]
    assert as_list(node.to_json()["tools"])[0] == {"tool": "Bash", "category": "run", "calls": 2, "failed": 1}


def test_a_gap_of_half_an_hour_without_a_record_is_a_break(tmp_path: Path) -> None:
    records = [reply(0), reply(100), reply(100 + 1800), reply(2000), reply(2000 + 1799)]
    track = next(item for item in _graph(tmp_path, records).tracks if item.node == "main")
    assert [(b.start, b.end) for b in track.breaks] == [(100.0, 1900.0)]


def test_a_source_is_had_by_the_nodes_whose_context_it_entered_and_a_listed_file_nobody_loaded_is_on_disk(
    tmp_path: Path,
) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    shared = _file(tmp_path, ".claude/rules/shared.md", 80, "rule")
    only_child = _file(tmp_path, "sub/CLAUDE.md", 40)
    never = _file(tmp_path, ".claude/rules/never.md", 40, "rule")
    heard = _file(tmp_path, ".claude/rules/heard.md", 40, "rule")
    records = [
        load(0.1, claude),
        load(0.2, shared),
        reply(1),
        call(5, "tuA", "agent"),
        launch(6, "A", None, "tuA"),
        load(6.1, claude, "A"),
        load(6.2, only_child, "A", "nested"),
        reply(7, "A"),
        load(8, shared, "A"),
        reply(20),
    ]
    graph = _graph(tmp_path, records, [claude, shared, only_child, never, heard], advertised={heard.path: True})
    by_id = {source.id: source for source in graph.sources}
    assert (by_id["CLAUDE.md"].had_by, by_id["CLAUDE.md"].availability) == (("main", "A"), "loaded")
    assert by_id[".claude/rules/shared.md"].had_by == ("main", "A")
    assert by_id["sub/CLAUDE.md"].had_by == ("A",)
    assert (by_id[".claude/rules/never.md"].had_by, by_id[".claude/rules/never.md"].availability) == ((), "on_disk")
    assert (by_id[".claude/rules/heard.md"].had_by, by_id[".claude/rules/heard.md"].availability) == ((), "listed")
    # The node's slots count its distinct sources per kind.
    assert _node(graph, "A").slots["instructions"].count == 2 and _node(graph, "A").slots["rule"].count == 1
    assert _node(graph, "main").slots["mcp"].count == 0


def test_the_findings_of_a_nodes_sources_add_up_in_its_slot(tmp_path: Path) -> None:
    one, two = _file(tmp_path, "CLAUDE.md", 40), _file(tmp_path, "sub/CLAUDE.md", 40)
    tallies = {
        "CLAUDE.md": FindingTally(3, {"error": 1, "warning": 2, "info": 0}),
        "sub/CLAUDE.md": FindingTally(2, {"error": 0, "warning": 2, "info": 0}),
    }
    graph = _graph(tmp_path, [load(0.1, one), load(0.2, two), reply(1)], [one, two], findings=tallies)
    assert _node(graph, "main").slots["instructions"].findings == 5


def test_a_loaded_file_the_listing_lacks_still_shows_as_a_source(tmp_path: Path) -> None:
    stray = tmp_path / "other" / "CLAUDE.md"
    stray.parent.mkdir()
    stray.write_text("y" * 80)
    graph = _graph(tmp_path, [load(0.1, stray), reply(1)])
    (source,) = graph.sources
    assert (source.id, source.kind, source.tokens_est, source.had_by, source.actionable) == (
        "other/CLAUDE.md",
        "instructions",
        20,
        ("main",),
        False,
    )


def test_a_load_says_what_brought_it_and_whether_it_sits_on_the_spine(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    nested = _file(tmp_path, "sub/CLAUDE.md", 40)
    skill = _file(tmp_path, ".claude/skills/demo/SKILL.md", 4000, "skill")
    big = _file(tmp_path, "docs/big.md", 8000)
    mcp = HarnessEntry("mcp_instructions", "MCP server instructions", 1, 800, added=(("docs", 800),))
    hook = HarnessEntry("hook_note", "SessionStart:startup", None, 120, event="SessionStart")
    records = [
        load(0.1, claude),
        rec("harness", 0.3, item=mcp),
        rec("harness", 0.4, item=hook),
        reply(1),
        load(2, nested, memory_type="nested"),
        rec("skill_run", 3, item=SkillRun("demo", False)),
        rec("skill_run", 3.5, item=SkillRun("demo", True)),
        call(4, "r1", "read", name="Read", path=big.path),
        load(5, claude),
    ]
    graph = _graph(tmp_path, records, [claude, nested, skill, big], runnable={"demo": skill.path})
    station = next(item for item in graph.stations if item.node == "main")
    shown = [(x.source, round(x.t or 0, 3), x.trigger, x.event, x.small) for x in station.loads]
    assert shown == [
        ("CLAUDE.md", 0.1, "session_start", None, True),
        ("mcp:docs", 0.3, "session_start", None, True),
        ("hook:SessionStart:startup", 0.4, "hook", "SessionStart", True),
        ("sub/CLAUDE.md", 2.0, "path_match", None, True),
        (".claude/skills/demo/SKILL.md", 3.0, "agent", None, False),
        ("docs/big.md", 4.0, "agent", None, False),
        ("CLAUDE.md", 5.0, "session_start", None, True),
    ]
    sizes = {s.id: s.tokens_est for s in graph.sources if s.kind in {"mcp", "hook"}}
    assert sizes == {"mcp:docs": 200, "hook:SessionStart:startup": 30}


def test_a_compaction_is_a_station_of_the_node_it_ran_in_with_that_nodes_own_context(tmp_path: Path) -> None:
    records = [
        reply(1, context=500),
        call(5, "tuA", "agent"),
        launch(6, "A", None, "tuA"),
        reply(10, "A", context=9000),
        rec("post_compact", 20, "A", source="auto"),
        reply(25, "A", context=1200),
        reply(30, context=700),
    ]
    graph = _graph(tmp_path, records)
    station = next(item for item in graph.stations if item.node == "A")
    assert station.compactions == (XrayCompaction(t=20.0, trigger="auto", before=9000, after=1200),)
    assert next(item for item in graph.stations if item.node == MAIN_ID).compactions == ()
    assert _agent(_node(graph, "A")).peak == 9000


def test_the_sources_the_parent_had_at_a_launch_and_the_child_never_had_are_withheld(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    style = _file(tmp_path, ".claude/rules/style.md", 1200, "rule")
    late = _file(tmp_path, ".claude/rules/late.md", 80, "rule")
    records = [
        load(0.1, claude),
        load(0.2, style),
        reply(1, context=51200),
        call(10, "tuA", "agent"),
        launch(11, "A", None, "tuA"),
        load(11.1, claude, "A"),
        reply(12, "A"),
        load(13, late),
        reply(30, context=60000),
    ]
    graph = _graph(tmp_path, records, [claude, style, late])
    withheld = _node(graph, "A").withheld
    assert withheld is not None
    assert [(item.source, item.tokens_est) for item in withheld.sources] == [(".claude/rules/style.md", 300)]
    assert withheld.conversation_tokens == 0
    assert _node(graph, MAIN_ID).withheld is None


_NO_COST = agent_cost([], load_price_list(), 0.0, (), SourceTable((), Path(), {}, {}))


class _Widget:
    """A producer of a second node kind whose node hangs under an agent."""

    kind = cast(NodeKind, "widget")

    def __init__(self, parent: str, source: str | None = None) -> None:
        self.parent = parent
        self.source = source
        self.producer = NodeProducer(self.kind, self.produce)

    def produce(self, records: Sequence[EventRecord], frame: Frame, context: ProducerContext) -> Produced:
        detail = XrayAgentDetail(
            None,
            None,
            (),
            XrayDown(None, 0),
            XrayBack(None, None),
            None,
            (),
            (),
            False,
            XrayUsage(_NO_COST, XrayComposition((), None)),
            None,
        )
        loads = () if self.source is None else (LoadEvent(self.source, 1.0, None, "agent", None),)
        spine = ProducedSpine((), loads, (), (), (1.0,))
        node = ProducedNode("w1", self.kind, self.parent, "a widget", None, 1.0, 2.0, detail, spine)
        return Produced((node,), (XrayEdge(self.parent, "w1", 0, None, 1.0, None, None),))


@pytest.fixture(name="widget")
def _widget() -> Iterator[_Widget]:
    stub = _Widget("A")
    register(stub.producer)
    yield stub
    PRODUCERS.remove(stub.producer)


def test_a_second_node_kind_hangs_under_an_agent_with_no_change_to_the_builder(tmp_path: Path, widget: _Widget) -> None:
    records = [reply(1), call(5, "tuA", "agent"), launch(6, "A", None, "tuA"), reply(7, "A"), reply(20)]
    graph = _graph(tmp_path, records)
    stub = _node(graph, "w1")
    assert (stub.kind, stub.tree.parent, stub.tree.depth) == ("widget", "A", 2)
    assert _node(graph, "A").tree.children == ("w1",)
    assert _node(graph, "A").tree.descendants == 1 and _node(graph, MAIN_ID).tree.descendants == 2
    # A kind the vocabulary gives no spine gets no station or track.
    assert "w1" not in {item.node for item in graph.stations} | {item.node for item in graph.tracks}
    assert [edge.child for edge in graph.edges] == ["A", "w1"]


def test_a_second_node_kind_with_a_spine_gets_a_station_and_a_track(tmp_path: Path, widget: _Widget) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    widget.source = "CLAUDE.md"
    vocabulary = vocabulary_for("claude", [])
    info = XrayNodeKindInfo(widget.kind, "Widget", False, True)
    wider = replace(vocabulary, node_kinds=(*vocabulary.node_kinds, info))
    records = [reply(1), call(5, "tuA", "agent"), launch(6, "A", None, "tuA"), reply(7, "A"), reply(20)]
    graph = _graph(tmp_path, records, [claude], vocabulary=wider)
    assert [load.source for item in graph.stations if item.node == "w1" for load in item.loads] == ["CLAUDE.md"]
    assert "w1" in {item.node for item in graph.tracks}
    assert next(s for s in graph.sources if s.id == "CLAUDE.md").had_by == ("w1",)
    assert _node(graph, "w1").slots["instructions"].count == 1


def test_a_producer_of_a_kind_already_registered_is_refused(widget: _Widget) -> None:
    with pytest.raises(ValueError, match="widget"):
        register(_Widget("A").producer)
    assert widget.producer in PRODUCERS


def _shape(value: JsonValue) -> JsonValue:
    """The keys a JSON value holds, recursively; a list holds the merge of its elements' keys."""
    if isinstance(value, dict):
        return {key: _shape(item) for key, item in value.items()}
    if isinstance(value, list):
        merged: dict[str, JsonValue] = {}
        for item in value:
            shape = _shape(item)
            if isinstance(shape, dict):
                merged = {**shape, **{key: inner for key, inner in merged.items() if inner is not None}}
        return merged or None
    return None


def _differences(built: JsonValue, sample: JsonValue, path: str) -> list[str]:
    """Where the key structure of `built` and `sample` differ; a null on either side holds no structure to compare,
    and neither does a map keyed by source id."""
    if not isinstance(built, dict) or not isinstance(sample, dict) or path.endswith(".child_sources"):
        return []
    found = [f"{path}.{key}" for key in sorted(built.keys() ^ sample.keys())]
    for key in built.keys() & sample.keys():
        found += _differences(built[key], sample[key], f"{path}.{key}")
    return found


def test_the_built_views_key_structure_matches_the_sample_the_page_is_built_against(tmp_path: Path) -> None:
    sample = json.loads((Path(__file__).resolve().parents[2] / "fixtures" / "xray" / "view_sample.json").read_text())
    claude = _file(tmp_path, "CLAUDE.md", 400)
    records = [
        load(0.1, claude),
        reply(1),
        call(5, "tuA", "agent"),
        launch(6, "A", None, "tuA", brief_chars=40),
        reply(7, "A"),
        call(8, "b1", "run", "A", fingerprint="f"),
        result(9, "b1", "A", error=True),
        reply(20),
    ]
    graph = _graph(tmp_path, records, [claude])
    view = XrayView(
        nodes=graph.nodes,
        edges=graph.edges,
        sources=graph.sources,
        stations=graph.stations,
        tracks=graph.tracks,
        builtin=graph.builtin,
        session_cost=graph.session_cost,
        version=1,
        info=XraySessionInfo("s", "p", at(0), 20.0, "newest"),
        model=None,
        window=None,
        adapter=vocabulary_for("claude", []),
        price_list=load_price_list().info,
        gaps=XrayGaps((), ()),
        verdict=XrayVerdict((), (), XrayCheck("done", None)),
    )
    built = view.to_json()
    assert as_list(built["nodes"])
    assert not _differences(_shape(built), _shape(as_object(sample)), "view")


def test_a_skill_that_ran_is_used_a_forked_one_is_used_but_not_loaded_and_a_command_counts_as_a_skill(
    tmp_path: Path,
) -> None:
    plain = _file(tmp_path, ".claude/skills/plain/SKILL.md", 80, "skill")
    forked = _file(tmp_path, ".claude/skills/forked/SKILL.md", 80, "skill")
    command = _file(tmp_path, ".claude/commands/go.md", 80, "command")
    idle = _file(tmp_path, ".claude/skills/idle/SKILL.md", 80, "skill")
    records = [
        reply(1),
        rec("skill_run", 2, item=SkillRun("plain", False)),
        rec("skill_run", 3, item=SkillRun("forked", True)),
        rec("skill_run", 4, item=SkillRun("go", False)),
    ]
    runnable = {"plain": plain.path, "forked": forked.path, "go": command.path, "idle": idle.path}
    frame = Frame(epoch(at(0)) or 0.0, tmp_path, {}, runnable, {}, False)
    files = [plain, forked, command, idle]
    table = build_sources(build_artifacts(files, {}, tmp_path, advertised={}), records, frame)
    graph = build_graph(records, frame, table, vocabulary_for("claude", []), load_price_list())
    (row,) = build_funnel(table.entries, graph.sources, ["skill"], ran_sources(records, table))
    assert (row.kind, row.on_disk, row.loaded, row.used) == ("skill", 4, 2, 3)


def _hook(label: str, chars: int, event: str) -> HarnessEntry:
    return HarnessEntry("hook_note", label, None, chars, event=event)


def test_a_hook_that_fires_again_and_again_is_one_firing_in_size_and_the_sum_of_what_the_parent_held_at_a_launch(
    tmp_path: Path,
) -> None:
    firing = "UserPromptSubmit:hook"
    records = [reply(0)]
    records += [
        rec("harness", 1 + n, item=_hook(firing, size, "UserPromptSubmit")) for n, size in enumerate((400, 1200, 800))
    ]
    records += [reply(5), call(6, "tuA", "agent"), launch(7, "A", None, "tuA"), reply(8, "A")]
    records += [rec("harness", 20, item=_hook(firing, 400, "UserPromptSubmit")), reply(30)]
    graph = _graph(tmp_path, records)
    source = next(item for item in graph.sources if item.id == f"hook:{firing}")
    assert source.tokens_est == 300
    withheld = _node(graph, "A").withheld
    assert withheld is not None
    assert [(item.source, item.tokens_est) for item in withheld.sources] == [(f"hook:{firing}", 100 + 300 + 200)]


@pytest.mark.parametrize(
    ("kind", "records", "back"),
    [
        ("stopped", [], None),
        ("no_handback", [], None),
        ("returned", [call(250, "hb", "handback", "X", chars=400)], 100),
    ],
)
def test_only_a_returned_or_failed_agent_has_a_size_coming_back_whatever_the_launch_acknowledged(
    tmp_path: Path, kind: str, records: list[EventRecord], back: int | None
) -> None:
    session = [
        reply(1),
        call(5, "tuX", "agent"),
        launch(6, "X", None, "tuX", stopped=kind == "stopped", background=True),
        reply(7, "X"),
        result(8, "tuX", chars=20),
        reply(300, "X"),
        *records,
        reply(1000),
    ]
    graph = _graph(tmp_path, session)
    edge = _edge(graph, "X")
    assert (edge.outcome, edge.back) == (kind, back)
    assert _agent(_node(graph, "X")).back.tokens_est == back
    assert (edge.back_t is None) == (back is None)


def test_an_agent_that_ends_on_a_synthetic_reply_failed_even_when_the_parent_saw_a_result(tmp_path: Path) -> None:
    session = [
        reply(1),
        call(5, "tuX", "agent"),
        launch(6, "X", None, "tuX"),
        reply(7, "X"),
        _text(250, "X", 40, synthetic=True),
        result(251, "tuX", chars=8),
        reply(1000),
    ]
    graph = _graph(tmp_path, session)
    assert _edge(graph, "X").outcome == "failed"
    assert _agent(_node(graph, "X")).outcome == "failed"


def test_a_session_that_is_not_live_leaves_an_agent_with_no_result_as_no_handback_and_a_live_one_running(
    tmp_path: Path,
) -> None:
    session = [
        reply(1),
        call(5, "tuX", "agent"),
        launch(6, "X", None, "tuX"),
        reply(7, "X"),
        call(9, "c", "other", "X"),
    ]
    assert _edge(_graph(tmp_path, session, live=False), "X").outcome == "no_handback"
    assert _edge(_graph(tmp_path, session, live=True), "X").outcome == "running"


def test_a_subagent_with_no_text_in_its_first_row_has_no_task_prompt_and_no_brief(tmp_path: Path) -> None:
    session = [reply(1), call(5, "tuX", "agent"), launch(6, "X", None, "tuX", brief_chars=None), reply(7, "X")]
    detail = _agent(_node(_graph(tmp_path, session), "X"))
    assert detail.brief is False and detail.down.task_tokens_est is None
    assert [item.label for item in detail.given] == []
    assert _agent(
        _node(_graph(tmp_path, [*session[:2], launch(6, "X", None, "tuX", brief_chars=40), session[3]]), "X")
    ).brief


def test_a_custom_agents_definition_file_is_given_to_it_right_after_the_task_prompt(tmp_path: Path) -> None:
    run = launch(6, "X", None, "tuX", brief_chars=400)
    run = EventRecord(**{**run.__dict__, "subagent_type": "reviewer"})
    session = [reply(1), call(5, "tuX", "agent"), run, reply(7, "X")]
    graph = _graph(tmp_path, session, agent_files={"reviewer": 625})
    detail = _agent(_node(graph, "X"))
    assert [(item.label, item.tokens_est, item.source) for item in detail.given] == [
        ("task prompt", 100, None),
        ("reviewer", 625, None),
    ]
    assert detail.down.inherited_tokens_est == 625
    other = _agent(_node(_graph(tmp_path, session, agent_files={"planner": 9}), "X"))
    assert [item.label for item in other.given] == ["task prompt"]


def test_how_many_times_the_peak_is_what_came_back_is_known_only_for_a_returned_agent(tmp_path: Path) -> None:
    session = [
        reply(1),
        call(5, "tuX", "agent"),
        launch(6, "X", None, "tuX"),
        reply(7, "X", context=40_000),
        call(250, "hb", "handback", "X", chars=800),
        reply(1000),
    ]
    detail = _agent(_node(_graph(tmp_path, session), "X"))
    assert (detail.outcome, detail.back.tokens_est, detail.back.ratio) == ("returned", 200, 200)
    failed = _agent(_node(_graph(tmp_path, [*session[:4], result(300, "tuX", chars=800, error=True)]), "X"))
    assert failed.back.ratio is None


def test_a_node_counts_how_many_of_its_children_had_each_source(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    rule = _file(tmp_path, ".claude/rules/r.md", 400, "rule")
    session = [
        reply(1),
        call(5, "t1", "agent"),
        launch(6, "A", None, "t1"),
        load(6.5, claude, "A"),
        reply(7, "A"),
        call(8, "t2", "agent"),
        launch(9, "B", None, "t2"),
        load(9.5, claude, "B"),
        load(9.6, rule, "B"),
        reply(10, "B"),
        reply(20),
    ]
    graph = _graph(tmp_path, session, [claude, rule])
    assert _node(graph, "main").child_sources == {"CLAUDE.md": 2, ".claude/rules/r.md": 1}
    assert _node(graph, "A").child_sources == {}


def _typed_launch(seconds: float, sub: str, parent: str | None, use_id: str, agent_type: str) -> EventRecord:
    return replace(launch(seconds, sub, parent, use_id), subagent_type=agent_type)


def _definition(root: Path, label: str) -> ArtifactFile:
    path = root / ".claude" / "agents" / f"{label}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("x" * 80)
    return ArtifactFile(str(path), "agent", "project", None, label, None, None)


def test_an_agent_definition_is_a_source_had_by_every_launch_of_its_type_at_any_depth(tmp_path: Path) -> None:
    reviewer, never = _definition(tmp_path, "reviewer"), _definition(tmp_path, "never")
    records = [
        reply(1),
        call(5, "tuA", "agent"),
        _typed_launch(6, "A", None, "tuA", "reviewer"),
        reply(7, "A"),
        call(8, "tuB", "agent", "A"),
        _typed_launch(9, "B", "A", "tuB", "reviewer"),
        reply(10, "B"),
        call(11, "tuC", "agent", "B"),
        launch(12, "C", "B", "tuC"),
        reply(13, "C"),
        reply(30),
    ]
    graph = _graph(tmp_path, records, [reviewer, never], advertised={never.path: True})
    by_name = {source.name: source for source in graph.sources if source.kind == "agent" and not source.builtin}
    assert set(by_name) == {"reviewer", "never"}
    assert (by_name["reviewer"].had_by, by_name["reviewer"].launches, by_name["reviewer"].availability) == (
        ("A", "B"),
        2,
        "loaded",
    )
    assert (by_name["never"].had_by, by_name["never"].launches, by_name["never"].availability) == ((), 0, "listed")
    assert all(source.launches is None for source in graph.sources if source.kind != "agent")
    assert all(source.launches == 1 for source in graph.sources if source.builtin)


def test_a_definition_nobody_listed_or_launched_is_on_disk(tmp_path: Path) -> None:
    graph = _graph(tmp_path, [reply(1), reply(30)], [_definition(tmp_path, "idle")])
    (source,) = [item for item in graph.sources if item.kind == "agent"]
    assert (source.availability, source.launches) == ("on_disk", 0)


def test_a_definition_backed_type_is_one_source_and_the_slots_count_definitions(tmp_path: Path) -> None:
    reviewer, helper = _definition(tmp_path, "reviewer"), _definition(tmp_path, "helper")
    records = [
        reply(1),
        call(5, "tuA", "agent"),
        _typed_launch(6, "A", None, "tuA", "reviewer"),
        reply(7, "A"),
        call(8, "tuB", "agent"),
        launch(9, "B", None, "tuB"),
        reply(10, "B"),
        reply(30),
    ]
    tally = {reviewer.path: FindingTally(2, {"error": 0, "warning": 2, "info": 0})}
    graph = _graph(tmp_path, records, [reviewer, helper], findings=tally)
    assert [(s.name, s.builtin) for s in graph.sources if s.kind == "agent" and s.name == "reviewer"] == [
        ("reviewer", False)
    ]
    assert _node(graph, "main").slots["agent"].count == 2
    assert (_node(graph, "A").slots["agent"].count, _node(graph, "A").slots["agent"].findings) == (1, 2)
    assert _node(graph, "B").slots["agent"].count == 0


def _hook_note(seconds: float, label: str, event: str, chars: int) -> EventRecord:
    return rec("harness", seconds, item=HarnessEntry("hook_note", label, None, chars, event=event))


def test_close_loads_of_one_hook_are_one_stretch_and_a_lone_note_stays_a_load(tmp_path: Path) -> None:
    records = [
        reply(0),
        _hook_note(0.5, "SessionStart:startup", "SessionStart", 120),
        _hook_note(100, "PreToolUse:Edit", "PreToolUse", 400),
        _hook_note(110, "PreToolUse:Edit", "PreToolUse", 800),
        _hook_note(120, "PreToolUse:Edit", "PreToolUse", 400),
        reply(1000),
    ]
    graph = _graph(tmp_path, records)
    station = next(item for item in graph.stations if item.node == "main")
    assert [(h.source, h.first, h.last, h.count, h.tokens_est) for h in station.hooks] == [
        ("hook:PreToolUse:Edit", 100.0, 120.0, 3, 400)
    ]
    assert [load.source for load in station.loads] == ["hook:SessionStart:startup"]
    # The hook still counts as a source the node had.
    assert next(item for item in graph.sources if item.id == "hook:PreToolUse:Edit").had_by == ("main",)


def _launches(tmp_path: Path, times: list[float], span: float) -> list[tuple[str, ...]]:
    records: list[EventRecord] = [reply(0)]
    for number, seconds in enumerate(times):
        sub, use_id = f"S{number}", f"tu{number}"
        records += [call(seconds, use_id, "agent"), launch(seconds + 0.1, sub, None, use_id), reply(seconds + 1, sub)]
    records.append(reply(span))
    graph = _graph(tmp_path, records)
    return [burst.members for burst in _node(graph, "main").tree.bursts]


def test_four_launches_within_a_minute_of_a_ten_minute_agent_are_one_burst(tmp_path: Path) -> None:
    assert _launches(tmp_path, [100, 120, 140, 160], 600) == [("S0", "S1", "S2", "S3")]


def test_two_launches_are_never_a_burst(tmp_path: Path) -> None:
    assert _launches(tmp_path, [100, 110], 600) == []


def test_a_launch_past_the_window_starts_a_new_group(tmp_path: Path) -> None:
    assert _launches(tmp_path, [0, 30, 60, 100, 130, 160], 600) == [("S0", "S1", "S2"), ("S3", "S4", "S5")]


def _handoff_edge(
    child: str, out_t: float, back_t: float | None, down: int = 10, outcome: AgentOutcome | None = "returned"
) -> XrayEdge:
    return XrayEdge("p", child, down, None, out_t, back_t, outcome)


def test_the_window_grows_with_a_long_agent_and_a_burst_sums_what_went_down() -> None:
    settings = XrayBurstSettings(window_s=90.0, window_share=0.013, min_size=3)
    edges = [_handoff_edge("a", 0, 50), _handoff_edge("b", 93, 80), _handoff_edge("c", 93.5, 120)]
    assert bursts(edges, 600.0, settings, {}) == ()
    (found,) = bursts(edges, 7200.0, settings, {})
    assert (found.members, found.first_launch, found.last_return, found.down_tokens) == (("a", "b", "c"), 0, 120, 30)
    (open_run,) = bursts(
        [_handoff_edge("a", 0, 5), _handoff_edge("b", 1, None, outcome="running"), _handoff_edge("c", 2, 7)],
        600.0,
        settings,
        {"a": 5, "b": 9, "c": 7},
    )
    assert open_run.last_return is None


def test_a_member_that_did_not_hand_back_ends_the_burst_at_its_own_end() -> None:
    settings = XrayBurstSettings(window_s=90.0, window_share=0.013, min_size=3)
    edges = [
        _handoff_edge("a", 0, 5),
        _handoff_edge("b", 1, None, outcome="stopped"),
        _handoff_edge("c", 2, None, outcome="no_handback"),
    ]
    (found,) = bursts(edges, 600.0, settings, {"a": 5, "b": 40, "c": 30})
    assert found.last_return == 40


def _entry(kind: HarnessKind, label: str, count: int | None, chars: int, seconds: float = 0.5) -> EventRecord:
    return rec("harness", seconds, item=HarnessEntry(kind, label, count, chars))


def test_the_builtin_items_follow_the_vocabulary_order_and_the_system_prompt_carries_the_remainder(
    tmp_path: Path,
) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    records = [
        _entry("session_context", "session context", None, 40),
        _entry("skill_list", "skills", 5, 4000),
        _entry("agent_list", "agents", 3, 400),
        _entry("deferred_tools", "deferred tools", 7, 800),
        load(0.4, claude),
        reply(1, context=20_000),
    ]
    graph = _graph(tmp_path, records, [claude])
    assert [(item.key, item.remainder) for item in graph.builtin] == [
        ("system_prompt", True),
        ("deferred_tools", False),
        ("agent_list", False),
        ("skill_list", False),
        ("session_context", False),
    ]
    sizes = {item.key: item.tokens_est for item in graph.builtin}
    # The reply total less the estimated instruction file (100) and skills listing (1000), the tool definitions
    # (200), the agent listing (100) and the session context (10).
    assert sizes == {
        "system_prompt": 20_000 - 100 - 1000 - 200 - 100 - 10,
        "deferred_tools": 200,
        "agent_list": 100,
        "skill_list": 1000,
        "session_context": 10,
    }
    notes = {item.key: item.note for item in graph.builtin}
    assert notes["agent_list"] == "3 agent descriptions" and notes["session_context"] is not None
    assert [item.visible for item in graph.builtin][:2] == ["hidden", "partial"]


def test_a_system_prompt_is_never_negative_when_the_estimates_overshoot_the_reply(tmp_path: Path) -> None:
    records = [_entry("skill_list", "skills", 5, 40_000), reply(1, context=500)]
    system = next(item for item in _graph(tmp_path, records).builtin if item.remainder)
    assert system.tokens_est == 0


def test_a_launched_built_in_type_is_an_agent_source_and_a_defined_type_is_not_listed_twice(tmp_path: Path) -> None:
    reviewer = _definition(tmp_path, "reviewer")
    records = [
        reply(1),
        call(5, "tuA", "agent"),
        _typed_launch(6, "A", None, "tuA", "Explore"),
        reply(7, "A"),
        call(8, "tuB", "agent"),
        _typed_launch(9, "B", None, "tuB", "Explore"),
        reply(10, "B"),
        call(11, "tuC", "agent"),
        _typed_launch(12, "C", None, "tuC", "reviewer"),
        reply(13, "C"),
        reply(30),
    ]
    graph = _graph(tmp_path, records, [reviewer])
    agents = [source for source in graph.sources if source.kind == "agent"]
    (built_in,) = [source for source in agents if source.builtin]
    assert (built_in.name, built_in.agent_type, built_in.label, built_in.path, built_in.tokens_est) == (
        "Explore",
        "Explore",
        "explore",
        None,
        None,
    )
    assert (built_in.availability, built_in.had_by, built_in.launches) == ("loaded", ("A", "B"), 2)
    assert built_in.id not in {source.id for source in agents if not source.builtin}
    (defined,) = [source for source in agents if not source.builtin]
    assert (defined.agent_type, defined.had_by, defined.builtin) == ("reviewer", ("C",), False)


def test_a_memory_item_is_labelled_without_its_type_prefix_and_the_index_is_told_apart(tmp_path: Path) -> None:
    topic = tmp_path / "feedback_pnpm-only.md"
    index = tmp_path / "MEMORY.md"
    topic.write_text("x")
    index.write_text("x")
    files = [
        ArtifactFile(str(topic), "memory", "auto", None, "pnpm-only", "feedback", True),
        ArtifactFile(str(index), "memory", "auto", None, "MEMORY.md", None, None),
    ]
    memory = [source for source in _graph(tmp_path, [reply(1)], files).sources if source.kind == "memory"]
    assert [(source.label, source.memory_role) for source in memory] == [("pnpm-only", "item"), ("MEMORY.md", "index")]


def test_a_rules_scopes_come_from_its_frontmatter(tmp_path: Path) -> None:
    scoped = tmp_path / ".claude" / "rules" / "py.md"
    scoped.parent.mkdir(parents=True)
    scoped.write_text('---\npaths:\n  - "src/**/*.py"\n  - tests/*.py\n---\n# Python\n')
    plain = tmp_path / ".claude" / "rules" / "all.md"
    plain.write_text("# Everything\n")
    files = [
        ArtifactFile(str(scoped), "rule", "project", None, "py", None, None),
        ArtifactFile(str(plain), "rule", "project", None, "all", None, None),
    ]
    rules = {source.label: source for source in _graph(tmp_path, [reply(1)], files).sources if source.kind == "rule"}
    assert rules["py.md"].scopes == ("src/**/*.py", "tests/*.py")
    assert rules["all.md"].scopes == ()


def test_an_mcp_server_lists_its_tools_with_their_call_counts(tmp_path: Path) -> None:
    records = [
        reply(1),
        call(2, "t1", "mcp", name="mcp__docs__search", server="docs"),
        call(3, "t2", "mcp", name="mcp__docs__fetch", server="docs"),
        call(4, "t3", "mcp", name="mcp__docs__search", server="docs"),
        call(5, "t4", "mcp", name="mcp__other__ping", server="other"),
        reply(30),
    ]
    servers = {source.name: source for source in _graph(tmp_path, records).sources if source.kind == "mcp"}
    assert servers["docs"].tools == (("mcp__docs__search", 2), ("mcp__docs__fetch", 1))
    assert servers["other"].tools == (("mcp__other__ping", 1),)


def _context_session(root: Path) -> tuple[list[EventRecord], list[ArtifactFile]]:
    claude = _file(root, "CLAUDE.md", 400)
    rule = _file(root, ".claude/rules/py.md", 800, "rule")
    records = [
        _entry("skill_list", "skills", 5, 4000),
        _entry("agent_list", "agents", 3, 400),
        load(0.4, claude),
        reply(1, context=30_000),
        load(2, rule, memory_type="nested"),
        _hook_note(3, "PreToolUse:hook", "PreToolUse", 200),
        _hook_note(4, "PreToolUse:hook", "PreToolUse", 200),
        call(5, "tuA", "agent"),
        _typed_launch(6, "A", None, "tuA", "Explore"),
        load(6.1, claude, "A"),
        reply(7, "A", context=9000),
        reply(40, context=60_000),
    ]
    return records, [claude, rule]


def test_in_context_adds_up_to_the_peak_on_every_node_and_orders_the_rows(tmp_path: Path) -> None:
    records, files = _context_session(tmp_path)
    graph = _graph(tmp_path, records, files)
    for node in graph.nodes:
        shown = _agent(node).in_context
        assert shown is not None and not shown.over
        assert shown.total == _agent(node).peak
        assert sum(row.tokens_est for row in shown.rows) == shown.total
    main = _agent(_node(graph, "main")).in_context
    assert main is not None
    assert [(row.key, row.label) for row in main.rows if row.key != "source"] == [
        ("hooks", "PreToolUse:hook"),
        ("builtin", "System prompt, tools and listings"),
        ("rest", "Conversation and tool results"),
    ]
    sources = [(row.label, row.kind, row.reason) for row in main.rows if row.key == "source"]
    assert sources == [
        ("CLAUDE.md", "instructions", "loaded with the session's instructions"),
        ("py.md", "rule", "loaded when a matching file was touched"),
    ]
    hook = next(row for row in main.rows if row.key == "hooks")
    assert (hook.reason, hook.tokens_est) == ("fired 2 times", 100)
    sub = _agent(_node(graph, "A")).in_context
    assert sub is not None
    assert [row.key for row in sub.rows] == ["task", "source", "builtin", "rest"]
    assert sub.rows[1].reason == "handed down at launch"


def test_in_context_marks_an_overshoot_and_leaves_the_last_row_at_zero(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 40_000)
    graph = _graph(tmp_path, [load(0.4, claude), reply(1, context=500)], [claude])
    shown = _agent(_node(graph, "main")).in_context
    assert shown is not None and shown.over and shown.total == 500
    assert shown.rows[-1].key == "rest" and shown.rows[-1].tokens_est == 0


def test_the_vocabulary_words_what_used_means_for_each_source_kind_and_the_price_list_states_its_method() -> None:
    kinds = {item.key: (item.verb, item.graph_label) for item in vocabulary_for("claude", []).source_kinds}
    assert kinds["agent"] == ("launched", "subagents") and kinds["mcp"] == ("connected", "MCP servers")
    assert {verb for verb, _ in kinds.values()} == {"loaded", "launched", "read", "connected", "fired"}
    assert "reply" in load_price_list().info.source_method


@pytest.mark.parametrize(
    ("tail", "back"),
    [
        ([], None),
        ([_text(250, "X", 90)], 22),
    ],
)
def test_a_launch_acknowledgement_is_never_the_size_an_agent_handed_back(
    tmp_path: Path, tail: list[EventRecord], back: int | None
) -> None:
    session = [
        reply(1),
        call(5, "tuX", "agent"),
        launch(6, "X", None, "tuX"),
        reply(7, "X"),
        result(8, "tuX", chars=267, ack=True),
        reply(251, "X"),
        *tail,
        reply(1000),
    ]
    graph = _graph(tmp_path, session)
    detail = _agent(_node(graph, "X"))
    assert detail.back.tokens_est == back
    assert (detail.back.ratio is None) == (back is None)
    assert _edge(graph, "X").back == back


def test_the_vocabulary_flags_which_kinds_count_as_instructions_in_context_and_which_stay_on_the_spine() -> None:
    kinds = vocabulary_for("claude", []).source_kinds
    assert {item.key for item in kinds if item.instructions} == {"instructions", "rule"}
    assert {item.key for item in kinds if item.spine} == {"hook"}
    flagged = {
        item["key"]: (item["instructions"], item["spine"])
        for item in vocabulary_for("claude", []).to_json()["source_kinds"]
    }  # type: ignore[index, union-attr]
    assert flagged["hook"] == (False, True) and flagged["rule"] == (True, False)


def _priced(seconds: float, sub: str | None = None, model: str = "claude-opus-4-8") -> EventRecord:
    """A reply of `model` that cost 0.0075 USD at list price when the model is priced."""
    usage = TokenUsage(f"m-{sub}-{seconds}", 1000, 0, 0, model=model, output_tokens=100)
    return rec("assistant_usage", seconds, sub, usage=usage)


def test_the_session_cost_sums_every_agent_counts_unpriced_replies_and_lists_agents_dearest_first(
    tmp_path: Path,
) -> None:
    records = [
        _priced(1),
        call(5, "tuA", "agent"),
        launch(6, "A", None, "tuA"),
        _priced(7, "A"),
        _priced(8, "A"),
        _priced(9, "A", model="unknown-model"),
        result(10, "tuA", chars=50),
    ]
    graph = _graph(tmp_path, records)
    cost = graph.session_cost
    assert cost.total_usd == pytest.approx(0.0225)
    assert cost.unpriced == 1
    assert [(node, round(usd, 4)) for node, usd in cost.by_agent] == [("A", 0.015), ("main", 0.0075)]
    assert graph.session_cost.to_json() == {
        "total_usd": cost.total_usd,
        "unpriced": 1,
        "by_agent": [["A", cost.by_agent[0][1]], ["main", cost.by_agent[1][1]]],
    }


def test_a_session_with_no_priced_reply_has_no_session_total(tmp_path: Path) -> None:
    graph = _graph(tmp_path, [_priced(1, model="unknown-model")])
    assert (graph.session_cost.total_usd, graph.session_cost.unpriced, graph.session_cost.by_agent) == (None, 1, ())


def test_a_call_whose_time_is_unknown_has_no_duration(tmp_path: Path) -> None:
    broken = replace(call(5, "t1", "read", name="Read"), time="not a time")
    graph = _graph(tmp_path, [reply(1), broken, result(9, "t1", chars=10), reply(20)])
    track = next(item for item in graph.tracks if item.node == "main")
    assert [item.duration_s for item in track.calls] == [None]


def test_the_system_prompt_size_leaves_out_the_mcp_instructions_and_hook_notes_the_context_counts_elsewhere(
    tmp_path: Path,
) -> None:
    mcp = HarnessEntry("mcp_instructions", "MCP server instructions", 1, 800, added=(("docs", 800),))
    records = [
        _entry("deferred_tools", "deferred tools", 3, 400),
        rec("harness", 0.3, item=mcp),
        rec("harness", 0.4, item=HarnessEntry("hook_note", "SessionStart:startup", None, 120, event="SessionStart")),
        reply(1, context=1000),
    ]
    sizes = {item.key: item.tokens_est for item in _graph(tmp_path, records).builtin}
    # The total less the hook note (30, counted as a hook note), the tool definitions (100) and the MCP servers'
    # instructions (200, once).
    assert sizes["system_prompt"] == 1000 - 30 - 100 - 200


def test_a_hook_row_counts_only_the_firings_whose_tokens_the_context_still_holds(tmp_path: Path) -> None:
    firing = "UserPromptSubmit:hook"
    records = [reply(0)]
    records += [rec("harness", 1 + n, item=_hook(firing, 400, "UserPromptSubmit")) for n in range(3)]
    records += [
        reply(4),
        rec("post_compact", 5),
        rec("harness", 6, item=_hook(firing, 400, "UserPromptSubmit")),
    ]
    records += [reply(7, context=5000)]
    shown = _agent(_node(_graph(tmp_path, records), "main")).in_context
    assert shown is not None
    hook = next(row for row in shown.rows if row.key == "hooks")
    assert (hook.reason, hook.tokens_est) == ("fired once", 100)


def test_the_launch_of_a_subagent_says_how_big_its_parents_conversation_was_not_the_whole_context(
    tmp_path: Path,
) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 4000)
    records = [
        load(0.1, claude),
        rec("assistant_text", 0.5, item=ReplyText(800, False)),
        reply(1, context=10_000),
        call(3, "tuA", "agent"),
        launch(4, "A", None, "tuA"),
        reply(5, "A"),
        reply(6, context=10_500),
    ]
    withheld = _node(_graph(tmp_path, records, [claude]), "A").withheld
    assert withheld is not None
    # The conversation (the reply's 800 characters, 200 tokens) at the launch; nothing else the parent held.
    assert withheld.conversation_tokens == 200
    assert "conversation_tokens" in withheld.to_json() and "context_tokens" not in withheld.to_json()


def test_a_session_with_no_instruction_load_records_reads_instruction_files_as_unrecorded_not_as_zero(
    tmp_path: Path,
) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    records = [_priced(1)]
    graph = _graph(tmp_path, records, [claude])
    (source,) = [item for item in graph.sources if item.kind == "instructions"]
    assert source.availability == "unrecorded"
    main = _agent(_node(graph, "main"))
    assert main.usage.cost.instructions_usd_est is None
    session = _graph(tmp_path, [load(0.1, claude), _priced(1)], [claude])
    assert [item.availability for item in session.sources if item.kind == "instructions"] == ["loaded"]
    assert _agent(_node(session, "main")).usage.cost.instructions_usd_est is not None


def test_the_funnel_does_not_count_an_unrecorded_kind_as_zero_loaded(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    records = [_priced(1)]
    frame = Frame(epoch(at(0)) or 0.0, tmp_path, {}, {}, {}, False)
    table = build_sources(build_artifacts([claude], {}, tmp_path, advertised={}), records, frame)
    graph = build_graph(records, frame, table, vocabulary_for("claude", []), load_price_list())
    (row,) = build_funnel(table.entries, graph.sources, ["instructions"], set())
    assert (row.on_disk, row.loaded, row.used) == (1, None, None)


def test_the_agents_funnel_row_counts_the_built_in_agent_types_a_session_launched(tmp_path: Path) -> None:
    definition = _file(tmp_path, ".claude/agents/reviewer.md", 80, "agent")
    records = [reply(1), call(5, "tuA", "agent"), launch(6, "A", None, "tuA"), reply(7, "A"), reply(1000)]
    frame = Frame(epoch(at(0)) or 0.0, tmp_path, {}, {}, {}, False)
    table = build_sources(build_artifacts([definition], {}, tmp_path, advertised={}), records, frame)
    graph = build_graph(records, frame, table, vocabulary_for("claude", []), load_price_list())
    (row,) = build_funnel(table.entries, graph.sources, ["agent"], set())
    assert (row.on_disk, row.loaded) == (2, 1)
