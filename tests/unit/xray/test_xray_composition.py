"""What each reply's context is made of: an exact total split into estimated categories, the remainder landing in
the system and tools category, built from records shaped as the transcript adapter emits them."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

import pytest

from reporails_cli.core.platform.contract.json_value import as_list
from reporails_cli.core.platform.dto.events import (
    EventRecord,
    HarnessEntry,
    MessageSize,
    PromptEntry,
    ReplyText,
    RequestSize,
    TokenUsage,
)
from reporails_cli.core.platform.dto.xray_composition import COMPOSITION_KEYS, REMAINDER_KEY
from reporails_cli.core.platform.dto.xray_sources import ArtifactFile
from reporails_cli.core.xray.vocabulary import vocabulary_for
from tests.unit.xray.test_xray_graph import _agent, _file, _graph, _node, launch, load, rec, reply, result

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

COLUMNS = ("t", "total", "input", "cache_write", "cache_read", *COMPOSITION_KEYS, "over_estimate", "measured")
Row = dict[str, object]


def _files(root: Path) -> tuple[ArtifactFile, ArtifactFile, ArtifactFile]:
    """An instruction file of 100 tokens, a rule of 200 and a memory note of 100."""
    return (
        _file(root, "CLAUDE.md", 400),
        _file(root, "rules/r.md", 800, "rule"),
        _file(root, "MEMORY.md", 400, "memory"),
    )


def _rows(root: Path, records: Sequence[EventRecord], node: str = "main") -> list[Row]:
    """The reply rows of `node` by column name."""
    graph = _graph(root, records, _files(root))
    rows = _agent(_node(graph, node)).usage.composition.to_json()["replies"]
    return [dict(zip(COLUMNS, as_list(row), strict=True)) for row in as_list(rows)]


def _num(row: Row, key: str) -> int:
    value = row[key]
    assert isinstance(value, int)
    return value


def _first_request(seconds: float, *read: ArtifactFile) -> EventRecord:
    """The first request after a compaction, holding the read results of the files `read`."""
    size = RequestSize("req", 0, 0, 0, MessageSize(), 0, (), None, reads=tuple(item.path for item in read))
    return rec("api_request", seconds, item=size)


def _note(seconds: float) -> EventRecord:
    """A hook note of 80 characters."""
    return rec("harness", seconds, item=HarnessEntry("hook_note", "h", None, 80, "PreToolUse"))


def _skills(seconds: float, chars: int) -> EventRecord:
    """A skills listing of `chars` characters."""
    return rec("harness", seconds, item=HarnessEntry("skill_list", "skills", 3, chars))


def _typed(seconds: float, chars: int) -> EventRecord:
    """A prompt a person typed."""
    return rec("prompt_submit", seconds, item=PromptEntry(f"p{seconds}", chars, False))


def _said(seconds: float, chars: int) -> EventRecord:
    """Text an agent wrote."""
    return rec("assistant_text", seconds, item=ReplyText(chars, False))


def _returned(seconds: float, chars: int) -> EventRecord:
    """A tool result of `chars` characters."""
    return result(seconds, f"r{seconds}", None, chars)


def _session(root: Path) -> list[EventRecord]:
    """The main agent loads a file, a rule and a memory note, takes a skills listing, three hook notes, a prompt, a
    tool result and its own text; subagent A is launched with a 1600-character brief."""
    claude, rule, memory = _files(root)
    return [
        load(0.1, claude),
        load(0.2, rule),
        load(0.3, memory),
        _skills(0.4, 1600),
        _typed(0.5, 800),
        _note(0.6),
        reply(1, context=10000),
        _note(1.5),
        _returned(2, 2000),
        _said(2.5, 400),
        _note(2.6),
        reply(3, context=12000),
        launch(4, "A", None, "tuA", brief_chars=1600),
        reply(5, "A", context=3000),
        reply(6, context=13000),
    ]


def test_every_reply_of_both_agents_has_categories_that_sum_exactly_to_its_total(tmp_path: Path) -> None:
    for node in ("main", "A"):
        rows = _rows(tmp_path, _session(tmp_path), node)
        assert rows
        for row in rows:
            assert sum(_num(row, key) for key in COMPOSITION_KEYS) == row["total"]
            assert _num(row, "input") + _num(row, "cache_write") + _num(row, "cache_read") == row["total"]
            assert row["over_estimate"] is False


def test_the_estimates_are_what_the_records_hold_and_the_remainder_is_the_system_and_tools(tmp_path: Path) -> None:
    first, second, *_ = _rows(tmp_path, _session(tmp_path))
    assert first["total"] == 10000 and first["cache_read"] == 9999 and first["input"] == 1
    # 100 instructions, 200 rule, 400 skills listing, 100 memory, one 20-token hook note, a 200-token prompt.
    assert [first[key] for key in COMPOSITION_KEYS[1:]] == [100, 200, 400, 100, 20, 200, 0]
    assert first[REMAINDER_KEY] == 10000 - 1020
    # Two more hook notes, the tool result (500) and the agent's own text (100) enter by the second reply.
    assert [second[key] for key in COMPOSITION_KEYS[1:]] == [100, 200, 400, 100, 60, 300, 500]
    assert second[REMAINDER_KEY] == 12000 - 1660


def test_a_subagents_brief_counts_in_its_own_conversation_and_not_the_parents(tmp_path: Path) -> None:
    (own,) = _rows(tmp_path, _session(tmp_path), "A")
    assert (own["conversation"], own[REMAINDER_KEY]) == (400, 2600)
    assert _rows(tmp_path, _session(tmp_path))[-1]["conversation"] == 300


def test_a_file_loaded_twice_counts_once_and_a_hook_firing_three_times_counts_three_times(tmp_path: Path) -> None:
    claude, _, _ = _files(tmp_path)
    records = [load(0.1, claude), _note(0.2), _note(0.3), _note(0.4), load(0.5, claude), reply(1, context=5000)]
    (row,) = _rows(tmp_path, records)
    assert (row["instructions"], row["hook_notes"]) == (100, 60)


def test_an_estimate_over_the_total_keeps_the_negative_remainder_and_flags_the_reply(tmp_path: Path) -> None:
    claude, rule, _ = _files(tmp_path)
    ok, over = _rows(tmp_path, [load(0.1, claude), load(0.2, rule), reply(1, context=1000), reply(2, context=200)])
    assert ok[REMAINDER_KEY] == 700 and ok["over_estimate"] is False
    assert over[REMAINDER_KEY] == -100 and over["over_estimate"] is True
    assert sum(_num(over, key) for key in COMPOSITION_KEYS) == over["total"]


def test_a_compaction_drops_the_hook_notes_and_the_hook_sources_attribution_and_keeps_the_files(
    tmp_path: Path,
) -> None:
    claude, _, _ = _files(tmp_path)

    def priced(seconds: float) -> EventRecord:
        return rec("assistant_usage", seconds, usage=TokenUsage(f"m{seconds}", 1, 0, 9999, "claude-opus-4-8"))

    records = [
        load(0.1, claude),
        _note(0.2),
        priced(1),
        rec("post_compact", 2, source="auto"),
        _first_request(2.5, claude),
        priced(3),
    ]
    before, after = _rows(tmp_path, records)
    assert (before["hook_notes"], after["hook_notes"], after["instructions"]) == (20, 0, 100)
    graph = _graph(tmp_path, records, _files(tmp_path))
    spent = dict(_agent(_node(graph, "main")).usage.cost.by_source_usd_est)
    rate = spent[next(key for key in spent if key.startswith("hook:"))] / 20
    assert spent["CLAUDE.md"] == pytest.approx(rate * 200)


def test_a_hook_note_after_a_compaction_and_before_the_next_reply_stays_in_the_context(tmp_path: Path) -> None:
    claude, _, _ = _files(tmp_path)
    records = [
        load(0.1, claude),
        rec("post_compact", 10, source="auto"),
        _first_request(11, claude),
        _note(12),
        rec("assistant_usage", 15, usage=TokenUsage("m15", 1, 0, 9999, "claude-opus-4-8")),
    ]
    (row,) = _rows(tmp_path, records)
    assert (row["hook_notes"], row["instructions"]) == (20, 100)
    graph = _graph(tmp_path, records, _files(tmp_path))
    spent = dict(_agent(_node(graph, "main")).usage.cost.by_source_usd_est)
    assert spent[next(key for key in spent if key.startswith("hook:"))] > 0


def test_a_compaction_zeroes_the_conversation_and_tool_results_after_it_and_keeps_the_loads(tmp_path: Path) -> None:
    claude, _, _ = _files(tmp_path)
    records = [
        load(0.1, claude),
        _typed(0.5, 800),
        _returned(0.7, 2000),
        reply(1, context=10000),
        rec("post_compact", 2, source="auto"),
        _first_request(2.5, claude),
        reply(3, context=4000),
        _typed(3.5, 400),
        reply(4, context=4500),
    ]
    before, after, later = _rows(tmp_path, records)
    assert (before["conversation"], before["tool_results"]) == (200, 500)
    assert (after["conversation"], after["tool_results"], after["instructions"]) == (0, 0, 100)
    assert (later["conversation"], later["tool_results"]) == (100, 0)


def test_a_compaction_takes_a_file_out_of_the_chart_when_its_read_result_is_not_in_the_first_request(
    tmp_path: Path,
) -> None:
    claude, rule, _ = _files(tmp_path)
    records = [
        load(0.1, claude),
        load(0.2, rule),
        reply(1, context=10000),
        rec("post_compact", 2, source="auto"),
        _first_request(2.5, claude),
        reply(3, context=4000),
    ]
    before, after = _rows(tmp_path, records)
    assert after["instructions"] == 100 and before["instructions"] + before["rules_skills"] > after["instructions"]
    unsettled_before, unsettled_after = _rows(tmp_path, [r for r in records if r.event != "api_request"])
    assert (unsettled_after["instructions"], unsettled_after["rules_skills"]) == (
        unsettled_before["instructions"],
        unsettled_before["rules_skills"],
    )


def test_the_skills_listing_sums_its_delta_rows_and_an_agent_without_a_reply_has_no_rows(tmp_path: Path) -> None:
    (row,) = _rows(tmp_path, [_skills(0.1, 1600), _skills(0.2, 800), reply(1, context=5000)])
    assert row["skill_listing"] == 600
    assert not _rows(tmp_path, [_skills(0.1, 1600)])


def test_the_vocabulary_names_every_category_and_the_remainder() -> None:
    vocabulary = vocabulary_for("claude", [])
    assert [item.key for item in vocabulary.composition.labels] == list(COMPOSITION_KEYS)
    assert vocabulary.composition.remainder == REMAINDER_KEY


def _hook_row(root: Path, records: Sequence[EventRecord]) -> tuple[str, int, float | None]:
    """The reason, tokens and time of the main agent's hook row at its peak reply."""
    shown = _agent(_node(_graph(root, records, _files(root)), "main")).in_context
    assert shown is not None
    row = next(item for item in shown.rows if item.key == "hooks")
    return row.reason, row.tokens_est, row.t


def _peak(seconds: float) -> EventRecord:
    return rec("assistant_usage", seconds, usage=TokenUsage(f"m{seconds}", 1, 0, 9999, "claude-opus-4-8"))


def test_a_hook_note_stamped_with_a_compactions_instant_builds_the_view_and_is_the_rows_firing(tmp_path: Path) -> None:
    claude, _, _ = _files(tmp_path)
    records = [load(0.1, claude), _note(5), rec("post_compact", 10, source="auto"), _note(10), _peak(15)]
    reason, tokens, moment = _hook_row(tmp_path, records)
    assert (reason, tokens) == ("fired once", 20)
    assert (
        moment
        == _hook_row(tmp_path, [load(0.1, claude), rec("post_compact", 10, source="auto"), _note(10), _peak(15)])[2]
    )
    assert moment is not None and moment > _hook_row(tmp_path, [load(0.1, claude), _note(5), _peak(15)])[2]


def test_the_hook_row_words_one_firing_and_several(tmp_path: Path) -> None:
    claude, _, _ = _files(tmp_path)
    assert _hook_row(tmp_path, [load(0.1, claude), _note(5), _peak(15)])[0] == "fired once"
    assert _hook_row(tmp_path, [load(0.1, claude), _note(5), _note(6), _peak(15)])[0] == "fired 2 times"


def test_a_built_in_note_words_a_count_of_one_in_the_singular(tmp_path: Path) -> None:
    def notes(count: int) -> list[str | None]:
        records = [
            rec("harness", 0.2, item=HarnessEntry("skill_list", "skills", count, 400)),
            rec("harness", 0.3, item=HarnessEntry("agent_list", "agents", count, 400)),
            rec("harness", 0.4, item=HarnessEntry("deferred_tools", "tools", count, 400)),
            _peak(5),
        ]
        return [
            item.note for item in _graph(tmp_path, records, _files(tmp_path)).builtin if item.key != "system_prompt"
        ]

    assert notes(1) == ["1 tool loaded on demand", "1 agent description", "1 skill description"]
    assert notes(2) == ["2 tools loaded on demand", "2 agent descriptions", "2 skill descriptions"]


def test_only_the_shell_category_carries_a_command_to_fetch() -> None:
    categories = vocabulary_for("claude", []).categories
    assert [item.key for item in categories if item.command] == ["run"]


def test_two_compactions_with_one_timestamp_build_the_view(tmp_path: Path) -> None:
    claude, _, _ = _files(tmp_path)
    records = [load(0.1, claude), rec("post_compact", 2, source="auto"), rec("post_compact", 2, source="manual")]
    station = next(item for item in _graph(tmp_path, records, _files(tmp_path)).stations if item.node == "main")
    assert len(station.compactions) == 2


def test_a_file_first_loaded_after_a_compaction_is_listed_by_the_next_compaction(tmp_path: Path) -> None:
    claude, rule, _ = _files(tmp_path)
    records = [
        load(0.1, claude),
        reply(1, context=10000),
        rec("post_compact", 2, source="auto"),
        _first_request(2.5, claude),
        load(2.7, rule),
        reply(3, context=4000),
        rec("post_compact", 4, source="auto"),
        _first_request(4.5, claude, rule),
        reply(5, context=3000),
    ]
    graph = _graph(tmp_path, records, _files(tmp_path))
    station = next(item for item in graph.stations if item.node == "main")
    first, second = station.compactions
    assert {item.source for item in first.files} == {"CLAUDE.md"}
    assert {item.source for item in second.files} == {"CLAUDE.md", "rules/r.md"}


def test_a_nested_file_with_no_read_result_of_its_own_is_unknown_after_a_compaction_not_dropped(tmp_path: Path) -> None:
    claude, rule, _ = _files(tmp_path)
    records = [
        load(0.1, claude),
        load(0.2, rule, memory_type="nested"),
        reply(1, context=10000),
        rec("post_compact", 2, source="auto"),
        _first_request(2.5, claude),
        reply(3, context=4000),
    ]
    graph = _graph(tmp_path, records, _files(tmp_path))
    (compaction,) = next(item for item in graph.stations if item.node == "main").compactions
    assert {item.source: item.state for item in compaction.files} == {"CLAUDE.md": "kept", "rules/r.md": "unknown"}


def test_an_unknown_file_keeps_its_chart_share_and_is_listed_by_the_next_compaction(tmp_path: Path) -> None:
    claude, rule, _ = _files(tmp_path)
    records = [
        load(0.1, claude),
        load(0.2, rule, memory_type="nested"),
        reply(1, context=10000),
        rec("post_compact", 2, source="auto"),
        _first_request(2.5, claude),
        reply(3, context=4000),
        rec("post_compact", 4, source="auto"),
        _first_request(4.5, claude),
        reply(5, context=3000),
    ]
    before, after, *_ = _rows(tmp_path, records)
    assert after["rules_skills"] == before["rules_skills"] > 0
    graph = _graph(tmp_path, records, _files(tmp_path))
    first, second = next(item for item in graph.stations if item.node == "main").compactions
    assert {item.source: item.state for item in first.files}["rules/r.md"] == "unknown"
    assert {item.source: item.state for item in second.files}["rules/r.md"] == "unknown"
