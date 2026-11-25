"""Which instruction files a compaction restored, from the transcript rows it kept."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.events import CompactionBoundary, EventRecord, InstructionLoad
from reporails_cli.core.platform.dto.xray_build import SourceTable
from reporails_cli.core.xray.graph import compaction_files
from reporails_cli.core.xray.graph.compaction_files import file_states

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]


def _load(path: str, row: str, time: str) -> EventRecord:
    return EventRecord("claude", "instruction_load", "s", time, item=InstructionLoad(path, None, row))


def test_every_file_one_kept_row_loaded_is_restored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compaction_files, "_instruction_source", lambda path, _sources: path)
    records = [
        _load("CLAUDE.md", "row-1", "2026-01-01T00:00:00Z"),
        _load(".claude/rules/a.md", "row-1", "2026-01-01T00:00:00Z"),
        _load(".claude/rules/b.md", "row-1", "2026-01-01T00:00:00Z"),
        EventRecord("claude", "post_compact", "s", "2026-01-01T00:01:00Z", item=CompactionBoundary("b", ("row-1",))),
        EventRecord("claude", "assistant_usage", "s", "2026-01-01T00:02:00Z"),
    ]
    (states,) = file_states(records, SourceTable((), Path(), {}, {}), (frozenset(),))
    assert {item.source: item.state for item in states} == {
        "CLAUDE.md": "restored",
        ".claude/rules/a.md": "restored",
        ".claude/rules/b.md": "restored",
    }


def test_a_file_state_says_whether_its_content_is_in_the_context(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(compaction_files, "_instruction_source", lambda path, _sources: path)
    records = [
        _load("CLAUDE.md", "row-1", "2026-01-01T00:00:00Z"),
        _load("kept.md", "row-1", "2026-01-01T00:00:00Z"),
        _load("dropped.md", "row-2", "2026-01-01T00:00:00Z"),
        EventRecord("claude", "post_compact", "s", "2026-01-01T00:01:00Z", item=CompactionBoundary("b", ("row-1",))),
        EventRecord("claude", "assistant_usage", "s", "2026-01-01T00:02:00Z"),
    ]
    (states,) = file_states(records, SourceTable((), Path(), {}, {}), (frozenset(),))
    assert {item.source: (item.state, item.in_context) for item in states} == {
        "CLAUDE.md": ("restored", True),
        "kept.md": ("restored", True),
        "dropped.md": ("summarized", False),
    }
    assert {item.source: item.to_json()["in_context"] for item in states}["dropped.md"] is False
