"""The session view: turns, subagents, loads, artifacts and growth, built from the transcript fixtures."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from reporails_cli.core.eventbus import store
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object
from reporails_cli.core.platform.dto.events import EventKind, EventRecord, ToolUse
from reporails_cli.core.platform.dto.xray import XrayLoad, XrayView
from reporails_cli.core.xray.session import XraySession

pytestmark = pytest.mark.unit

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript"
SESSION = "session"
TOP_KEYS = {
    "version",
    "session",
    "project",
    "started_at",
    "length_s",
    "window",
    "first_context",
    "start",
    "turns",
    "subagents",
    "artifacts",
    "refusals",
    "not_known",
}
SUB_308 = "a27081343121455fb"
NEW_TURN = (
    {
        "type": "system",
        "timestamp": "2026-10-17T16:54:50.000Z",
        "sessionId": "s",
        "subtype": "turn_duration",
        "durationMs": 10,
    },
    {
        "type": "assistant",
        "timestamp": "2026-10-17T16:55:10.000Z",
        "sessionId": "s",
        "message": {
            "id": "msg_new",
            "role": "assistant",
            "content": [],
            "usage": {"input_tokens": 3, "cache_creation_input_tokens": 100, "cache_read_input_tokens": 30000},
        },
    },
)


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / ".claude" / "skills" / "demo").mkdir(parents=True)
    (root / ".claude" / "agents").mkdir()
    (root / "sub").mkdir()
    (root / "CLAUDE.md").write_text("# Rules\n\nRun `pytest` before committing every change.\n" * 2)
    (root / "sub" / "CLAUDE.md").write_text("# Sub\n\nKeep `sub/` small.\n")
    skill = "---\nname: demo\ndescription: Demo.\n---\n\n# Demo\n"
    (root / ".claude" / "skills" / "demo" / "SKILL.md").write_text(skill)
    agent = "---\nname: helper\ndescription: Helps.\n---\n\n# Helper\n"
    (root / ".claude" / "agents" / "helper.md").write_text(agent)
    hooks = {"hooks": {"PreToolUse": [{"matcher": "Read", "hooks": [{"type": "command", "command": "true"}]}]}}
    (root / ".claude" / "settings.json").write_text(json.dumps(hooks))
    return root


def _session(tmp_path: Path, version: str, root: Path) -> XraySession:
    """A session over a copy of the fixture whose paths point into `root`."""
    copy = tmp_path / version
    shutil.copytree(FIXTURES / version, copy)
    for file in copy.rglob("*.jsonl"):
        file.write_text(file.read_text().replace("/work/proj", str(root)))
    return XraySession(root, copy / "session.jsonl")


def _append_turn(tmp_path: Path, version: str) -> None:
    with (tmp_path / version / "session.jsonl").open("a") as handle:
        for row in NEW_TURN:
            handle.write(json.dumps(row) + "\n")


def _bus(event: EventKind, time: str, source: str | None = None, paths: tuple[str, ...] = ()) -> None:
    tool = "Read" if event == "pre_tool" else None
    store.append(
        EventRecord(
            agent="claude",
            event=event,
            session_id=SESSION,
            time=time,
            source=source,
            tool=ToolUse(tool, None, paths[0] if paths else None) if tool else None,
        )
    )


def _fixture_turn_contexts(version: str) -> list[int]:
    """Per turn, the three counts summed for its last main reply, worked out from the raw rows."""
    rows = [json.loads(line) for line in (FIXTURES / version / "session.jsonl").read_text().splitlines()]
    turns: list[dict[str, int]] = [{}]
    for row in rows:
        if row.get("type") == "assistant":
            message = row["message"]
            usage = message["usage"]
            turns[-1][message["id"]] = (
                usage["input_tokens"] + usage["cache_creation_input_tokens"] + usage["cache_read_input_tokens"]
            )
        elif row.get("subtype") == "turn_duration":
            turns.append({})
    return [list(turn.values())[-1] for turn in turns if turn]


def _view(session: XraySession, findings: dict[str, int] | None = None) -> XrayView:
    session.refresh()
    return session.view(findings or {})


def _names(loads: tuple[XrayLoad, ...]) -> list[str]:
    return [Path(load.path).name for load in loads]


@pytest.mark.parametrize("version", ["2.1.301", "2.1.308"])
def test_turn_context_is_the_three_counts_of_its_last_reply(tmp_path: Path, version: str) -> None:
    view = _view(_session(tmp_path, version, _project(tmp_path)))
    expected = _fixture_turn_contexts(version)
    assert [turn.context for turn in view.turns] == expected
    assert expected[0] > 20000
    assert view.first_context == view.turns[0].context_start


def test_a_turn_spans_the_replies_between_two_turn_ends(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    assert [(turn.n, turn.replies) for turn in view.turns] == [(1, 1), (2, 1)]
    assert view.turns[0].t < view.turns[1].t


def test_start_loads_belong_to_the_main_session_and_subagent_loads_to_the_subagent(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.308", _project(tmp_path)))
    assert _names(view.start) == ["CLAUDE.md", "MEMORY.md"]
    assert [load.kind for load in view.start] == ["project", "memory"]
    assert _names(view.turns[0].loads) == ["CLAUDE.md"]
    assert view.turns[0].loads[0].kind == "nested"
    (sub,) = view.subagents
    assert sub.id == SUB_308 and sub.type == "general-purpose"
    assert _names(sub.loads) == ["CLAUDE.md", "MEMORY.md", "CLAUDE.md"]
    assert [load.kind for load in sub.loads] == ["project", "memory", "nested"]
    assert sub.turn == 1 and sub.start is not None and sub.end is not None and sub.start < sub.end
    assert [context for _, context in sub.series] == [2 + 16279, 2 + 2330 + 16279]
    assert view.turns[0].subagents == (SUB_308,)


def test_a_load_is_sized_from_the_file_on_disk(tmp_path: Path) -> None:
    root = _project(tmp_path)
    view = _view(_session(tmp_path, "2.1.308", root))
    assert view.start[0].tokens_est == (root / "CLAUDE.md").stat().st_size // 4
    assert view.start[1].tokens_est is None


def test_refresh_reports_growth_and_bumps_the_version(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.301", _project(tmp_path))
    assert session.version == 0
    assert session.refresh() is True
    version = session.version
    assert session.refresh() is False
    assert session.version == version
    assert len(session.view({}).turns) == 2

    _append_turn(tmp_path, "2.1.301")
    assert session.refresh() is True
    assert session.version == version + 1
    view = session.view({})
    assert [turn.n for turn in view.turns] == [1, 2, 3]
    assert view.turns[2].context == 30103
    assert session.refresh() is False


def test_the_version_follows_the_findings_it_is_given(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.301", _project(tmp_path))
    session.refresh()
    version = session.version
    session.view({})
    assert session.version == version
    session.view({"a.md": 2})
    assert session.version == version + 1
    session.view({"a.md": 2})
    assert session.version == version + 1


def test_without_bus_records_reads_and_compactions_are_not_known(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    assert all(turn.reads is None and turn.compaction is None for turn in view.turns)
    assert "reads and compactions" in view.not_known


def test_bus_reads_and_compactions_land_in_the_turn_they_were_timed_in(tmp_path: Path) -> None:
    _bus("pre_tool", "2026-10-17T16:54:00.000Z", paths=("/p/notes.md",))
    _bus("pre_compact", "2026-10-17T16:54:30.000Z", source="manual")
    _bus("post_compact", "2026-10-17T16:54:31.000Z", source="manual")
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    first, second = view.turns
    assert first.reads == () and first.compaction is None
    assert second.reads == ("/p/notes.md",)
    compaction = second.compaction
    assert compaction is not None
    assert (compaction.trigger, compaction.before, compaction.after) == ("manual", 25172, 26009)
    assert "reads and compactions" not in view.not_known


def test_artifacts_list_what_could_load_and_the_turns_it_sat_in_context(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _bus("pre_compact", "2026-10-17T16:54:30.000Z", source="auto")
    session = _session(tmp_path, "2.1.301", root)
    _append_turn(tmp_path, "2.1.301")
    view = _view(session, {str(root / "CLAUDE.md"): 3})
    by_path = {a.path: a for a in view.artifacts}
    kinds = {(Path(path).name, a.kind) for path, a in by_path.items()}
    assert {("SKILL.md", "skill"), ("helper.md", "agent"), ("settings.json", "hook")} <= kinds
    main = by_path[str(root / "CLAUDE.md")]
    # Loaded at the start and in context in turn 2, where the compaction ran, then gone in turn 3.
    assert main.loaded and main.turns == (0, 1, 2) and main.findings == 3
    assert view.start[0].findings == 3
    skill = by_path[str(root / ".claude" / "skills" / "demo" / "SKILL.md")]
    assert not skill.loaded and skill.turns == ()
    assert by_path[str(root / ".claude" / "agents" / "helper.md")].findings is None


def test_a_loaded_file_stays_in_context_without_a_compaction(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.301", root)
    _append_turn(tmp_path, "2.1.301")
    artifacts = {a.path: a for a in _view(session).artifacts}
    assert artifacts[str(root / "CLAUDE.md")].turns == (0, 1, 2, 3)
    nested = artifacts[str(root / "sub" / "CLAUDE.md")]
    assert nested.loaded and nested.turns == (1, 2, 3)


def test_the_view_holds_numbers_names_and_paths_only(tmp_path: Path) -> None:
    data = _view(_session(tmp_path, "2.1.308", _project(tmp_path))).to_json()
    assert set(data) == TOP_KEYS
    assert "PLACEHOLDER" not in json.dumps(data)
    assert data["project"] == "proj" and data["window"] is None and data["session"] == SESSION
    assert as_list(data["refusals"]) == []
    turn_keys = {"n", "t", "context_start", "context", "replies", "loads", "reads", "subagents", "compaction"}
    assert set(as_object(as_list(data["turns"])[0])) == turn_keys
    assert set(as_object(as_list(data["subagents"])[0])) == {"id", "type", "turn", "start", "end", "series", "loads"}
    assert set(as_object(as_list(data["start"])[0])) == {"path", "kind", "t", "tokens_est", "findings"}
    assert set(as_object(as_list(data["artifacts"])[0])) == {"path", "kind", "loaded", "turns", "findings"}


def test_a_session_with_no_records_is_an_empty_view(tmp_path: Path) -> None:
    session = XraySession(_project(tmp_path), tmp_path / "missing.jsonl")
    assert session.refresh() is False
    view = session.view({})
    assert (view.turns, view.start, view.subagents, view.first_context, view.length_s) == ((), (), (), None, None)


def test_the_json_is_plain_data(tmp_path: Path) -> None:
    data: JsonObject = _view(_session(tmp_path, "2.1.301", _project(tmp_path))).to_json()
    assert json.loads(json.dumps(data)) == data
