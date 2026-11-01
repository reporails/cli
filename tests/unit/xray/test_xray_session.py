"""The session view: turns, subagents, loads, artifacts and growth, built from the transcript fixtures."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from reporails_cli.core.eventbus import store
from reporails_cli.core.eventbus.transcript import read_transcript
from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object
from reporails_cli.core.platform.dto.events import EventKind, EventRecord, HarnessEntry, ToolUse, TranscriptCursor
from reporails_cli.core.platform.dto.xray import ArtifactFile, FindingTally, XrayCheck, XrayLoad, XrayView
from reporails_cli.core.xray.artifacts import PEEK_LIMIT, artifact_files, build_artifacts
from reporails_cli.core.xray.derive import BYTES_PER_TOKEN, Replies, build_harness
from reporails_cli.core.xray.session import XraySession

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript"
SESSION = "session"
TOP_KEYS = {
    "version",
    "session",
    "project",
    "started_at",
    "length_s",
    "window",
    "model",
    "funnel",
    "first_context",
    "peak",
    "preload_tokens_est",
    "start",
    "turns",
    "compactions",
    "subagents",
    "artifacts",
    "refusals",
    "not_known",
    "harness",
    "check",
    "facts",
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


def _append_compaction(tmp_path: Path, version: str, time: str, trigger: str) -> None:
    row = {
        "type": "system",
        "subtype": "compact_boundary",
        "timestamp": time,
        "sessionId": "s",
        "compactMetadata": {"trigger": trigger},
    }
    with (tmp_path / version / "session.jsonl").open("a") as handle:
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


RUNNING = XrayCheck("running", None)


def _tally(count: int) -> FindingTally:
    return FindingTally(count, {"error": 0, "warning": count, "info": 0})


def _view(session: XraySession, findings: dict[str, FindingTally] | None = None) -> XrayView:
    session.refresh()
    return session.view(findings or {}, RUNNING)


def _names(loads: tuple[XrayLoad, ...]) -> list[str]:
    return [Path(load.path).name for load in loads]


@pytest.mark.parametrize("version", ["2.1.301", "2.1.308"])
def test_turn_context_is_the_three_counts_of_its_last_reply(tmp_path: Path, version: str) -> None:
    view = _view(_session(tmp_path, version, _project(tmp_path)))
    expected = _fixture_turn_contexts(version)
    assert [turn.context.last for turn in view.turns] == expected
    assert expected[0] > 20000
    assert view.context.first_context == view.turns[0].context.first


def test_a_turn_spans_the_replies_between_two_turn_ends(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    assert [(turn.n, len(turn.context.series)) for turn in view.turns] == [(1, 1), (2, 1)]
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
    assert len(session.view({}, RUNNING).turns) == 2

    _append_turn(tmp_path, "2.1.301")
    assert session.refresh() is True
    assert session.version == version + 1
    view = session.view({}, RUNNING)
    assert [turn.n for turn in view.turns] == [1, 2, 3]
    assert view.turns[2].context.last == 30103
    assert session.refresh() is False


def test_the_version_follows_the_findings_it_is_given(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.301", _project(tmp_path))
    session.refresh()
    version = session.version
    session.view({}, RUNNING)
    assert session.version == version
    session.view({"a.md": _tally(2)}, RUNNING)
    assert session.version == version + 1
    session.view({"a.md": _tally(2)}, RUNNING)
    assert session.version == version + 1
    session.view({"a.md": _tally(2)}, XrayCheck("done", None))
    assert session.version == version + 2


def test_without_bus_records_reads_and_compactions_are_not_known(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    assert all(turn.reads is None for turn in view.turns)
    assert view.compactions == ()
    assert "reads" in view.gaps.not_known


def test_a_compact_boundary_row_is_the_turns_compaction_with_no_bus(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.301", _project(tmp_path))
    _append_compaction(tmp_path, "2.1.301", "2026-10-17T16:54:30.000Z", "manual")
    view = _view(session)
    (compaction,) = view.compactions
    assert compaction.turn == 2
    assert (compaction.trigger, compaction.before, compaction.after) == ("manual", 25172, 26009)
    assert "reads" in view.gaps.not_known


def test_a_bus_compact_record_alone_draws_no_compaction(tmp_path: Path) -> None:
    _bus("pre_compact", "2026-10-17T16:54:30.000Z", source="manual")
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    assert view.compactions == ()


def test_bus_reads_land_in_the_turn_they_were_timed_in_and_a_row_compacts_it(tmp_path: Path) -> None:
    _bus("pre_tool", "2026-10-17T16:54:00.000Z", paths=("/p/notes.md",))
    session = _session(tmp_path, "2.1.301", _project(tmp_path))
    _append_compaction(tmp_path, "2.1.301", "2026-10-17T16:54:30.000Z", "manual")
    view = _view(session)
    first, second = view.turns
    assert first.reads == ()
    assert second.reads == ("/p/notes.md",)
    (compaction,) = view.compactions
    assert compaction.turn == 2
    assert (compaction.trigger, compaction.before, compaction.after) == ("manual", 25172, 26009)
    assert "reads" not in view.gaps.not_known


def test_artifacts_list_what_could_load_and_the_turns_it_sat_in_context(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.301", root)
    _append_compaction(tmp_path, "2.1.301", "2026-10-17T16:54:30.000Z", "auto")
    _append_turn(tmp_path, "2.1.301")
    view = _view(session, {str(root / "CLAUDE.md"): _tally(3)})
    by_path = {a.path: a for a in view.artifacts}
    kinds = {(Path(path).name, a.kind) for path, a in by_path.items()}
    assert {("SKILL.md", "skill"), ("helper.md", "agent"), ("settings.json", "hook")} <= kinds
    main = by_path["CLAUDE.md"]
    # Loaded at the start and in context in turn 2, where the compaction ran, then gone in turn 3.
    assert main.loaded and main.turns == (0, 1, 2) and main.findings == _tally(3)
    assert view.start[0].findings == _tally(3)
    assert main.tokens_est == (root / "CLAUDE.md").stat().st_size // BYTES_PER_TOKEN > 0
    skill = by_path[".claude/skills/demo/SKILL.md"]
    assert not skill.loaded and skill.turns == ()
    assert by_path[".claude/agents/helper.md"].findings is None


def test_a_skills_supporting_file_is_no_artifact_of_its_own(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / ".claude" / "skills" / "demo" / "reference.md").write_text("# Reference\n\nDetails the demo skill cites.\n")
    kinds = {(Path(a.path).name, a.kind) for a in artifact_files(root, [])}
    assert ("SKILL.md", "skill") in kinds
    assert not any(name == "reference.md" for name, _ in kinds)
    assert [kind for name, kind in kinds if name == "SKILL.md"] == ["skill"]


def test_a_loaded_file_stays_in_context_without_a_compaction(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.301", root)
    _append_turn(tmp_path, "2.1.301")
    artifacts = {a.path: a for a in _view(session).artifacts}
    assert artifacts["CLAUDE.md"].turns == (0, 1, 2, 3)
    nested = artifacts["sub/CLAUDE.md"]
    assert nested.loaded and nested.turns == (1, 2, 3)


def test_the_view_holds_numbers_names_and_paths_only(tmp_path: Path) -> None:
    data = _view(_session(tmp_path, "2.1.308", _project(tmp_path))).to_json()
    assert set(data) == TOP_KEYS
    assert "PLACEHOLDER" not in json.dumps(data)
    assert data["project"] == "proj" and data["window"] is None and data["session"] == SESSION
    assert as_list(data["refusals"]) == []
    turn_keys = {
        "n", "start", "opened_by", "stop_blocks", "delta", "t", "context_start", "context", "replies", "loads",
        "reads", "subagents", "series", "prompts", "notes", "skill_runs",
    }  # fmt: skip
    assert set(as_object(as_list(data["turns"])[0])) == turn_keys
    assert set(as_object(as_list(data["subagents"])[0])) == {
        "id",
        "type",
        "turn",
        "start",
        "end",
        "series",
        "loads",
        "skill_runs",
        "peak",
        "has_project_instructions",
    }
    assert set(as_object(as_list(data["start"])[0])) == {"path", "kind", "t", "tokens_est", "findings"}
    assert set(as_object(as_list(data["artifacts"])[0])) == {
        "path",
        "kind",
        "scope",
        "plugin",
        "label",
        "memory_type",
        "linked",
        "loaded",
        "turns",
        "findings",
        "actionable",
        "tokens_est",
        "advertised",
        "contexts",
        "session_tokens_est",
    }
    assert data["check"] == {"state": "running", "message": None}
    assert data["check"] == {"state": "running", "message": None}


def test_a_session_with_no_records_is_an_empty_view(tmp_path: Path) -> None:
    session = XraySession(_project(tmp_path), tmp_path / "missing.jsonl")
    assert session.refresh() is False
    view = session.view({}, RUNNING)
    assert (view.turns, view.start, view.subagents, view.context.first_context, view.info.length_s) == (
        (),
        (),
        (),
        None,
        None,
    )


def test_the_json_is_plain_data(tmp_path: Path) -> None:
    data: JsonObject = _view(_session(tmp_path, "2.1.301", _project(tmp_path))).to_json()
    assert json.loads(json.dumps(data)) == data


def test_only_a_project_file_that_exists_is_actionable(tmp_path: Path) -> None:
    root = _project(tmp_path)
    memory = tmp_path / "home" / ".claude" / "projects" / "p" / "memory" / "MEMORY.md"
    memory.parent.mkdir(parents=True)
    memory.write_text("# memory\n")
    files = (
        ArtifactFile(str(root / "CLAUDE.md"), "instructions", "project", None, "CLAUDE.md", None, None),
        ArtifactFile(
            str(root / "missing" / "CLAUDE.md"), "instructions", "project", None, "missing/CLAUDE.md", None, None
        ),
        ArtifactFile(
            str(root / ".claude" / "settings.json"), "hook", "project", None, ".claude/settings.json", None, None
        ),
        ArtifactFile(str(memory), "memory", "auto", None, "MEMORY.md", None, None),
    )
    got = [a.actionable for a in build_artifacts(files, set(), {}, {}, root, advertised={}, contexts={})]
    assert got == [True, False, False, False]


def test_a_session_acts_on_only_the_files_its_view_lists(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "notes.txt").write_text("notes\n")
    session = _session(tmp_path, "2.1.301", root)
    assert session.acts_on("CLAUDE.md") is True
    assert session.acts_on("notes.txt") is False
    assert session.acts_on(".claude/settings.json") is False
    assert session.acts_on("../proj/CLAUDE.md") is False


def test_a_skill_lists_its_entry_file_only(tmp_path: Path) -> None:
    root = _project(tmp_path)
    folder = root / ".claude" / "skills" / "demo"
    (folder / "ref.md").write_text("# ref\n")
    (folder / "deeper").mkdir()
    (folder / "deeper" / "SKILL.md").write_text("# nested\n")
    skills = [Path(f.path).relative_to(root).as_posix() for f in artifact_files(root, []) if f.kind == "skill"]
    assert skills == [".claude/skills/demo/SKILL.md"]


def test_the_artifact_list_carries_user_and_plugin_files_with_their_scope_and_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    plugin = tmp_path / "plugins" / "cache" / "p"
    (plugin / "commands").mkdir(parents=True)
    (plugin / "commands" / "go.md").write_text("---\ndescription: Go.\n---\n\n# Go\n")
    registry = {"version": 2, "plugins": {"p@m": [{"scope": "user", "installPath": str(plugin), "version": "1"}]}}
    (tmp_path / "plugins" / "installed_plugins.json").write_text(json.dumps(registry))
    monkeypatch.setenv("CLAUDE_CODE_PLUGIN_CACHE_DIR", str(tmp_path / "plugins"))
    user_skill = Path.home() / ".claude" / "skills" / "mine"
    user_skill.mkdir(parents=True)
    (user_skill / "SKILL.md").write_text("---\nname: mine\ndescription: Mine.\n---\n\n# Mine\n")
    (root / ".claude" / "rules").mkdir()
    (root / ".claude" / "rules" / "style.md").write_text("# Style\n\nUse `ruff` always.\n")
    session = _session(tmp_path, "2.1.301", root)
    by_label = {(a.kind, a.label): a for a in _view(session).artifacts}
    assert by_label[("skill", "mine")].scope == "user" and not by_label[("skill", "mine")].actionable
    command = by_label[("command", "p:go")]
    assert (command.scope, command.plugin, command.actionable) == ("plugin", "p@m", False)
    assert by_label[("rule", ".claude/rules/style.md")].scope == "project"


def test_a_path_shows_relative_to_the_project_or_the_home_folder(tmp_path: Path) -> None:
    home = Path.home()
    assert relative_wire_path(str(tmp_path / "a" / "b.md"), tmp_path) == "a/b.md"
    assert relative_wire_path(str(home / ".claude" / "x.md"), tmp_path) == "~/.claude/x.md"
    assert relative_wire_path("/elsewhere/x.md", tmp_path) == "/elsewhere/x.md"


def _text_size(*numbers: int) -> int:
    return sum(len(f"PLACEHOLDER-TEXT-{number}") for number in numbers)


def test_a_turn_series_is_the_context_of_each_of_its_replies_in_order(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.308-harness", _project(tmp_path)))
    (turn,) = view.turns
    assert [context for _, context in turn.context.series] == [2 + 500 + 1000, 2 + 700 + 1000, 2 + 900 + 1000]
    assert [t for t, _ in turn.context.series] == sorted(t for t, _ in turn.context.series)
    assert (turn.context.first, turn.context.last, len(turn.context.series)) == (1502, 1902, 3)
    assert turn.to_json()["series"] == [[t, c] for t, c in turn.context.series]


def test_the_harness_lists_the_first_of_each_kind_and_the_session_start_notes(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.308-harness", root)
    late = {
        "type": "attachment",
        "timestamp": "2026-10-30T20:03:30.000Z",
        "sessionId": "s",
        "attachment": {
            "type": "hook_additional_context",
            "content": ["PLACEHOLDER-TEXT-90"],
            "hookName": "SessionStart",
            "toolUseID": "SessionStart",
            "hookEvent": "SessionStart",
        },
    }
    again = {**late, "attachment": {"type": "skill_listing", "content": "x", "skillCount": 1}}
    with (tmp_path / "2.1.308-harness" / "session.jsonl").open("a") as handle:
        handle.write(json.dumps(late) + "\n" + json.dumps(again) + "\n")
    items = _view(session).harness
    assert items is not None
    got = [(item.kind, item.label, item.count, item.tokens_est) for item in items]
    assert got == [
        ("hook_note", "SessionStart", None, _text_size(2) // 4),
        ("session_context", "session context", None, _text_size(4, 5) // 4),
        ("system_prompt", "system prompt", 3, _text_size(6, 7, 8) // 4),
        ("deferred_tools", "deferred tools", 2, _text_size(10, 11) // 4),
        ("agent_list", "agents", 3, _text_size(12, 13, 14) // 4),
        ("mcp_instructions", "MCP server instructions", 1, _text_size(15) // 4),
        ("skill_list", "skills", 8, (_text_size(16) + 1) // 4),
    ]


def _turns_session(tmp_path: Path) -> XraySession:
    return _session(tmp_path, "2.1.309-turns", _project(tmp_path))


def test_a_turn_lists_the_prompts_typed_in_it_and_the_hook_notes_after_the_first_reply(tmp_path: Path) -> None:
    view = _view(_turns_session(tmp_path))
    first, second = view.turns
    assert [(p.id, p.queued) for p in first.prompts] == [("p-one", False)]
    assert [(p.id, p.queued) for p in second.prompts] == [("p-two", False), ("q-one", True)]
    assert [(n.kind, n.event, n.label) for n in first.notes] == [
        ("hook_note", "UserPromptSubmit", "UserPromptSubmit"),
        ("stop_block", "Stop", "Stop"),
    ]
    assert [(n.kind, n.event) for n in second.notes] == [("hook_note", "PostToolUse")]
    assert [n.tokens_est for n in first.notes] == [2 * len("PLACEHOLDER-TEXT-4") // 4, 4]
    assert first.prompts[0].t < first.notes[0].t < first.notes[-1].t <= first.t


def test_the_session_start_notes_stay_in_the_harness_and_out_of_the_turns(tmp_path: Path) -> None:
    view = _view(_turns_session(tmp_path))
    items = view.harness or ()
    assert [(i.kind, i.label) for i in items] == [
        ("hook_note", "SessionStart:startup"),
        ("hook_note", "SessionStart"),
    ]
    assert all(n.event != "SessionStart" for turn in view.turns for n in turn.notes)


def test_the_view_no_longer_calls_stop_blocks_hook_notes_and_prompts_unknown(tmp_path: Path) -> None:
    view = _view(_turns_session(tmp_path))
    assert not {"stop hook blocks", "hook notes", "prompts"} & set(view.gaps.not_known)


def test_a_prompt_text_is_given_only_for_a_prompt_the_records_name(tmp_path: Path) -> None:
    session = _turns_session(tmp_path)
    session.refresh()
    assert session.prompt("p-one") == "PLACEHOLDER-TEXT-3"
    assert session.prompt("q-one") == "PLACEHOLDER-TEXT-15"
    assert session.prompt("t-result") is None
    assert session.prompt("../../etc/passwd") is None


def test_a_session_start_note_after_a_compaction_is_a_note_of_its_turn(tmp_path: Path) -> None:
    session = _turns_session(tmp_path)
    late = {
        "type": "attachment",
        "timestamp": "2026-10-31T10:03:00.000Z",
        "sessionId": "s",
        "attachment": {
            "type": "hook_additional_context",
            "content": ["PLACEHOLDER-TEXT-99"],
            "hookName": "SessionStart:compact",
            "toolUseID": "SessionStart",
            "hookEvent": "SessionStart",
        },
    }
    with (tmp_path / "2.1.309-turns" / "session.jsonl").open("a") as handle:
        handle.write(json.dumps(late) + "\n")
    view = _view(session)
    assert [item.label for item in view.harness or ()] == ["SessionStart:startup", "SessionStart"]
    assert [(n.event, n.label) for n in view.turns[-1].notes] == [("SessionStart", "SessionStart:compact")]


def test_the_deltas_before_the_first_compaction_sum_to_what_the_listing_after_it_holds(tmp_path: Path) -> None:
    root = _project(tmp_path)
    copy = tmp_path / "2.1.309-compaction"
    shutil.copytree(FIXTURES / "2.1.309-compaction", copy)
    session = XraySession(root, copy / "session.jsonl")
    items = {item.kind: item for item in _view(session).harness or ()}
    rows = [json.loads(line) for line in (copy / "session.jsonl").read_text().splitlines()]
    after = next(r["attachment"] for r in rows[8:] if r.get("attachment", {}).get("type") == "deferred_tools_delta")
    assert items["deferred_tools"].count == len(after["addedNames"]) == 38 + 12
    assert items["agent_list"].count == 20 and items["mcp_instructions"].count == 1
    assert items["skill_list"].count == 51
    before = [r["attachment"] for r in rows[:7] if r.get("attachment", {}).get("type") == "deferred_tools_delta"]
    assert items["deferred_tools"].tokens_est == sum(len(x) for a in before for x in a["addedLines"]) // 4


def _append_delta(tmp_path: Path, version: str, time: str, **fields: list[str]) -> None:
    attachment = {"type": "deferred_tools_delta", "addedNames": [], "addedLines": [], **fields}
    row = {"type": "attachment", "timestamp": time, "sessionId": "s", "attachment": attachment}
    with (tmp_path / version / "session.jsonl").open("a") as handle:
        handle.write(json.dumps(row) + "\n")


def test_a_harness_row_after_the_last_turn_end_opens_no_empty_turn(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.301", _project(tmp_path))
    end = {"type": "system", "timestamp": "2098-12-31T00:00:00.000Z", "sessionId": "s", "subtype": "turn_duration"}
    with (tmp_path / "2.1.301" / "session.jsonl").open("a") as handle:
        handle.write(json.dumps({**end, "durationMs": 10}) + "\n")
    before = len(_view(session).turns)
    _append_delta(tmp_path, "2.1.301", "2099-01-01T00:00:00.000Z", addedNames=["T"], addedLines=["a tool line"])
    assert len(_view(session).turns) == before


def test_a_tool_the_harness_retracts_takes_its_size_off_with_it(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.308-harness", _project(tmp_path))

    def deferred(view: XrayView) -> tuple[int | None, int | None]:
        item = next(i for i in view.harness or () if i.kind == "deferred_tools")
        return item.count, item.tokens_est

    first = deferred(_view(session))
    names = ["ToolA", "ToolB", "ToolC", "ToolD"]
    lines = [f"{name}: " + "x" * 40 for name in names]
    _append_delta(tmp_path, "2.1.308-harness", "2099-01-01T00:00:00.000Z", addedNames=names, addedLines=lines)
    session.refresh()
    grown = deferred(session.view({}, RUNNING))
    assert grown[0] == (first[0] or 0) + 4 and (grown[1] or 0) > (first[1] or 0)
    _append_delta(tmp_path, "2.1.308-harness", "2099-01-01T00:00:01.000Z", removedNames=names)
    session.refresh()
    assert deferred(session.view({}, RUNNING)) == first


def test_a_session_with_no_harness_row_has_a_null_harness(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    assert view.harness is None and view.to_json()["harness"] is None


def test_no_view_or_record_holds_transcript_text(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.308-harness", _project(tmp_path))
    view = _view(session)
    assert view.harness
    assert "PLACEHOLDER-TEXT" not in json.dumps(view.to_json())
    records, _ = read_transcript("claude", tmp_path / "2.1.308-harness" / "session.jsonl", TranscriptCursor())
    assert records and all("PLACEHOLDER-TEXT" not in repr(record) for record in records)


def test_no_view_or_record_holds_prompt_or_hook_text(tmp_path: Path) -> None:
    session = _turns_session(tmp_path)
    view = _view(session)
    assert any(turn.prompts and turn.notes for turn in view.turns)
    assert "PLACEHOLDER-TEXT" not in json.dumps(view.to_json())
    records, _ = read_transcript("claude", tmp_path / "2.1.309-turns" / "session.jsonl", TranscriptCursor())
    assert records and all("PLACEHOLDER-TEXT" not in repr(record) for record in records)
    assert all("PLACEHOLDER-TEXT" not in json.dumps(record.to_json()) for record in records)


def test_a_session_peeks_only_a_listed_file_that_is_not_a_hook_config(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "notes.txt").write_text("notes\n")
    session = _session(tmp_path, "2.1.301", root)
    session.refresh()
    assert session.peek("CLAUDE.md") == ((root / "CLAUDE.md").read_text(), False)
    assert session.peek(".claude/skills/demo/SKILL.md") is not None
    assert session.peek("notes.txt") is None
    assert session.peek(".claude/settings.json") is None
    assert session.peek("../proj/CLAUDE.md") is None


def test_a_peek_is_cut_at_the_character_limit(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / "CLAUDE.md").write_text("a" * (PEEK_LIMIT + 5))
    session = _session(tmp_path, "2.1.301", root)
    text, truncated = session.peek("CLAUDE.md") or ("", False)
    assert len(text) == PEEK_LIMIT and truncated is True


def test_a_brief_is_given_only_for_a_subagent_the_records_name(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.308-harness", _project(tmp_path))
    session.refresh()
    assert session.brief("abrief0000000001") == "PLACEHOLDER-TEXT-19"
    assert session.brief("nosuchagent") is None
    assert session.brief("../../../etc/passwd") is None


def test_a_file_whose_config_scope_is_no_artifact_scope_is_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    listing = {"invocable": [{"path": "a/SKILL.md", "file_type": "skills", "precedence": "enterprise", "label": "a"}]}
    monkeypatch.setattr("reporails_cli.core.xray.artifacts.expected_loads", lambda root, plugins: listing)
    with pytest.raises(ValueError, match="enterprise"):
        artifact_files(tmp_path, [])


def _append_rows(tmp_path: Path, *rows: JsonObject) -> None:
    with (tmp_path / "2.1.301" / "session.jsonl").open("a") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


def _skill_run_row(name: str, time: str) -> JsonObject:
    return {
        "type": "user",
        "uuid": "u-skill",
        "sessionId": "s",
        "timestamp": time,
        "message": {"role": "user", "content": [{"type": "tool_result", "content": "Launching skill"}]},
        "toolUseResult": {"success": True, "commandName": name},
    }


def test_a_skill_that_ran_is_loaded_from_its_turn_and_a_compaction_brings_it_back(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.301", root)
    _append_turn(tmp_path, "2.1.301")
    _append_rows(tmp_path, _skill_run_row("demo", "2026-10-17T16:55:15.000Z"))
    _append_rows(tmp_path, *_end_and_reply("2026-10-17T16:55:20.000Z", "2026-10-17T16:55:30.000Z"))
    view = _view(session)
    skill = next(a for a in view.artifacts if a.path == ".claude/skills/demo/SKILL.md")
    assert skill.loaded and skill.turns == (3, 4)
    (run,) = view.turns[2].skill_runs
    assert run.name == "demo" and run.path == skill.path and run.tokens_est == skill.tokens_est
    _append_compaction(tmp_path, "2.1.301", "2026-10-17T16:56:30.000Z", "auto")
    _append_rows(tmp_path, *_end_and_reply("2026-10-17T16:56:40.000Z", "2026-10-17T16:56:50.000Z"))
    again = next(a for a in _view(session).artifacts if a.path == skill.path)
    assert again.loaded and again.turns == (3, 4, 5)


def test_a_run_matching_no_listed_file_still_shows_in_its_turn_by_name(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.301", root)
    _append_turn(tmp_path, "2.1.301")
    _append_rows(tmp_path, _skill_run_row("not-listed", "2026-10-17T16:55:15.000Z"))
    view = _view(session)
    (run,) = view.turns[-1].skill_runs
    assert (run.name, run.path, run.tokens_est) == ("not-listed", None, None)
    assert not any(a.label == "not-listed" for a in view.artifacts)


def test_a_subagent_of_a_listed_agent_type_marks_that_agent_loaded_in_its_turn(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / ".claude" / "agents" / "writer.md").write_text("---\nname: writer\ndescription: Writes.\n---\n\n# Writer\n")
    session = _session(tmp_path, "2.1.308", root)
    meta = next((tmp_path / "2.1.308" / "session" / "subagents").glob("*.meta.json"))
    meta.write_text(json.dumps({**json.loads(meta.read_text()), "agentType": "writer"}))
    view = _view(session)
    by_path = {a.path: a for a in view.artifacts}
    (sub,) = view.subagents
    assert sub.type == "writer" and sub.turn is not None
    assert by_path[".claude/agents/writer.md"].loaded and by_path[".claude/agents/writer.md"].turns == (sub.turn,)
    assert not by_path[".claude/agents/helper.md"].loaded


def test_a_built_in_subagent_type_changes_no_agent_artifact(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.308", root)
    meta = next((tmp_path / "2.1.308" / "session" / "subagents").glob("*.meta.json"))
    meta.write_text(json.dumps({**json.loads(meta.read_text()), "agentType": "Explore"}))
    agents = [a for a in _view(session).artifacts if a.kind == "agent"]
    assert agents and not any(a.loaded or a.turns for a in agents)


def _end_and_reply(time_end: str, time_reply: str) -> tuple[JsonObject, JsonObject]:
    """A turn end at `time_end` and a main reply at `time_reply`, which opens the next turn."""
    message = {**as_object(NEW_TURN[1]["message"]), "id": f"msg_{time_reply}"}
    return (
        {"type": "system", "timestamp": time_end, "sessionId": "s", "subtype": "turn_duration"},
        {**NEW_TURN[1], "timestamp": time_reply, "message": message},
    )


def _add_skill(root: Path, name: str, size: int, *, scope_root: Path | None = None) -> None:
    folder = (scope_root or root) / ".claude" / "skills" / name
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text(f"---\nname: {name}\ndescription: Skill.\n---\n" + "x" * size)


def _runs_then_compaction(tmp_path: Path, names: list[str]) -> XrayView:
    """Each of `names` run in turn 3, a compaction in turn 5, then one more turn."""
    root = _project(tmp_path)
    for name in [n for n in names if n != "demo"]:
        _add_skill(root, name, 100_000 if name == "big" else 20_000)
    session = _session(tmp_path, "2.1.301", root)
    _append_turn(tmp_path, "2.1.301")
    _append_rows(tmp_path, *(_skill_run_row(n, f"2026-10-17T16:55:{10 + i:02d}.000Z") for i, n in enumerate(names)))
    _append_rows(tmp_path, *_end_and_reply("2026-10-17T16:55:30.000Z", "2026-10-17T16:55:40.000Z"))
    _append_rows(tmp_path, *_end_and_reply("2026-10-17T16:55:45.000Z", "2026-10-17T16:55:50.000Z"))
    _append_compaction(tmp_path, "2.1.301", "2026-10-17T16:55:55.000Z", "auto")
    _append_rows(tmp_path, *_end_and_reply("2026-10-17T16:56:00.000Z", "2026-10-17T16:56:10.000Z"))
    return _view(session)


def _turns_of(view: XrayView, name: str) -> tuple[int, ...]:
    return next(a.turns for a in view.artifacts if a.label == name)


def test_a_compaction_brings_back_the_latest_runs_until_the_shared_budget_is_spent(tmp_path: Path) -> None:
    names = [f"skill-{n}" for n in range(1, 7)]
    view = _runs_then_compaction(tmp_path, names)
    # Six runs of 5,000 tokens each: the budget of 25,000 keeps the five latest, and the oldest is not brought back.
    assert _turns_of(view, "skill-1") == (3, 4, 5)
    assert all(_turns_of(view, name) == (3, 4, 5, 6) for name in names[1:])


def test_a_run_is_brought_back_at_no_more_than_five_thousand_tokens(tmp_path: Path) -> None:
    view = _runs_then_compaction(tmp_path, ["demo", "big"])
    # `big` is 25,000 tokens on disk but counts 5,000 against the budget, so the older `demo` fits beside it.
    assert _turns_of(view, "big") == (3, 4, 5, 6) and _turns_of(view, "demo") == (3, 4, 5, 6)


def test_a_forked_skill_run_is_not_in_the_main_context(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.301", root)
    _append_turn(tmp_path, "2.1.301")
    row = _skill_run_row("demo", "2026-10-17T16:55:15.000Z")
    row["toolUseResult"] = {"success": True, "commandName": "demo", "status": "forked", "agentId": "a1"}
    _append_rows(tmp_path, row)
    view = _view(session)
    skill = next(a for a in view.artifacts if a.label == "demo")
    assert not skill.loaded and skill.turns == ()
    (run,) = view.turns[-1].skill_runs
    assert run.forked and run.path == skill.path


def test_a_re_added_tool_keeps_its_size_and_is_not_counted_twice() -> None:
    def row(time: str, entry: HarnessEntry) -> EventRecord:
        return EventRecord("claude", "harness", "s", time, item=entry)

    kind = "deferred_tools"
    first = row("2026-10-31T10:00:00Z", HarnessEntry(kind, "deferred tools", 1, 400, added=(("tool_b", 400),)))
    added = row("2026-10-31T10:00:01Z", HarnessEntry(kind, "deferred tools", 1, 500, added=(("tool_a", 500),)))
    readded = row("2026-10-31T10:00:02Z", HarnessEntry(kind, "deferred tools", 1, 0, readded=("tool_a",)))
    removed = row("2026-10-31T10:00:03Z", HarnessEntry(kind, "deferred tools", -1, 0, removed=("tool_a",)))

    def summed(*records: EventRecord) -> tuple[int | None, int | None]:
        (item,) = build_harness(list(records), Replies(())) or ()
        return item.count, item.tokens_est

    assert summed(first) == (1, 100)
    assert summed(first, added) == (2, 225)
    assert summed(first, added, readded) == (2, 225)
    assert summed(first, added, readded, removed) == summed(first)


def test_a_skill_of_the_user_folder_wins_over_the_project_skill_of_the_same_name(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _add_skill(root, "deploy", 10)
    _add_skill(root, "deploy", 10, scope_root=Path.home())
    session = _session(tmp_path, "2.1.301", root)
    _append_turn(tmp_path, "2.1.301")
    _append_rows(tmp_path, _skill_run_row("deploy", "2026-10-17T16:55:15.000Z"))
    by_path = {a.path: a for a in _view(session).artifacts}
    assert by_path["~/.claude/skills/deploy/SKILL.md"].loaded
    assert not by_path[".claude/skills/deploy/SKILL.md"].loaded


def _set_agent_type(tmp_path: Path, agent_type: str) -> None:
    meta = next((tmp_path / "2.1.308" / "session" / "subagents").glob("*.meta.json"))
    meta.write_text(json.dumps({**json.loads(meta.read_text()), "agentType": agent_type}))


def test_an_agent_of_the_project_wins_over_the_user_agent_of_the_same_name(tmp_path: Path) -> None:
    root = _project(tmp_path)
    user_agents = Path.home() / ".claude" / "agents"
    user_agents.mkdir(parents=True)
    (user_agents / "helper.md").write_text("---\nname: helper\ndescription: Helps.\n---\n\n# Mine\n")
    session = _session(tmp_path, "2.1.308", root)
    _set_agent_type(tmp_path, "helper")
    by_path = {a.path: a for a in _view(session).artifacts}
    assert by_path[".claude/agents/helper.md"].loaded
    assert not by_path["~/.claude/agents/helper.md"].loaded


def test_an_agent_is_known_by_its_frontmatter_name_not_its_file_name(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / ".claude" / "agents" / "reviewer.md").write_text("---\nname: code-reviewer\ndescription: Reviews.\n---\n")
    session = _session(tmp_path, "2.1.308", root)
    _set_agent_type(tmp_path, "code-reviewer")
    reviewer = next(a for a in _view(session).artifacts if a.path == ".claude/agents/reviewer.md")
    assert reviewer.label == "code-reviewer" and reviewer.loaded


def test_a_skill_a_subagent_ran_is_loaded_in_the_turn_the_subagent_ran(tmp_path: Path) -> None:
    root = _project(tmp_path)
    session = _session(tmp_path, "2.1.308", root)
    sub_file = next((tmp_path / "2.1.308" / "session" / "subagents").glob("agent-*.jsonl"))
    last = json.loads(sub_file.read_text().splitlines()[-1])
    row = {**_skill_run_row("demo", last["timestamp"]), "sessionId": last["sessionId"], "isSidechain": True}
    with sub_file.open("a") as handle:
        handle.write(json.dumps(row) + "\n")
    view = _view(session)
    (sub,) = view.subagents
    skill = next(a for a in view.artifacts if a.label == "demo")
    assert [run.name for run in sub.skill_runs] == ["demo"]
    assert skill.loaded and skill.turns == (sub.turn,)


def _user_demo_skill() -> None:
    folder = Path.home() / ".claude" / "skills" / "demo"
    folder.mkdir(parents=True)
    (folder / "SKILL.md").write_text("---\nname: demo\ndescription: User demo.\n---\n\n# Demo\n")


def test_the_model_is_the_latest_main_reply_that_names_one_and_the_window_shows_past_200k(tmp_path: Path) -> None:
    data = _view(_session(tmp_path, "2.1.310-listing", _project(tmp_path))).to_json()
    # The last main reply names no model, so the one before it stands; the subagent's model is not the session's.
    assert data["model"] == "claude-opus-5[1m]"
    assert data["window"] == {"size": 1_000_000, "basis": "observed"}
    assert "context window" not in as_list(data["not_known"])


def test_a_session_below_200k_has_no_window_and_no_model_when_no_row_names_one(tmp_path: Path) -> None:
    data = _view(_session(tmp_path, "2.1.308", _project(tmp_path))).to_json()
    assert data["window"] is None and data["model"] is None
    assert "context window" in as_list(data["not_known"])


def test_an_artifact_is_advertised_when_the_listing_names_it_and_none_without_names(tmp_path: Path) -> None:
    root = _project(tmp_path)
    by_label = {(a.kind, a.label): a for a in _view(_session(tmp_path, "2.1.310-listing", root)).artifacts}
    assert by_label[("skill", "demo")].advertised is True
    assert by_label[("agent", "helper")].advertised is True
    assert by_label[("instructions", "CLAUDE.md")].advertised is None
    bare = {(a.kind, a.label): a for a in _view(_session(tmp_path, "2.1.308", root)).artifacts}
    assert bare[("skill", "demo")].advertised is None and bare[("agent", "helper")].advertised is None


def test_of_two_skills_sharing_a_label_only_the_winning_scope_is_advertised(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _user_demo_skill()
    demos = [a for a in _view(_session(tmp_path, "2.1.310-listing", root)).artifacts if a.label == "demo"]
    assert {a.scope: a.advertised for a in demos} == {"user": True, "project": False}


def test_the_funnel_counts_what_the_artifacts_show_for_each_kind_on_disk(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.310-listing", _project(tmp_path)))
    rows = {row.kind: row for row in view.verdict.funnel}
    assert list(rows) == ["instructions", "skill", "agent", "hook"]
    for kind, row in rows.items():
        items = [a for a in view.artifacts if a.kind == kind]
        assert row.on_disk == len(items)
        assert row.loaded == (None if kind == "hook" else sum(a.loaded for a in items))
    assert (rows["skill"].advertised, rows["skill"].used) == (1, 0)
    assert (rows["agent"].advertised, rows["agent"].loaded, rows["agent"].used) == (1, 1, 1)
    assert rows["instructions"].advertised is None and rows["instructions"].used is None
    assert rows["hook"].advertised is None and rows["hook"].used is None


def test_a_file_counts_the_main_context_and_each_subagent_that_put_it_in_its_own(tmp_path: Path) -> None:
    root = _project(tmp_path)
    view = _view(_session(tmp_path, "2.1.310-listing", root))
    by_path = {a.path: a for a in view.artifacts}
    (sub,) = view.subagents
    assert sub.has_project_instructions and sub.peak == 30_000
    # The project CLAUDE.md loaded at the main start and again into the subagent's context.
    claude = by_path["CLAUDE.md"]
    assert claude.contexts == 2 and claude.session_tokens_est == 2 * (claude.tokens_est or 0) > 0
    # The agent file is in the context of the subagent that ran as it, and no other.
    helper = by_path[".claude/agents/helper.md"]
    assert helper.contexts == 1
    assert by_path[".claude/skills/demo/SKILL.md"].contexts == 0


def test_every_compaction_is_kept_each_band_ends_at_the_next_and_the_last_at_the_session_end(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.309-compactions", _project(tmp_path)))
    first, second = view.compactions
    assert (first.turn, first.trigger, second.turn, second.trigger) == (2, "manual", 3, "auto")
    assert first.band_end == second.t
    assert view.info.length_s is not None and second.band_end == view.info.length_s
    assert first.t < second.t < second.band_end


def test_a_file_loaded_only_before_the_first_compaction_is_out_of_context_after_it(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.309-compactions", _project(tmp_path)))
    by_path = {a.path: a for a in view.artifacts}
    # Loaded in turn 1 and in context in turn 2, where the first compaction ran, then gone in turn 3.
    assert by_path["sub/CLAUDE.md"].turns == (1, 2)


def test_the_peak_is_the_highest_context_a_reply_or_a_compaction_before_reached(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.309-compactions", _project(tmp_path)))
    first, second = view.compactions
    assert first.before == 200096 and second.before == 61843 and second.after == 30102
    assert view.context.peak == first.before


def test_the_preload_is_the_harness_items_plus_the_start_loads(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    harness = sum(item.tokens_est or 0 for item in view.harness or ())
    assert view.context.preload_tokens_est == harness + sum(load.tokens_est or 0 for load in view.start) > 0


def test_a_turn_with_a_prompt_is_opened_by_it_and_prompts_are_numbered_through_the_session(tmp_path: Path) -> None:
    view = _view(_turns_session(tmp_path))
    first, second = view.turns
    assert (first.opened_by, second.opened_by) == ("prompt", "prompt")
    assert [p.no for turn in view.turns for p in turn.prompts] == [1, 2, 3]
    assert first.start == first.prompts[0].t and second.start == second.prompts[0].t
    assert (first.stop_blocks, second.stop_blocks) == (1, 0)


def test_a_turn_delta_is_its_context_less_the_last_known_context_before_it(tmp_path: Path) -> None:
    view = _view(_turns_session(tmp_path))
    first, second = view.turns
    contexts = _fixture_turn_contexts("2.1.309-turns")
    assert first.context.delta == 0 and view.context.first_context == contexts[0]
    assert second.context.delta == contexts[1] - contexts[0]


def _without_rows(tmp_path: Path, drop: set[int]) -> XraySession:
    """The turns fixture with the rows at the `drop` indexes removed."""
    session = _turns_session(tmp_path)
    path = tmp_path / "2.1.309-turns" / "session.jsonl"
    lines = path.read_text().splitlines()
    path.write_text("".join(line + "\n" for index, line in enumerate(lines) if index not in drop))
    return session


def test_a_turn_with_no_prompt_after_a_stop_block_was_opened_by_the_stop_hook(tmp_path: Path) -> None:
    view = _view(_without_rows(tmp_path, {13, 14, 15, 16}))
    first, second = view.turns
    assert second.prompts == () and second.opened_by == "stop_hook"
    assert first.opened_by == "prompt"
    assert second.start == second.context.series[0][0]
    assert second.context.delta is not None


def test_a_first_turn_with_no_prompt_is_opened_by_the_session_start(tmp_path: Path) -> None:
    view = _view(_without_rows(tmp_path, {3}))
    assert view.turns[0].prompts == () and view.turns[0].opened_by == "session_start"
    assert view.turns[1].opened_by == "prompt"
