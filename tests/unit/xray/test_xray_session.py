"""The session view built from the transcript fixtures: its nodes, sources, funnel and the files a session lists."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters.payload import relative_wire_path
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list
from reporails_cli.core.platform.dto.xray import ArtifactFile, FindingTally, XrayCheck, XrayView
from reporails_cli.core.xray.artifacts import PEEK_LIMIT, artifact_files, build_artifacts
from reporails_cli.core.xray.derive import BYTES_PER_TOKEN
from reporails_cli.core.xray.session import XraySession

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript"
RUNNING = XrayCheck("running", None)
TOP_KEYS = {
    "version", "session", "project", "started_at", "length_s", "model", "window", "adapter", "nodes", "edges",
    "sources", "stations", "track", "funnel", "facts", "check", "refusals", "not_known",
}  # fmt: skip
HANDOFFS = "2.1.309-handoffs"
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


def _tally(count: int) -> FindingTally:
    return FindingTally(count, {"error": 0, "warning": count, "info": 0})


def _view(session: XraySession, findings: dict[str, FindingTally] | None = None) -> XrayView:
    session.refresh()
    return session.view(findings or {}, RUNNING)


def _handoffs(tmp_path: Path) -> XrayView:
    return _view(_session(tmp_path, HANDOFFS, _project(tmp_path)))


def test_the_handoffs_session_reads_as_a_tree_of_agents_with_how_each_ended(tmp_path: Path) -> None:
    view = _handoffs(tmp_path)
    nodes = {node.id[:5]: node for node in view.nodes}
    assert {key: (node.parent and node.parent[:5], node.depth, node.descendants) for key, node in nodes.items()} == {
        "main": (None, 0, 6),
        "aaaa0": ("main", 1, 2),
        "abbb0": ("aaaa0", 2, 1),
        "accc0": ("abbb0", 3, 0),
        "addd0": ("main", 1, 0),
        "aeee0": ("main", 1, 0),
        "afff0": ("main", 1, 0),
    }
    assert {edge.child[:5]: edge.outcome for edge in view.edges} == {
        "aaaa0": "returned",
        "abbb0": "no_handback",
        "accc0": "no_handback",
        "addd0": "returned",
        "aeee0": "stopped",
        "afff0": "no_handback",
    }
    assert nodes["addd0"].type == "Explore" and nodes["main"].children[0].startswith("aaaa0")


def test_the_handoffs_session_shows_what_the_main_agent_did_on_its_station_and_track(tmp_path: Path) -> None:
    view = _handoffs(tmp_path)
    station = next(item for item in view.stations if item.node == "main")
    assert [(item.server, item.calls) for item in station.mcp] == [
        ("mcp:plugin_docs_server", 3),
        ("mcp:plugin_docs_server", 1),
    ]
    assert [(item.trigger, item.before is not None) for item in station.compactions] == [("manual", True)]
    track = next(item for item in view.tracks if item.node == "main")
    assert [run.count for run in track.failure_runs] == [3]
    losses = [fact for fact in view.verdict.facts if fact.kind == "compaction_loss"]
    assert [(fact.target.kind, fact.target.value) for fact in losses if fact.target] == [("node", "main")]


def test_the_handoffs_session_holds_no_transcript_text(tmp_path: Path) -> None:
    data = _handoffs(tmp_path).to_json()
    assert set(data) == TOP_KEYS
    assert "PLACEHOLDER-TEXT" not in json.dumps(data)


def test_the_vocabulary_lists_the_agent_types_found_on_disk_after_the_built_in_ones(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.301", _project(tmp_path)))
    keys = [item.key for item in view.adapter.agent_types]
    assert keys[:5] == ["main", "Explore", "general-purpose", "Plan", "fork"] and keys[5:] == ["helper"]


def test_refresh_reports_growth_and_bumps_the_version(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.301", _project(tmp_path))
    assert session.version == 0
    assert session.refresh() is True
    version = session.version
    assert session.refresh() is False
    assert session.version == version
    before = session.view({}, RUNNING).nodes[0].detail
    _append_turn(tmp_path, "2.1.301")
    assert session.refresh() is True
    assert session.version == version + 1
    after = session.view({}, RUNNING).nodes[0].detail
    assert len(after.series) == len(before.series) + 1 and after.series[-1][1] == 30103
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


def test_a_source_lists_what_could_load_with_its_size_findings_and_the_nodes_that_had_it(tmp_path: Path) -> None:
    root = _project(tmp_path)
    view = _view(_session(tmp_path, "2.1.301", root), {"CLAUDE.md": _tally(3)})
    by_id = {source.id: source for source in view.sources}
    main = by_id["CLAUDE.md"]
    assert (main.kind, main.name, main.path, main.availability, main.had_by) == (
        "instructions",
        "CLAUDE.md",
        "CLAUDE.md",
        "loaded",
        ("main", "a45a65cf310da614a"),
    )
    assert main.findings == _tally(3) and main.actionable
    assert main.tokens_est == (root / "CLAUDE.md").stat().st_size // BYTES_PER_TOKEN > 0
    skill = by_id[".claude/skills/demo/SKILL.md"]
    assert (skill.kind, skill.availability, skill.had_by) == ("skill", "on_disk", ())
    # Agent files and hook configs are no source.
    assert not any(source.path and source.path.endswith(("helper.md", "settings.json")) for source in view.sources)


def test_a_skills_supporting_file_is_no_artifact_of_its_own(tmp_path: Path) -> None:
    root = _project(tmp_path)
    (root / ".claude" / "skills" / "demo" / "reference.md").write_text("# Reference\n\nDetails the demo skill cites.\n")
    kinds = {(Path(a.path).name, a.kind) for a in artifact_files(root, [])}
    assert ("SKILL.md", "skill") in kinds
    assert not any(name == "reference.md" for name, _ in kinds)
    assert [kind for name, kind in kinds if name == "SKILL.md"] == ["skill"]


def test_a_session_with_no_records_is_an_empty_view(tmp_path: Path) -> None:
    session = XraySession(_project(tmp_path), tmp_path / "missing.jsonl")
    assert session.refresh() is False
    view = session.view({}, RUNNING)
    assert view.info.length_s is None and view.edges == ()
    (main,) = view.nodes
    assert (main.id, main.end, main.children, main.detail.series) == ("main", 0.0, (), ())


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
    got = [a.actionable for a in build_artifacts(files, {}, root, advertised={})]
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


def test_the_source_list_carries_user_and_plugin_files_with_their_label_and_kind(
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
    by_name = {(s.kind, s.name): s for s in _view(_session(tmp_path, "2.1.301", root)).sources}
    assert not by_name[("skill", "mine")].actionable
    # A command folds into the skill kind.
    assert not by_name[("skill", "p:go")].actionable
    assert by_name[("rule", ".claude/rules/style.md")].actionable


def test_a_path_shows_relative_to_the_project_or_the_home_folder(tmp_path: Path) -> None:
    home = Path.home()
    assert relative_wire_path(str(tmp_path / "a" / "b.md"), tmp_path) == "a/b.md"
    assert relative_wire_path(str(home / ".claude" / "x.md"), tmp_path) == "~/.claude/x.md"
    assert relative_wire_path("/elsewhere/x.md", tmp_path) == "/elsewhere/x.md"


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


def test_a_source_is_listed_when_the_harness_listing_names_it_and_the_funnel_counts_it(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.310-listing", _project(tmp_path)))
    skill = next(s for s in view.sources if s.name == "demo")
    assert (skill.availability, skill.had_by) == ("listed", ())
    rows = {row.kind: row for row in view.verdict.funnel}
    # Rows carry source kinds only: a command folds into the skill row and agent files have none.
    assert list(rows) == ["instructions", "skill"]
    assert (rows["skill"].advertised, rows["skill"].loaded, rows["skill"].used) == (1, 0, 0)
    assert rows["instructions"].loaded == 1 and rows["instructions"].used is None


def test_a_file_that_entered_two_contexts_is_a_repeated_instruction(tmp_path: Path) -> None:
    view = _view(_session(tmp_path, "2.1.310-listing", _project(tmp_path)))
    claude = next(s for s in view.sources if s.id == "CLAUDE.md")
    assert len(claude.had_by) == 2
    (fact,) = [f for f in view.verdict.facts if f.kind == "repeated_instructions"]
    assert dict(fact.numbers) == {"files": 1, "contexts": 2, "tokens_est": claude.tokens_est}
    assert fact.target is not None and (fact.target.kind, fact.target.value) == ("path", "CLAUDE.md")


def test_a_prompt_text_is_given_only_for_a_prompt_the_records_name(tmp_path: Path) -> None:
    session = _session(tmp_path, "2.1.309-turns", _project(tmp_path))
    session.refresh()
    main = next(node for node in session.view({}, RUNNING).nodes if node.id == "main")
    typed = main.detail.prompts
    assert typed and session.prompt(typed[0].id) is not None
    assert session.prompt("nosuchprompt") is None
