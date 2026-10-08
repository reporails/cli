"""`remedy_brief(path, location)` — the full rewrite brief for one workflow location.

`remedy_brief.remedy_brief_tool` builds the brief from an already-resolved location dict (as the
stored `validate` payload carries it, already relative-pathed) and a scan root; it runs the
same single-file pipeline `validate(path=<file>)` runs for each of the location's files.
`server._serve_remedy_brief` is the thin state-lookup wrapper: `no_workflow` / `workflow_requires_pro` /
`location_not_found` structured errors, and a served brief resets the path's call count.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.core.heal.preservation import PRESERVATION_CONTRACT
from reporails_cli.interfaces.mcp import remedy_brief, server, snapshots, tools

pytestmark = [pytest.mark.unit, pytest.mark.subsys_server]


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every brief here runs offline, whatever server the shell points at."""
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")


def _rules_installed() -> bool:
    from reporails_cli.core.platform.config.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(not _rules_installed(), reason="Rules framework not installed")

_has_onnx_model = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
).exists()
requires_model = pytest.mark.skipif(not _has_onnx_model, reason="Bundled ONNX model not available")


def _fake_map(files: tuple[Any, ...] = ()) -> Any:
    """A minimal stand-in for a mapper `RulesetMap` — `_brief_file_entry` only reads `.atoms`
    (via `atoms_for_file`) and `.files` (via `_file_loading` / `_file_agent`)."""
    return SimpleNamespace(atoms=(), files=files)


def _main_location(files: list[str]) -> dict[str, Any]:
    return {
        "order": 1,
        "element": "CLAUDE.md",
        "kind": "main",
        "loading": "session_start",
        "files": files,
        "importance": "gate_mover",
        "findings": [
            {
                "rule": "CORE:C:0042",
                "file": "CLAUDE.md",
                "line": 3,
                "pi": 0,
                "message": "Vague instruction.",
                "remedy": "Name it.",
            }
        ],
        "relations": [
            {
                "rule": "CORE:C:0044",
                "file": "CLAUDE.md",
                "line": 5,
                "partner_file": "skills/deploy/SKILL.md",
                "partner_line": 2,
                "message": "Repeats its partner.",
                "remedy": "Delete it here.",
            }
        ],
    }


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
def test_the_guide_renders_as_markdown_in_rule_order_and_the_same_every_time() -> None:
    markdown = remedy_brief.ideal_instruction_markdown()

    guide = remedy_brief.ideal_instruction_guide()
    headings = [line for line in markdown.splitlines() if line.startswith("### ")]
    assert headings == [f"### {g['title']} ({g['id']})" for g in guide]
    assert [g["id"] for g in guide] == list(remedy_brief.IDEAL_INSTRUCTION_RULE_IDS)
    for entry in guide:
        assert entry["pass"] in markdown
        assert entry["antipatterns"] in markdown
    assert markdown.count("# The Ideal Instruction\n") == 0, "a rule's own title line is not repeated"
    assert remedy_brief.ideal_instruction_markdown() == markdown


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
def test_ideal_instruction_ids_are_in_fixed_order_with_statement_and_examples() -> None:
    guide = remedy_brief.ideal_instruction_guide()
    assert [g["id"] for g in guide] == list(remedy_brief.IDEAL_INSTRUCTION_RULE_IDS)
    for entry in guide:
        assert set(entry) == {"id", "title", "statement", "pass", "antipatterns"}
        assert entry["title"], entry["id"]
    # At least the well-documented rules carry a non-empty statement / pass / antipatterns —
    # a wholly-empty guide entry for every field would mean the extraction broke.
    assert any(e["statement"] for e in guide)
    assert any(e["pass"] for e in guide)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_file_with_no_map_makes_the_whole_brief_a_structured_error(monkeypatch, tmp_path: Path) -> None:
    """When a file of the location yields no map (a pipeline error, an offline server),
    the whole reply is a structured `brief_unavailable` error naming the file — never an entry
    with empty inventories and no snapshot, which reads as "there is genuinely nothing here".
    The message also names the underlying cause (here the payload's own `error` field, since
    there is no `mapper_error`), so a caller can tell WHY, not just THAT."""
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"error": "offline"}, None, None))
    location = _main_location(["CLAUDE.md"])

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    assert reply == {
        "error": "brief_unavailable",
        "message": "Could not build the rewrite brief for CLAUDE.md — its pipeline run produced no map: offline",
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_no_map_names_the_mapper_s_own_swallowed_exception(monkeypatch, tmp_path: Path) -> None:
    """The live concurrency defect: `_build_map` swallows a mapper exception into a payload
    `mapper_error` field (`interfaces/mcp/tools.py`). `brief_unavailable`'s message must name
    THAT — not the generic "produced no map" — and must prefer it over a bare `error` field
    when both are present, since `mapper_error` is the more specific cause."""
    monkeypatch.setattr(
        tools,
        "run_pipeline_for_path",
        lambda path, full=False: (
            {"error": "offline", "mapper_error": "RuntimeError: dictionary changed size during iteration"},
            None,
            None,
        ),
    )
    location = _main_location(["CLAUDE.md"])

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    assert reply == {
        "error": "brief_unavailable",
        "message": (
            "Could not build the rewrite brief for CLAUDE.md — its pipeline run produced no map: "
            "RuntimeError: dictionary changed size during iteration"
        ),
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_second_file_with_no_map_also_makes_the_whole_brief_an_error(monkeypatch, tmp_path: Path) -> None:
    """The first file of a multi-file location builds fine; the second yields no map — the
    whole brief is still the structured error, not a partial reply."""
    calls = {"n": 0}

    def fake_run(path: str, full: bool = False) -> tuple[dict[str, Any], Any, float | None]:
        calls["n"] += 1
        if calls["n"] == 1:
            return {"files": {}}, _fake_map(), None
        return {"error": "offline"}, None, None

    monkeypatch.setattr(tools, "run_pipeline_for_path", fake_run)
    location = _main_location(["CLAUDE.md", "SKILL.md"])

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    assert reply["error"] == "brief_unavailable"
    assert "SKILL.md" in reply["message"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_directory_in_files_still_briefs_the_locations_real_skill_files(monkeypatch, tmp_path: Path) -> None:
    """A skill folder that nests sub-skills but has no `SKILL.md` of its own puts a
    directory into the location's `files`. The directory must not sink the whole brief — the
    location's real `SKILL.md` files still brief, and the directory's own finding stays in
    `findings` untouched."""
    skill_dir = tmp_path / ".claude" / "skills" / "presentation"
    (skill_dir / "writing").mkdir(parents=True)
    (skill_dir / "writing" / "SKILL.md").write_text("# writing\n", encoding="utf-8")

    def fake_run(path: str, full: bool = False) -> tuple[dict[str, Any], Any, float | None]:
        return {"files": {}}, _fake_map(), None

    monkeypatch.setattr(tools, "run_pipeline_for_path", fake_run)
    location = {
        "order": 2,
        "element": ".claude/skills/presentation",
        "kind": "skills",
        "loading": "on_demand",
        "importance": "conditional",
        "files": [
            ".claude/skills/presentation",
            ".claude/skills/presentation/writing/SKILL.md",
        ],
        "findings": [
            {
                "rule": "CORE:S:0040",
                "file": ".claude/skills/presentation",
                "line": 0,
                "pi": 0,
                "message": "Skill directory has no own SKILL.md.",
                "remedy": "n/a",
            }
        ],
        "relations": [],
    }

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    assert "error" not in reply
    assert reply["location"]["files"] == location["files"]
    assert reply["edits"] == [] and reply["slots"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_location_of_only_directories_names_the_cause_once(tmp_path: Path) -> None:
    """When every one of a location's `files` is a directory, the reply is a structured
    `brief_unavailable` naming the cause a single time — never the generic "produced no map"
    fallback text echoed twice into the same sentence."""
    skill_dir = tmp_path / ".claude" / "skills" / "presentation"
    skill_dir.mkdir(parents=True)
    location = {
        "order": 2,
        "element": ".claude/skills/presentation",
        "kind": "skills",
        "loading": "on_demand",
        "importance": "conditional",
        "files": [".claude/skills/presentation"],
        "findings": [],
        "relations": [],
    }

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    assert reply["error"] == "brief_unavailable"
    assert reply["message"] == (
        "Could not build the rewrite brief for .claude/skills/presentation — every one of its "
        "files is a directory with no SKILL.md of its own."
    )


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_dilution_finding_does_not_make_its_line_deletable(monkeypatch, tmp_path: Path) -> None:
    """A `CORE:C:0041` entry in the location does not make the prose on its line deletable:
    deleting that line is reported in `lost_context` like the deletion of any other prose."""
    from reporails_cli.core.heal import preservation
    from reporails_cli.interfaces.mcp import snapshots

    abs_file = tmp_path / "CLAUDE.md"
    abs_file.write_text(
        "# Project\n\n"
        "The api runs on port 8001 and reloads from the source tree on every edit.\n\n"
        "The build uses a local cache that survives restarts.\n",
        encoding="utf-8",
    )
    trimmable = SimpleNamespace(
        line=3,
        position_index=0,
        text="The api runs on port 8001 and reloads from the source tree on every edit.",
        charge_value=0,
        named_tokens=[],
        embedding_int8=None,
        unformatted_code=[],
        kind="excitation",
        role="",
        file_path=str(abs_file),
        format="prose",
        heading_context="",
        scope_conditional=False,
        plain_text="The api runs on port 8001 and reloads from the source tree on every edit.",
        modality="none",
    )
    control = SimpleNamespace(
        line=5,
        position_index=1,
        text="The build uses a local cache that survives restarts.",
        charge_value=0,
        named_tokens=[],
        embedding_int8=None,
        unformatted_code=[],
        kind="excitation",
        role="",
        file_path=str(abs_file),
        format="prose",
        heading_context="",
        scope_conditional=False,
        plain_text="The build uses a local cache that survives restarts.",
        modality="none",
    )
    fake_map = SimpleNamespace(atoms=(trimmable, control), files=())
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, fake_map, None))

    location = _main_location(["CLAUDE.md"])
    location["relations"] = []
    location["findings"] = [
        {
            "rule": "CORE:C:0041",
            "file": "CLAUDE.md",
            "line": 3,
            "pi": 0,
            "message": "Excess context around the instruction.",
            "remedy": "Trim it.",
        }
    ]

    remedy_brief.build_remedy_brief(location, tmp_path)

    snap = snapshots.get_snapshot(abs_file)
    assert snap is not None

    after_finding_trimmed = "# Project\n\nThe build uses a local cache that survives restarts.\n"
    result = preservation.compare(snap, fake_map, after_finding_trimmed, score_after=None)
    assert result["lost_context"] == [
        {"line": 3, "text": "The api runs on port 8001 and reloads from the source tree on every edit."}
    ]
    assert result["ok"] is False


@pytest.mark.unit
@pytest.mark.subsys_server
def test_brief_unavailable_leaves_an_earlier_file_s_snapshot_untouched(monkeypatch, tmp_path: Path) -> None:
    """All-or-nothing: file A of a two-file location builds fine, file B yields no map — the
    whole reply is `brief_unavailable`, and A's pre-existing snapshot (from an earlier,
    fully-successful brief) must survive unchanged. A partial build must never overwrite a
    file's snapshot with one for a brief that was never delivered."""
    from reporails_cli.interfaces.mcp import snapshots

    file_a = tmp_path / "CLAUDE.md"
    file_a.write_text("# Project\n\nOriginal content kept from the earlier successful brief.\n", encoding="utf-8")
    file_b = tmp_path / "SKILL.md"
    file_b.write_text("# Skill\n", encoding="utf-8")

    # Seed A's snapshot as if an earlier, fully-successful brief already covered it.
    snapshots.snapshot_file(file_a, _fake_map(), 3.14, [])
    baseline = snapshots.get_snapshot(file_a)
    assert baseline is not None and baseline.score == 3.14

    calls = {"n": 0}

    def fake_run(path: str, full: bool = False) -> tuple[dict[str, Any], Any, float | None]:
        calls["n"] += 1
        if calls["n"] == 1:
            return {"files": {}}, _fake_map(), 9.0
        return {"error": "offline"}, None, None

    monkeypatch.setattr(tools, "run_pipeline_for_path", fake_run)
    location = _main_location(["CLAUDE.md", "SKILL.md"])

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    assert reply["error"] == "brief_unavailable"
    after = snapshots.get_snapshot(file_a)
    assert after is not None and after.score == 3.14, "A's snapshot must survive a brief the location never delivered"


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
def test_the_brief_carries_the_fixed_preservation_contract_and_a_next_step(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, _fake_map(), None))
    location = _main_location(["CLAUDE.md"])

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    assert reply["preservation_contract"] == PRESERVATION_CONTRACT
    assert reply["next"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_brief_carries_the_root_and_each_file_s_absolute_path(monkeypatch, tmp_path: Path) -> None:
    """A location names its files relative to its project root. When the healed project is not
    the caller's own cwd, that relative name alone is ambiguous — `validate(path=<file>)`
    resolves it against the MCP server's cwd, not the project's. The brief also carries the
    absolute `root` and each file's absolute `path`, so a rewrite or preservation check for a
    project rooted outside the caller's cwd can never land on the wrong file of the same name."""
    project_root = tmp_path / "elsewhere" / "project"
    project_root.mkdir(parents=True)
    abs_file = project_root / "CLAUDE.md"
    abs_file.write_text("# Project\n", encoding="utf-8")
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, _fake_map(), None))
    location = _main_location(["CLAUDE.md"])

    reply = remedy_brief.build_remedy_brief(location, project_root)

    assert reply["location"]["root"] == str(project_root)
    assert abs_file.exists()


@pytest.mark.unit
@pytest.mark.subsys_server
def test_resolve_from_root_handles_relative_and_home_paths(tmp_path: Path) -> None:
    assert remedy_brief.resolve_from_root("CLAUDE.md", tmp_path) == (tmp_path / "CLAUDE.md").resolve()
    assert (
        remedy_brief.resolve_from_root("~/.claude/CLAUDE.md", tmp_path) == (Path.home() / ".claude/CLAUDE.md").resolve()
    )


# ---------------------------------------------------------------------------
# `server._serve_remedy_brief` — state lookup, structured errors, breaker safety
# ---------------------------------------------------------------------------


def setup_module() -> None:
    server._validate_states.clear()


def teardown_module() -> None:
    server._validate_states.clear()


@pytest.mark.unit
@pytest.mark.subsys_server
def test_no_workflow_before_any_validate(tmp_path: Path) -> None:
    server._validate_states.clear()
    reply = server._serve_remedy_brief(str(tmp_path), 1, has_guide=True)
    assert reply == {
        "error": "no_workflow",
        "message": "Call validate for this path (and these targets) first; remedy_brief reads its workflow.",
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_workflow_requires_pro_when_the_last_validate_carried_no_workflow(tmp_path: Path) -> None:
    """An unpaid or offline `validate` carries no `workflow` key at all (never `None` —
    the key is simply absent). `remedy_brief` right after it must name the real cause
    (`workflow_requires_pro`) — never the `no_workflow` / "Call validate ... first" message,
    which sends the agent straight back into the `validate` it just ran and never tells it the
    brief itself is the Pro feature it lacks."""
    server._validate_states.clear()
    server._validate_states[str(tmp_path.resolve())] = server._CircuitState(
        full_payload={"files": {}}, scan_root=tmp_path
    )
    reply = server._serve_remedy_brief(str(tmp_path), 1, has_guide=True)
    assert reply["error"] == "workflow_requires_pro"
    assert "call validate" not in reply["message"].lower()
    assert "pro" in reply["message"].lower()


@pytest.mark.unit
@pytest.mark.subsys_server
def test_no_workflow_when_the_last_validate_carried_workflow_none(tmp_path: Path) -> None:
    """A distinct edge from `workflow_requires_pro`: the `workflow` key is present but not a
    dict (a malformed or null value) — still `no_workflow`, since a `workflow` key that IS
    present, just unusable, is not the tier-gated absence `workflow_requires_pro` names."""
    server._validate_states.clear()
    server._validate_states[str(tmp_path.resolve())] = server._CircuitState(
        full_payload={"files": {}, "workflow": None}, scan_root=tmp_path
    )
    reply = server._serve_remedy_brief(str(tmp_path), 1, has_guide=True)
    assert reply["error"] == "no_workflow"


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("kwargs", [{}, {"has_guide": False}])
def test_a_caller_without_the_rewrite_guide_is_told_to_update_and_nothing_runs(
    monkeypatch, tmp_path: Path, kwargs: dict[str, bool]
) -> None:
    """A caller that does not carry the rewrite guide (the reporails plugin before 0.6.2) gets
    `plugin_update_required` before any work: no pipeline run, no snapshot, and the circuit
    breaker counters stay as they were."""
    server._validate_states.clear()
    snapshots.clear_snapshots()
    target = tmp_path / "CLAUDE.md"
    target.write_text("# T\n\nAlways run the tests.\n", encoding="utf-8")

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("the pipeline must not run for a refused caller")

    monkeypatch.setattr(tools, "run_pipeline_for_path", _boom)
    payload = {"workflow": {"locations": [{"order": 1, "kind": "main", "files": ["CLAUDE.md"]}]}}
    state = server._CircuitState(full_payload=payload, scan_root=tmp_path, call_count=3, consecutive_unchanged=1)
    server._validate_states[str(tmp_path.resolve())] = state

    reply = server._serve_remedy_brief(str(tmp_path), 1, **kwargs)

    assert reply["error"] == "plugin_update_required"
    assert "reporails plugin 0.6.2 or later" in reply["message"]
    assert "your agent has to carry" not in reply["message"]
    assert snapshots.get_snapshot(target) is None
    assert (state.call_count, state.consecutive_unchanged) == (3, 1)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_caller_with_the_rewrite_guide_gets_the_brief(monkeypatch, tmp_path: Path) -> None:
    server._validate_states.clear()
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, _fake_map(), None))
    payload = {"workflow": {"locations": [{"order": 1, "kind": "other", "files": []}]}}
    server._validate_states[str(tmp_path.resolve())] = server._CircuitState(full_payload=payload, scan_root=tmp_path)

    reply = server._serve_remedy_brief(str(tmp_path), 1, has_guide=True)

    assert "error" not in reply
    assert reply["location"]["root"] == str(tmp_path)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_location_not_found_names_the_count(tmp_path: Path) -> None:
    server._validate_states.clear()
    payload = {"workflow": {"locations": [{"order": 1, "kind": "main", "files": []}]}}
    server._validate_states[str(tmp_path.resolve())] = server._CircuitState(full_payload=payload, scan_root=tmp_path)

    reply = server._serve_remedy_brief(str(tmp_path), 9, has_guide=True)

    assert reply == {
        "error": "location_not_found",
        "message": "The workflow has no location 9; it has 1.",
    }


@pytest.mark.unit
@pytest.mark.subsys_server
def test_serve_remedy_brief_resets_call_count_but_leaves_consecutive_unchanged(monkeypatch, tmp_path: Path) -> None:
    """A served brief resets `call_count` (the agent is still working the loop) every
    time it is served; `consecutive_unchanged` — the actual no-progress guard — is untouched."""
    server._validate_states.clear()
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, _fake_map(), None))
    payload = {"workflow": {"locations": [{"order": 1, "kind": "other", "files": []}]}}
    state = server._CircuitState(full_payload=payload, scan_root=tmp_path, call_count=3, consecutive_unchanged=1)
    server._validate_states[str(tmp_path.resolve())] = state

    for _ in range(4):
        reply = server._serve_remedy_brief(str(tmp_path), 1, has_guide=True)
        assert "error" not in reply
        after = server._validate_states[str(tmp_path.resolve())]
        assert (after.call_count, after.consecutive_unchanged) == (0, 1)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_only_relation_lines_of_the_file_are_deletable() -> None:
    relations = [{"file": "CLAUDE.md", "line": 4}, {"file": "OTHER.md", "line": 9}]
    assert remedy_brief._relation_lines("CLAUDE.md", relations) == [4]


# ── findings from review: the real brief path ────────────────────────────


def _atom(file: Path, line: int, text: str, pi: int = 0, fmt: str = "prose") -> Any:
    return SimpleNamespace(
        line=line,
        position_index=pi,
        text=text,
        charge_value=0,
        named_tokens=["`foo`"],
        embedding_int8=None,
        unformatted_code=[],
        kind="excitation",
        role="",
        file_path=str(file),
        format=fmt,
        heading_context="",
        scope_conditional=False,
        plain_text=text,
        modality="none",
        lead_in="",
        list_depth=0,
    )


def _op_location(op: str, line: int, expect: dict[str, Any]) -> dict[str, Any]:
    return {
        "order": 1,
        "element": "CLAUDE.md",
        "kind": "main",
        "loading": "session_start",
        "files": ["CLAUDE.md"],
        "importance": "gate_mover",
        "findings": [{"rule": "CORE:C:0058", "file": "CLAUDE.md", "line": line, "pi": 0, "op": op, "expect": expect}],
        "relations": [],
    }


def _brief_with(monkeypatch, tmp_path: Path, text: str, atoms: list[Any], location: dict[str, Any]) -> dict[str, Any]:
    snapshots.clear_snapshots()
    (tmp_path / "CLAUDE.md").write_text(text, encoding="utf-8")
    fake_map = SimpleNamespace(atoms=tuple(atoms), files=())
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, fake_map, None))
    return remedy_brief.build_remedy_brief(location, tmp_path, fake_map)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_deduped_line_s_edit_removes_its_line_break_through_the_real_brief(monkeypatch, tmp_path: Path) -> None:
    text = "# T\n\nDup `foo` line.\n\nKeep `foo`.\n"
    atoms = [_atom(tmp_path / "CLAUDE.md", 3, "Dup `foo` line."), _atom(tmp_path / "CLAUDE.md", 5, "Keep `foo`.")]
    reply = _brief_with(monkeypatch, tmp_path, text, atoms, _op_location("dedupe", 3, {"keep": ["CLAUDE.md", 5]}))
    (edit,) = reply["edits"]
    assert text.replace(edit["before"], edit["after"], 1) == "# T\n\nKeep `foo`.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_named_move_becomes_an_exact_edit(monkeypatch, tmp_path: Path) -> None:
    text = "# T\n\n- one\n- two\n- three\n"
    file = tmp_path / "CLAUDE.md"
    atoms = [_atom(file, n, t, fmt="list") for n, t in ((3, "one"), (4, "two"), (5, "three"))]
    reply = _brief_with(monkeypatch, tmp_path, text, atoms, _op_location("move", 5, {"after": ["CLAUDE.md", 3]}))
    assert reply["slots"] == []
    (edit,) = reply["edits"]
    assert text.replace(edit["before"], edit["after"], 1) == "# T\n\n- one\n- three\n- two\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_file_whose_imports_expand_gets_no_exact_edits(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "extra.md").write_text("Imported `foo` one.\nImported two.\n", encoding="utf-8")
    text = "@extra.md\n\nDup `foo` line.\n\nKeep `foo`.\n"
    file = tmp_path / "CLAUDE.md"
    # atom lines count the imported lines, so the dup sits at expanded line 5
    atoms = [_atom(file, 5, "Dup `foo` line."), _atom(file, 7, "Keep `foo`.")]
    reply = _brief_with(monkeypatch, tmp_path, text, atoms, _op_location("dedupe", 5, {"keep": ["CLAUDE.md", 7]}))
    assert reply["edits"] == []
    assert [r["reason"] for r in reply["refused"]] == ["imports_expand"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_asking_for_the_same_brief_again_keeps_the_original_baseline(monkeypatch, tmp_path: Path) -> None:
    text = "# T\n\nDup `foo` line.\n\nKeep `foo`.\n"
    file = tmp_path / "CLAUDE.md"
    atoms = [_atom(file, 3, "Dup `foo` line."), _atom(file, 5, "Keep `foo`.")]
    location = _op_location("dedupe", 3, {"keep": ["CLAUDE.md", 5]})
    first = _brief_with(monkeypatch, tmp_path, text, atoms, location)
    plan = snapshots.get_plan(file)
    file.write_text("# T\n\nKeep `foo`.\n", encoding="utf-8")  # the agent applied the edit
    again = remedy_brief.build_remedy_brief(location, tmp_path, SimpleNamespace(atoms=tuple(atoms), files=()))
    snap = snapshots.get_snapshot(file)
    assert snap is not None and snap.text == text
    assert snapshots.get_plan(file) is plan
    assert again["edits"] == first["edits"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_slot_s_line_is_its_line_after_the_plan_s_edits(monkeypatch, tmp_path: Path) -> None:
    from reporails_cli.core.heal.conformance import check_plan

    text = "# T\n\nDup `foo` line.\n\nKeep `foo`.\n\nOther thing.\n"
    file = tmp_path / "CLAUDE.md"
    atoms = [_atom(file, 3, "Dup `foo` line."), _atom(file, 5, "Keep `foo`."), _atom(file, 7, "Other thing.")]
    location = _op_location("dedupe", 3, {"keep": ["CLAUDE.md", 5]})
    location["findings"].append(
        {"rule": "CORE:C:0042", "file": "CLAUDE.md", "line": 7, "pi": 0, "op": "elaborate", "expect": {}}
    )
    reply = _brief_with(monkeypatch, tmp_path, text, atoms, location)
    (edit,) = reply["edits"]
    (slot,) = reply["slots"]
    after_edits = text.replace(edit["before"], edit["after"], 1).splitlines()
    assert after_edits[slot["line"] - 1] == "Other thing."
    rewritten = [*after_edits[:-1], "Other thing, said once."]
    plan = snapshots.get_plan(file)
    assert plan is not None
    key = str(file)
    assert check_plan(plan, {key: text.splitlines()}, {key: rewritten}, {key: []}) == []


@pytest.mark.unit
@pytest.mark.subsys_server
def test_an_edit_s_before_occurs_once_in_the_file(monkeypatch, tmp_path: Path) -> None:
    text = "# T\n\nSame `foo` line.\n\nOther.\n\nSame `foo` line.\n"
    file = tmp_path / "CLAUDE.md"
    atoms = [_atom(file, 3, "Same `foo` line."), _atom(file, 7, "Same `foo` line.")]
    reply = _brief_with(monkeypatch, tmp_path, text, atoms, _op_location("dedupe", 7, {"keep": ["CLAUDE.md", 3]}))
    (edit,) = reply["edits"]
    assert text.count(edit["before"]) == 1
    assert text.replace(edit["before"], edit["after"], 1) == "# T\n\nSame `foo` line.\n\nOther.\n"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_brief_after_a_project_validate_takes_a_fresh_baseline(monkeypatch, tmp_path: Path) -> None:
    import asyncio

    text = "# T\n\nDup `foo` line.\n\nKeep `foo`.\n"
    file = tmp_path / "CLAUDE.md"
    atoms = [_atom(file, 3, "Dup `foo` line."), _atom(file, 5, "Keep `foo`.")]
    location = _op_location("dedupe", 3, {"keep": ["CLAUDE.md", 5]})
    fake_map = SimpleNamespace(atoms=tuple(atoms), files=())
    _brief_with(monkeypatch, tmp_path, text, atoms, location)
    edited = "# T\n\nKeep `foo`.\n"
    file.write_text(edited, encoding="utf-8")
    monkeypatch.setattr(server, "model_not_ready_error", lambda: None)
    monkeypatch.setattr(server, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, fake_map, None))
    server._validate_states.clear()
    asyncio.run(server._run_validate(str(tmp_path), True))
    remedy_brief.build_remedy_brief(location, tmp_path, fake_map)
    snap = snapshots.get_snapshot(file)
    assert snap is not None and snap.text == edited
