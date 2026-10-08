"""`remedy_brief(path, location)` — the full rewrite brief for one workflow location.

`remedy_brief.remedy_brief_tool` builds the brief from an already-resolved location dict (as the
stored `validate` payload carries it, already relative-pathed) and a scan root; it runs the
same single-file pipeline `validate(path=<file>)` runs for each of the location's files.
`server._serve_remedy_brief` is the thin state-lookup wrapper: `no_workflow` / `workflow_requires_pro` /
`location_not_found` structured errors, and a served brief resets the path's call count.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.core.heal.preservation import PRESERVATION_CONTRACT
from reporails_cli.interfaces.mcp import remedy_brief, server, tools
from reporails_cli.interfaces.mcp.remedy_brief_paging import page_reply

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
@requires_model
@requires_rules
def test_the_brief_shapes_files_findings_relations_and_inventory(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(
        "# Project\n\nRun `pytest` before committing.\n\n## Testing\n\nKeep tests fast.\n", encoding="utf-8"
    )
    location = _main_location(["CLAUDE.md"])

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    assert reply["location"] == {
        "order": 1,
        "element": "CLAUDE.md",
        "kind": "main",
        "loading": "session_start",
        "importance": "gate_mover",
        "files": ["CLAUDE.md"],
        "root": str(tmp_path),
    }
    assert "findings" not in reply["location"] and "relations" not in reply["location"]

    # findings/relations pass through as given — already relative from the stored payload.
    assert reply["findings"] == location["findings"]
    assert reply["relations"] == location["relations"]

    (file_entry,) = reply["files"]
    assert file_entry["file"] == "CLAUDE.md"
    assert file_entry["path"] == str((tmp_path / "CLAUDE.md").resolve())
    assert file_entry["loading"] == "session_start"
    # The test suite runs offline (no diagnostics server): a file's display score comes from
    # the server, so it is `None` here — null means the file went unscored.
    assert file_entry["score"] is None

    instr_texts = {e["text"]: e for e in file_entry["instructions"]}
    assert "Run `pytest` before committing." in instr_texts
    run_entry = instr_texts["Run `pytest` before committing."]
    assert run_entry["polarity"] in (-1, 0, 1)
    assert "pytest" in run_entry["named"]
    assert "Keep tests fast." in instr_texts

    headings = {e["text"]: e["depth"] for e in file_entry["headings"]}
    assert headings == {"Project": 1, "Testing": 2}


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
@requires_model
def test_the_brief_no_longer_carries_the_ideal_instruction_guide(tmp_path: Path) -> None:
    """The guide is the same for every location, so the remedy agent definition carries it
    (`ideal_instruction_markdown`) and no part of a brief repeats it."""
    (tmp_path / "CLAUDE.md").write_text("# Project\n\nRun tests before committing.\n", encoding="utf-8")
    location = _main_location(["CLAUDE.md"])

    first = remedy_brief.remedy_brief_tool(location, tmp_path, part=1)

    for part_number in range(1, first.get("total_parts", 1) + 1):
        reply = remedy_brief.remedy_brief_tool(location, tmp_path, part=part_number)
        assert "ideal_instruction" not in reply
        assert "ideal_instruction_parts" not in reply
    (file_entry,) = first["files"]
    assert file_entry["file"] == "CLAUDE.md"


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
@requires_model
@requires_rules
def test_a_large_file_s_brief_pages_under_the_client_limit(tmp_path: Path) -> None:
    """A 632-line skill's brief measured 67,098 chars — over the client's MCP output cap,
    with no way for a shell-less remedy agent to read the rest. A location whose single file is
    at least 650 lines must page: part 1 stays comfortably under 20,000 chars, and every part's
    `files[]`, concatenated in order, carries the whole brief (every instruction the file has)."""
    lines = ["---", "name: big-skill", "description: A very large skill.", "---", ""]
    lines.extend(
        f"Step {i}: run the browser action number {i} and record the resulting page state." for i in range(700)
    )
    skill_dir = tmp_path / ".claude" / "skills" / "big-skill"
    skill_dir.mkdir(parents=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rel = ".claude/skills/big-skill/SKILL.md"
    location = {
        "order": 1,
        "element": ".claude/skills/big-skill",
        "kind": "skills",
        "loading": "on_demand",
        "importance": "conditional",
        "files": [rel],
        "findings": [],
        "relations": [],
    }

    first = remedy_brief.remedy_brief_tool(location, tmp_path, part=1)
    first_size = len(json.dumps(first, separators=(",", ":")))
    assert first_size < 20_000, f"part 1 is {first_size} chars, over the client cap"

    total_parts = first.get("total_parts", 1)
    assert total_parts > 1, "a 700-instruction single-file location must actually page"

    collected: list[Any] = []
    for part_number in range(1, total_parts + 1):
        reply = remedy_brief.remedy_brief_tool(location, tmp_path, part=part_number)
        assert reply["part"] == part_number
        assert reply["total_parts"] == total_parts
        size = len(json.dumps(reply, separators=(",", ":")))
        assert size < 20_000, f"part {part_number} is {size} chars, over the client cap"
        for entry in reply["files"]:
            assert entry["file"] == rel
            collected.extend(entry["instructions"])

    assert len(collected) == 700
    assert first["next_part"]
    last = remedy_brief.remedy_brief_tool(location, tmp_path, part=total_parts)
    assert "next_part" not in last


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
@requires_rules
def test_artifact_rules_are_only_capability_specific_never_universal() -> None:
    from reporails_cli.core.platform.adapters.rules_query import load_all_rules

    block = remedy_brief.artifact_rules_for_kind("skills")
    assert block is not None and block["capability"] == "skills"
    assert block["rules"], "the skill capability must have at least one artifact rule"

    by_id = {r.id: r for r in load_all_rules()}
    for entry in block["rules"]:
        rule = by_id[entry["id"]]
        assert rule.match is not None and rule.match.type is not None, (
            f"{entry['id']} is a universal rule (no match.type) and must not appear in artifact_rules"
        )


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
def test_artifact_rules_omitted_for_a_type_no_rule_names() -> None:
    assert remedy_brief.artifact_rules_for_kind("generic") is None
    assert remedy_brief.artifact_rules_for_kind("unknown-kind") is None


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
def test_artifact_rules_scope_to_the_named_agents_not_every_agent() -> None:
    """`main` unscoped pulls in every known agent's namespace rules (`CURSOR:S:0006`,
    `CODEX:S:0001`, `COPILOT:S:0002`, ...) — scoped to the location's own files' agent, only
    CORE plus that agent's rules must come back, so the rewrite agent never gets another
    agent's pass/fail examples."""
    unscoped = remedy_brief.artifact_rules_for_kind("main")
    unscoped_ids = {e["id"] for e in unscoped["rules"]}
    assert any(i.startswith(("CURSOR:", "CODEX:", "COPILOT:")) for i in unscoped_ids), (
        "sanity: the unscoped call must still pull in another agent's rules"
    )

    scoped = remedy_brief.artifact_rules_for_kind("main", ["claude"])
    scoped_ids = {e["id"] for e in scoped["rules"]}
    assert not any(i.startswith(("CURSOR:", "CODEX:", "COPILOT:", "ANTIGRAVITY:")) for i in scoped_ids)


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
def test_the_brief_scopes_artifact_rules_to_the_files_own_agent(monkeypatch, tmp_path: Path) -> None:
    """End to end: `remedy_brief_tool` reads each file's `FileRecord.agent` off its own map
    and passes that through to `artifact_rules_for_kind`, instead of loading every agent."""
    abs_file = tmp_path / "CLAUDE.md"
    abs_file.write_text("# Project\n", encoding="utf-8")
    fake_map = _fake_map(files=(SimpleNamespace(path=str(abs_file), agent="cursor", loading="session_start"),))
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, fake_map, None))
    location = _main_location(["CLAUDE.md"])

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    ids = {e["id"] for e in reply["artifact_rules"]["rules"]}
    assert not any(i.startswith(("CODEX:", "COPILOT:", "ANTIGRAVITY:")) for i in ids)


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

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

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

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

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

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

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

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    assert "error" not in reply
    (file_entry,) = reply["files"]
    assert file_entry["file"] == ".claude/skills/presentation/writing/SKILL.md"
    assert reply["findings"] == location["findings"]


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

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

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

    remedy_brief.remedy_brief_tool(location, tmp_path)

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

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    assert reply["error"] == "brief_unavailable"
    after = snapshots.get_snapshot(file_a)
    assert after is not None and after.score == 3.14, "A's snapshot must survive a brief the location never delivered"


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
def test_the_brief_carries_the_fixed_preservation_contract_and_a_next_step(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, _fake_map(), None))
    location = _main_location(["CLAUDE.md"])

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    assert reply["preservation_contract"] == PRESERVATION_CONTRACT
    assert reply["next"]


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_rules
def test_the_brief_omits_artifact_rules_for_a_location_of_kind_other(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, _fake_map(), None))
    location = {**_main_location(["extra.md"]), "kind": "other"}

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    assert "artifact_rules" not in reply


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

    reply = remedy_brief.remedy_brief_tool(location, project_root)

    assert reply["location"]["root"] == str(project_root)
    (file_entry,) = reply["files"]
    assert file_entry["path"] == str(abs_file)
    assert Path(file_entry["path"]).exists()


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_brief_orders_findings_weakest_first_by_impact_tier(monkeypatch, tmp_path: Path) -> None:
    """A location's `findings` are ordered gate_mover -> conditional -> cosmetic -> "" —
    weight, never line order, is the primary key. A cosmetic finding on an earlier line must
    not sort ahead of a gate_mover finding on a later one."""
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, _fake_map(), None))
    location = _main_location(["CLAUDE.md"])
    location["relations"] = []
    location["findings"] = [
        {
            "rule": "RULE:COSMETIC",
            "file": "CLAUDE.md",
            "line": 3,
            "pi": 0,
            "message": "m1",
            "remedy": "r1",
            "impact_tier": "cosmetic",
        },
        {
            "rule": "RULE:CONDITIONAL",
            "file": "CLAUDE.md",
            "line": 8,
            "pi": 0,
            "message": "m2",
            "remedy": "r2",
            "impact_tier": "conditional",
        },
        {
            "rule": "RULE:GATE",
            "file": "CLAUDE.md",
            "line": 20,
            "pi": 0,
            "message": "m3",
            "remedy": "r3",
            "impact_tier": "gate_mover",
        },
        {
            "rule": "RULE:UNKNOWN",
            "file": "CLAUDE.md",
            "line": 1,
            "pi": 0,
            "message": "m4",
            "remedy": "r4",
        },
    ]

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    assert [f["rule"] for f in reply["findings"]] == ["RULE:GATE", "RULE:CONDITIONAL", "RULE:COSMETIC", "RULE:UNKNOWN"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_brief_marks_each_instruction_with_the_rule_ids_that_target_its_line(monkeypatch, tmp_path: Path) -> None:
    """A `files[].instructions` entry sharing a finding's line carries `targets`, the rule
    ids of every finding on that line, weakest-first. An instruction no finding names is left
    without a `targets` key."""
    abs_file = tmp_path / "CLAUDE.md"
    abs_file.write_text("# Project\n\nFirst instruction.\n\nUntargeted instruction.\n\nSecond instruction.\n")
    first = SimpleNamespace(
        line=3,
        position_index=0,
        text="First instruction.",
        charge_value=1,
        named_tokens=[],
        embedding_int8=None,
        unformatted_code=[],
        kind="excitation",
        role="",
        file_path=str(abs_file),
        format="prose",
        heading_context="",
        scope_conditional=False,
        plain_text="First instruction.",
        modality="direct",
    )
    untargeted = SimpleNamespace(
        line=5,
        position_index=1,
        text="Untargeted instruction.",
        charge_value=1,
        named_tokens=[],
        embedding_int8=None,
        unformatted_code=[],
        kind="excitation",
        role="",
        file_path=str(abs_file),
        format="prose",
        heading_context="",
        scope_conditional=False,
        plain_text="Untargeted instruction.",
        modality="direct",
    )
    second = SimpleNamespace(
        line=7,
        position_index=2,
        text="Second instruction.",
        charge_value=1,
        named_tokens=[],
        embedding_int8=None,
        unformatted_code=[],
        kind="excitation",
        role="",
        file_path=str(abs_file),
        format="prose",
        heading_context="",
        scope_conditional=False,
        plain_text="Second instruction.",
        modality="direct",
    )
    fake_map = SimpleNamespace(atoms=(first, untargeted, second), files=())
    monkeypatch.setattr(tools, "run_pipeline_for_path", lambda path, full=False: ({"files": {}}, fake_map, None))

    location = _main_location(["CLAUDE.md"])
    location["relations"] = []
    location["findings"] = [
        {
            "rule": "RULE:COSMETIC",
            "file": "CLAUDE.md",
            "line": 7,
            "pi": 2,
            "message": "m1",
            "remedy": "r1",
            "impact_tier": "cosmetic",
        },
        {
            "rule": "RULE:GATE",
            "file": "CLAUDE.md",
            "line": 3,
            "pi": 0,
            "message": "m2",
            "remedy": "r2",
            "impact_tier": "gate_mover",
        },
    ]

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    by_text = {e["text"]: e for e in reply["files"][0]["instructions"]}
    assert by_text["First instruction."]["targets"] == ["RULE:GATE"]
    assert by_text["Second instruction."]["targets"] == ["RULE:COSMETIC"]
    assert "targets" not in by_text["Untargeted instruction."]


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
    reply = server._serve_remedy_brief(str(tmp_path), 1)
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
    reply = server._serve_remedy_brief(str(tmp_path), 1)
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
    reply = server._serve_remedy_brief(str(tmp_path), 1)
    assert reply["error"] == "no_workflow"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_location_not_found_names_the_count(tmp_path: Path) -> None:
    server._validate_states.clear()
    payload = {"workflow": {"locations": [{"order": 1, "kind": "main", "files": []}]}}
    server._validate_states[str(tmp_path.resolve())] = server._CircuitState(full_payload=payload, scan_root=tmp_path)

    reply = server._serve_remedy_brief(str(tmp_path), 9)

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
        reply = server._serve_remedy_brief(str(tmp_path), 1)
        assert "error" not in reply
        after = server._validate_states[str(tmp_path.resolve())]
        assert (after.call_count, after.consecutive_unchanged) == (0, 1)


def _big_skill_workflow(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    """A single 700-instruction `SKILL.md` big enough that its brief pages into several
    parts (mirrors `test_a_large_file_s_brief_pages_under_the_client_limit`'s fixture), wired
    as a one-location `validate` workflow payload ready to drop onto a `_CircuitState`."""
    lines = ["---", "name: big-skill", "description: A very large skill.", "---", ""]
    lines.extend(
        f"Step {i}: run the browser action number {i} and record the resulting page state." for i in range(700)
    )
    skill_dir = tmp_path / ".claude" / "skills" / "big-skill"
    skill_dir.mkdir(parents=True)
    skill_file = skill_dir / "SKILL.md"
    skill_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    rel = ".claude/skills/big-skill/SKILL.md"
    payload = {
        "tier": "pro",
        "workflow": {
            "locations": [
                {
                    "order": 1,
                    "element": ".claude/skills/big-skill",
                    "kind": "skills",
                    "loading": "on_demand",
                    "importance": "conditional",
                    "files": [rel],
                    "findings": [],
                    "relations": [],
                }
            ]
        },
    }
    return skill_file, payload


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
@requires_rules
def test_paged_remedy_brief_is_built_once_not_once_per_part(monkeypatch, tmp_path: Path) -> None:
    """`server._serve_remedy_brief` used to rebuild the WHOLE brief — re-running
    the location's own file pipeline (one server `diagnose` per file) and re-committing the
    preservation snapshot — on EVERY `part` call, so a 28-part brief cost 28 pipeline runs
    instead of 1. Fetching every part of a multi-part brief must cost exactly the same number
    of pipeline runs as fetching part 1 alone: the brief is built once per (path, targets,
    location) and every later part is served from that one build."""
    skill_file, payload = _big_skill_workflow(tmp_path)
    server._validate_states.clear()
    server._validate_states[str(tmp_path.resolve())] = server._CircuitState(full_payload=payload, scan_root=tmp_path)

    real_run = tools.run_pipeline_for_path
    calls = {"n": 0}

    def counting_run(path: str, full: bool = False) -> tuple[dict[str, Any], Any, float | None]:
        calls["n"] += 1
        return real_run(path, full)

    monkeypatch.setattr(tools, "run_pipeline_for_path", counting_run)

    first = server._serve_remedy_brief(str(tmp_path), 1)
    total_parts = first.get("total_parts", 1)
    assert total_parts > 1, "a 700-instruction single-file location must actually page"
    calls_for_part_one_alone = calls["n"]
    assert calls_for_part_one_alone == 1, "one file, one pipeline run, to build the whole brief"

    for part_number in range(2, total_parts + 1):
        reply = server._serve_remedy_brief(str(tmp_path), 1, part=part_number)
        assert reply["part"] == part_number

    assert calls["n"] == calls_for_part_one_alone, (
        f"fetching all {total_parts} parts cost {calls['n']} pipeline runs; "
        f"fetching part 1 alone cost {calls_for_part_one_alone}"
    )
    assert skill_file.exists()  # sanity: the fixture file itself is untouched by this test


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
@requires_rules
def test_editing_the_file_between_parts_leaves_the_committed_snapshot_untouched(tmp_path: Path) -> None:
    """Because a rebuild-per-part re-ran the file pipeline against whatever the
    file held AT THAT MOMENT, it also re-committed the preservation snapshot on every part call
    — so if the agent edited the file between two part calls (entirely plausible: paging exists
    so the agent can read a brief across several turns), the next part call silently overwrote
    the snapshot with the EDITED text, corrupting the baseline a later
    `validate(path=<file>)` preservation check compares against. Serving part 2 from the
    part-1 build must leave the snapshot exactly the pre-edit text."""
    from reporails_cli.interfaces.mcp import snapshots

    skill_file, payload = _big_skill_workflow(tmp_path)
    original_text = skill_file.read_text(encoding="utf-8")
    server._validate_states.clear()
    server._validate_states[str(tmp_path.resolve())] = server._CircuitState(full_payload=payload, scan_root=tmp_path)

    first = server._serve_remedy_brief(str(tmp_path), 1)
    total_parts = first.get("total_parts", 1)
    assert total_parts > 1, "a 700-instruction single-file location must actually page"
    assert snapshots.get_snapshot(skill_file).text == original_text

    skill_file.write_text(original_text + "\nEdited after part 1, before part 2.\n", encoding="utf-8")

    reply = server._serve_remedy_brief(str(tmp_path), 1, part=2)

    assert reply["part"] == 2
    assert snapshots.get_snapshot(skill_file).text == original_text, (
        "part 2 must not have re-run the pipeline against the edited file and re-snapshotted it"
    )


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
@requires_rules
def test_the_procedure_serves_the_location_s_own_well_formed_line_fixes_and_writes_nothing(tmp_path: Path) -> None:
    """The brief's `procedure` lists the deterministic line fixes for the location's own files
    only, then the kind's rules in the order to work them. Nothing is written. A basename
    detected inside a longer path backticks the full relative path (not a partial span
    `_well_formed` would withhold); a line whose constraint already carries bold emphasis is
    left as its own clean single-emphasis state rather than nested into italic."""
    main = tmp_path / "CLAUDE.md"
    main.write_text(
        "# Project\n\nRun the checks in tests/unit/test_parser.py before committing.\n\n"
        "**Never** commit secrets to the repo.\n\nNever commit **production** keys.\n",
        encoding="utf-8",
    )
    other = tmp_path / ".claude" / "rules" / "keys.md"
    other.parent.mkdir(parents=True)
    other.write_text("# Keys\n\nNever commit **staging** keys.\n", encoding="utf-8")
    before = {p: p.read_bytes() for p in (main, other)}
    location = {**_main_location(["CLAUDE.md"]), "findings": [], "relations": []}

    reply = remedy_brief.remedy_brief_tool(location, tmp_path)

    fixes = reply["procedure"]["mechanical_fixes"]
    assert [(f["path"], f["line"], f["after"]) for f in fixes] == [
        (str(main.resolve()), 3, "Run the checks in `tests/unit/test_parser.py` before committing."),
        (str(main.resolve()), 7, "Never commit *production* keys."),
    ]
    assert reply["procedure"]["rules"] == [e["id"] for e in reply["artifact_rules"]["rules"]]
    assert {p: p.read_bytes() for p in (main, other)} == before


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("before", "after", "served"),
    [
        ("Run tests/unit/test_x.py first.", "Run tests/unit/`test_x.py` first.", False),
        ("Run test_x.py first.", "Run `test_x.py` first.", True),
        ("**Never** commit secrets.", "***Never** commit secrets.*", False),
        ("Never commit secrets.", "*Never commit secrets.*", True),
        ("Never commit **prod** keys.", "Never commit *prod* keys.", True),
        # a glob star at the end of the line is no italic run, so the bold before it is no nesting:
        ("Keep **Note** and never edit build/*", "Keep **Note** and never edit build/*", True),
        ("Keep **Note** and never edit src.", "Keep **Note** and *never edit src.*", False),
        # Real cases: the italic fixer re-wraps a line already wrapped once (or a bold-to-italic
        # fix lands on an already-bolded line), stacking another `*` onto the run instead of
        # replacing it — a real agent-instruction file's already-bolded constraint line:
        (
            "- ***Do not guess from names.** If the docs don't mention MCP, … source of truth.*",
            "- ****Do not guess from names.** … source of truth.**",
            False,
        ),
        # The first of three chained fixes on the same line (*** → **** → ***** → ******); the
        # same-line chaining withholds the rest once this one is withheld:
        (
            "- ***Never trust unverified input.** validate everything.*",
            "- ****Never trust unverified input.** validate everything.**",
            False,
        ),
        # A real rule-instruction file's already double-bolded constraint line:
        (
            "- ****G3 No jargon**: user-facing text in `rule.md` must NOT contain internal terms "
            "(`derivation chain`, `step1 constraint`).**",
            "- *****G3 No jargon**: user-facing text in `rule.md` must NOT contain internal terms "
            "(`derivation chain`, `step1 constraint`).***",
            False,
        ),
    ],
)
def test_a_line_fix_is_served_only_when_it_reads_as_intended(before: str, after: str, served: bool) -> None:
    assert remedy_brief._well_formed(before, after) is served


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("text", "partial", "run"),
    [
        ("Run `pytest` now", False, 0),
        ("Run tests/unit/`x.py` now", True, 0),
        ("Run `a`b now", True, 0),
        # a double-backtick span holds a single backtick and the stars inside it
        ("Use ``a ` b**`` here", False, 0),
        ("Use ``a ` b**`` and ***bold***", False, 3),
        ("Run ``a``b now", True, 0),
        # an unmatched backtick opens no span: the stars after it are plain text
        ("a ` b ** c", False, 2),
        # an escaped backtick is text, not a span edge
        ("a \\`b** c\\` d", False, 2),
    ],
)
def test_code_spans_are_read_as_the_markdown_parse_reads_them(text: str, partial: bool, run: int) -> None:
    assert remedy_brief._has_partial_code_span(text) is partial
    assert remedy_brief._max_asterisk_run(text) == run


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_later_fix_chained_onto_a_withheld_line_is_also_withheld() -> None:
    """`apply_mechanical_fixes(dry_run=True)` runs its fixers in sequence on the same in-memory
    lines, so a later fix on a line has the earlier fix's output as its `before`. Once the
    backtick fix on line 7 is withheld (it backticks only part of a path), the italic fix that
    comes after it on the SAME line was built on text the file never has — its `before` already
    carries the withheld backtick. No fix is served for that line; an unrelated line is untouched."""
    fixes = [
        SimpleNamespace(
            line=7,
            before="Run tests/unit/test_parser.py before committing.",
            after="Run tests/unit/`test_parser.py` before committing.",
        ),
        SimpleNamespace(
            line=7,
            before="Run tests/unit/`test_parser.py` before committing.",
            after="*Run tests/unit/`test_parser.py` before committing.*",
        ),
        SimpleNamespace(
            line=3,
            before="Never commit **production** keys.",
            after="Never commit *production* keys.",
        ),
    ]

    kept = remedy_brief._drop_chained_after_withheld(fixes)

    assert [f.line for f in kept] == [3]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_two_concurrent_part_requests_for_one_location_build_the_brief_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading
    import time

    server._validate_states.clear()
    payload = {"workflow": {"locations": [{"order": 1, "kind": "main", "files": []}]}}
    server._validate_states[str(tmp_path.resolve())] = server._CircuitState(full_payload=payload, scan_root=tmp_path)
    builds: list[int] = []

    def slow_build(loc: dict, root: Path) -> tuple:
        builds.append(1)
        time.sleep(0.2)
        return ("full", [], {})

    monkeypatch.setattr(server, "build_remedy_brief", slow_build)
    monkeypatch.setattr(server, "page_reply", lambda *a, **k: {"ok": True})
    threads = [threading.Thread(target=server._serve_remedy_brief, args=(str(tmp_path), 1)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)
    assert builds == [1]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_only_relation_lines_of_the_file_are_deletable() -> None:
    relations = [{"file": "CLAUDE.md", "line": 4}, {"file": "OTHER.md", "line": 9}]
    assert remedy_brief._relation_lines("CLAUDE.md", relations) == [4]


def _synthetic_brief(instruction_count: int) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """A hand-built brief: one file of `instruction_count` instructions."""
    location_out = {"order": 1, "element": "CLAUDE.md", "files": ["CLAUDE.md"], "root": "/tmp/project"}
    file_entry = {
        "file": "CLAUDE.md",
        "instructions": [{"text": f"Instruction {i} " + "x" * 120} for i in range(instruction_count)],
        "headings": [],
    }
    full = {
        "location": location_out,
        "procedure": "p" * 300,
        "files": [file_entry],
        "findings": [],
        "relations": [],
    }
    return full, [file_entry], location_out


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("instruction_count", [118, 119, 400])
def test_every_part_of_a_paged_brief_stays_under_the_stated_size(instruction_count: int) -> None:
    """A part is sized as the whole reply, location and paging fields included, so no part of a
    brief runs past the 16,000-character target."""
    full, files_out, location_out = _synthetic_brief(instruction_count)
    total = page_reply(full, files_out, location_out, 1)["total_parts"]
    for number in range(1, total + 1):
        reply = page_reply(full, files_out, location_out, number)
        size = len(json.dumps(reply, separators=(",", ":")))
        assert size <= 16_000, f"part {number} of {total} is {size} characters"


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("past_last", [0, -1, 1, 50])
def test_a_part_outside_the_brief_is_an_error_naming_the_valid_range(past_last: int) -> None:
    """Asking for part 0, a negative part or a part past the last one is an error that names
    the valid range, not the last part served again."""
    full, files_out, location_out = _synthetic_brief(400)
    total = page_reply(full, files_out, location_out, 1)["total_parts"]
    part = past_last if past_last <= 0 else total + past_last
    reply = page_reply(full, files_out, location_out, part)
    assert reply["error"] == "part_out_of_range"
    assert f"1 to {total}" in reply["message"]
    assert "part" not in reply


def _real_shaped_brief(
    *,
    artifact_rules_chars: int = 11_964,
    procedure_rules: int = 20,
    fixes: int = 20,
    fix_chars: int = 150,
    files: int = 1,
    instructions: list[int] | None = None,
    headings: int = 0,
    heading_chars: int = 60,
    findings: int = 0,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]:
    """A brief shaped like a root instruction file's: fixed fields larger than one part,
    headings, instructions of very different lengths, and (optionally) many files, findings and
    line fixes."""
    sizes = instructions if instructions is not None else [30, 400, 90, 1_500, 60, 250] * 20
    names = [f"docs/file-{i}.md" for i in range(files)]
    location_out = {"order": 1, "element": "CLAUDE.md", "files": names, "root": "/tmp/project"}
    entries = [
        {
            "file": name,
            "path": f"/tmp/project/{name}",
            "instructions": [{"line": i, "text": f"{name} {i} " + "x" * n} for i, n in enumerate(sizes)],
            "headings": [{"line": i, "text": f"{name} h{i} " + "h" * heading_chars} for i in range(headings)],
        }
        for name in names
    ]
    found = [{"file": names[i % len(names)], "line": i, "message": "m" * 150} for i in range(findings)]
    full = {
        "location": location_out,
        "files": entries,
        "findings": found,
        "relations": [],
        "preservation_contract": "c" * 640,
        "next": "n" * 430,
        "procedure": {
            "mechanical_fixes": [
                {"file": names[0], "line": i, "before": "b" * fix_chars, "after": "a" * fix_chars} for i in range(fixes)
            ],
            "rules": [f"rule-{i}" for i in range(procedure_rules)],
        },
        "artifact_rules": {"rules": [{"id": "r", "text": "t" * artifact_rules_chars}]},
    }
    return full, entries, location_out


def _all_parts(full: dict[str, Any], files_out: list[dict[str, Any]], location_out: dict[str, Any]) -> list[Any]:
    total = page_reply(full, files_out, location_out, 1).get("total_parts", 1)
    return [page_reply(full, files_out, location_out, n) for n in range(1, total + 1)]


def _part_is_empty(reply: dict[str, Any]) -> bool:
    carries = (
        reply["files"],
        reply["findings"],
        reply["relations"],
        (reply.get("procedure") or {}).get("mechanical_fixes"),
        [k for k in reply if k not in _PART_BOOKKEEPING and k not in ("files", "findings", "relations")],
    )
    return not any(carries)


_PART_BOOKKEEPING = ("location", "part", "total_parts", "next_part")


def _reassembled(parts: list[dict[str, Any]], full: dict[str, Any]) -> dict[str, Any]:
    """The brief rebuilt out of its parts: the fixed fields from whichever part holds them, the
    list fields concatenated in part order."""
    out: dict[str, Any] = {"files": {}, "findings": [], "relations": [], "fixes": []}
    for reply in parts:
        for entry in reply["files"]:
            held = out["files"].setdefault(entry["file"], {"instructions": [], "headings": [], "rest": entry})
            held["instructions"].extend(entry["instructions"])
            held["headings"].extend(entry["headings"])
        out["findings"].extend(reply["findings"])
        out["relations"].extend(reply["relations"])
        out["fixes"].extend((reply.get("procedure") or {}).get("mechanical_fixes") or [])
        for key in ("preservation_contract", "next", "artifact_rules"):
            if key in reply:
                assert key not in out, f"{key} rides more than one part"
                out[key] = reply[key]
        if "rules" in (reply.get("procedure") or {}):
            assert "rules" not in out, "procedure.rules rides more than one part"
            out["rules"] = reply["procedure"]["rules"]
    for key in ("preservation_contract", "next", "artifact_rules"):
        assert out[key] == full[key]
    assert out["rules"] == full["procedure"]["rules"]
    assert out["fixes"] == full["procedure"]["mechanical_fixes"]
    assert out["findings"] == full["findings"]
    for entry in full["files"]:
        held = out["files"][entry["file"]]
        assert held["instructions"] == entry["instructions"]
        assert held["headings"] == entry["headings"]
        assert held["rest"]["path"] == entry["path"]
    return out


_REAL_SHAPES = {
    "fixed fields larger than a part": {},
    "long headings": {"headings": 150, "heading_chars": 400},
    "instructions of very different lengths": {"instructions": [10] * 200 + [6_000, 40, 9_000, 25] * 5},
    "many files": {"files": 90, "instructions": [60, 300, 80]},
    "many line fixes": {"fixes": 1_500, "fix_chars": 300},
    "many findings": {"findings": 400},
}


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize("shape", list(_REAL_SHAPES))
def test_a_paged_real_shaped_brief_has_no_empty_part_stays_in_the_limit_and_loses_nothing(shape: str) -> None:
    """With fixed fields larger than one part, long headings, instructions of very different
    lengths, a location of many files, thousands of line fixes or many findings, no part is
    empty, every part is within 16,000 characters, and the parts together carry the whole brief
    exactly once."""
    full, files_out, location_out = _real_shaped_brief(**_REAL_SHAPES[shape])
    parts = _all_parts(full, files_out, location_out)
    assert len(parts) > 1
    for number, reply in enumerate(parts, 1):
        assert reply["part"] == number
        assert reply["total_parts"] == len(parts)
        assert "ideal_instruction_parts" not in reply and "ideal_instruction" not in reply
        assert not _part_is_empty(reply), f"part {number} of {len(parts)} carries nothing"
        size = len(json.dumps(reply, separators=(",", ":")))
        assert size <= 16_000, f"part {number} of {len(parts)} is {size} characters"
    _reassembled(parts, full)


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_root_instruction_file_with_large_fixed_fields_pages_into_a_handful_of_parts() -> None:
    """A 120-instruction file beside 12,000 characters of artifact rules is a handful of
    parts, in proportion to its content, not one per character of the file."""
    full, files_out, location_out = _real_shaped_brief()
    content = sum(len(json.dumps(e, separators=(",", ":"))) for e in files_out) + 12_000
    assert len(_all_parts(full, files_out, location_out)) <= content // 8_000 + 2


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    "shape",
    [
        {"artifact_rules_chars": 30_000},
        {"instructions": [200, 25_000, 200]},
        {"fixes": 3, "fix_chars": 40_000},
    ],
)
def test_a_single_item_larger_than_the_limit_ships_alone_and_uncut(shape: dict[str, Any]) -> None:
    """One fixed field, instruction or line fix larger than a whole part rides a part of its
    own, uncut; every other part stays within the limit and the union is the whole brief."""
    full, files_out, location_out = _real_shaped_brief(**shape)
    parts = _all_parts(full, files_out, location_out)
    oversized = [n for n, reply in enumerate(parts, 1) if len(json.dumps(reply, separators=(",", ":"))) > 16_000]
    assert len(oversized) >= 1
    for n in oversized:
        reply = parts[n - 1]
        items = (
            ([reply["artifact_rules"]] if "artifact_rules" in reply else [])
            + [i for e in reply["files"] for i in e["instructions"]]
            + (reply.get("procedure") or {}).get("mechanical_fixes", [])
        )
        assert len(items) == 1, f"part {n} is over the limit and holds {len(items)} items"
    for number, reply in enumerate(parts, 1):
        assert not _part_is_empty(reply), f"part {number} carries nothing"
    _reassembled(parts, full)
