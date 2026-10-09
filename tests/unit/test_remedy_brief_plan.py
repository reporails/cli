"""`remedy_brief` replies with the plan: exact edits, the few slots, and `validate` checks the result."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from reporails_cli.formatters.mcp_view import render_text_view
from reporails_cli.interfaces.mcp import remedy_brief, server, snapshots, tools

SPLIT = "*Do not preload a fixed trinity or walk the whole corpus — resolve only the named entries.*"
NEGATION = "*Never bypass `reviewer` on cross-release work.*"
BARE = "Handle errors."
TEXT = f"# Rules\n\n{SPLIT}\n\n{NEGATION}\n\n{BARE}\n\n## Notes\n\nKeep notes short.\n"
C58, C42 = "CORE:C:0058", "CORE:C:0042"

_has_model = (
    Path(__file__).resolve().parents[2] / "src/reporails_cli/bundled/models/minilm-l6-v2/onnx/model.onnx"
).exists()
requires_model = pytest.mark.skipif(not _has_model, reason="Bundled ONNX model not available")


@pytest.fixture(autouse=True)
def _offline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    snapshots.clear_snapshots()


def _finding(rule: str, line: int, op: str, **extra: Any) -> dict[str, Any]:
    return {"rule": rule, "file": "CLAUDE.md", "line": line, "pi": None, "op": op, "expect": {}, **extra}


def _location() -> dict[str, Any]:
    return {
        "order": 1,
        "element": "CLAUDE.md",
        "kind": "main",
        "loading": "session_start",
        "importance": "gate_mover",
        "files": ["CLAUDE.md"],
        "findings": [
            _finding(C58, 3, "split"),
            _finding(C58, 5, "negation-form"),
            _finding(C42, 7, "elaborate", members=[_finding(C42, 7, "together")]),
        ],
        "relations": [],
    }


def _brief(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    file = tmp_path / "CLAUDE.md"
    file.write_text(TEXT, encoding="utf-8")
    reply = remedy_brief.build_remedy_brief(_location(), tmp_path)
    assert "error" not in reply, reply
    return file, reply


def _apply(file: Path, reply: dict[str, Any]) -> None:
    text = file.read_text(encoding="utf-8")
    for edit in reply["edits"]:
        assert text.count(edit["before"]) == 1
        text = text.replace(edit["before"], edit["after"])
    file.write_text(text, encoding="utf-8")


def _conformance(file: Path, root: Path) -> dict[str, Any]:
    payload, ruleset_map, score = tools.run_pipeline_for_path(str(file), True)
    return server._with_preservation(payload, file, ruleset_map, score, root)["conformance"]


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
def test_the_brief_is_the_plan(tmp_path: Path) -> None:
    file, reply = _brief(tmp_path)

    assert set(reply) == {"location", "edits", "slots", "guides", "ops", "refused", "preservation_contract", "next"}
    assert [(e["op"], e["line_start"], e["line_end"]) for e in reply["edits"]] == [
        ("negation-form", 5, 5),
        ("split", 3, 3),
    ]
    assert all(e["path"] == str(file) and e["file"] == "CLAUDE.md" for e in reply["edits"])
    (slot,) = reply["slots"]
    assert (slot["op"], slot["bound"], slot["line"], slot["text"]) == ("elaborate", "section", 7, BARE)
    assert set(reply["guides"]) == {C42}
    assert set(reply["guides"][C42]) == {"title", "pass", "fail"} and reply["guides"][C42]["title"]
    assert list(reply["ops"]) == ["elaborate"] and "using only words from its own section" in reply["ops"]["elaborate"]
    assert reply["refused"] == []


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
def test_an_edit_s_before_is_the_file_s_current_lines(tmp_path: Path) -> None:
    file, reply = _brief(tmp_path)
    lines = file.read_text(encoding="utf-8").splitlines()

    for edit in reply["edits"]:
        assert edit["before"] == "\n".join(lines[edit["line_start"] - 1 : edit["line_end"]])
        assert edit["after"] != edit["before"]


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
def test_validate_of_a_file_with_the_edits_applied_conforms(tmp_path: Path) -> None:
    file, reply = _brief(tmp_path)
    _apply(file, reply)

    assert _conformance(file, tmp_path) == {"ok": True, "deviations": []}


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
def test_a_change_outside_the_plan_is_a_deviation(tmp_path: Path) -> None:
    file, reply = _brief(tmp_path)
    _apply(file, reply)
    file.write_text(
        file.read_text(encoding="utf-8").replace("Keep notes short.", "Keep notes brief."), encoding="utf-8"
    )

    block = _conformance(file, tmp_path)

    assert block["ok"] is False
    assert block["deviations"][0]["op"] == "outside"
    assert set(block["deviations"][0]) == {"file", "line", "op", "rule", "expected", "found"}


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_text_view_lists_conformance() -> None:
    payload = {
        "preservation": {"ok": True},
        "conformance": {
            "ok": False,
            "deviations": [
                {"file": "CLAUDE.md", "line": 9, "op": "outside", "rule": "", "expected": "same", "found": "changed"}
            ],
        },
    }

    lines = render_text_view(payload).splitlines()

    assert "conformance.ok: false" in lines
    assert [line for line in lines if line.startswith("conformance.deviation:")] == [
        "conformance.deviation: CLAUDE.md line 9 — outside — expected same, found changed"
    ]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_a_move_is_one_block_spanning_both_places() -> None:
    from reporails_cli.core.platform.dto.heal_plan import Edit, Plan

    lines = ["a", "b", "c", "d"]
    plan = Plan(edits=(Edit("f", 4, "d", None, "move", "r", move_after=1),))

    (entry,) = remedy_brief._edit_entries(plan, {"f": lines}, {})

    assert (entry["line_start"], entry["line_end"], entry["before"], entry["after"]) == (
        1,
        4,
        "a\nb\nc\nd",
        "a\nd\nb\nc",
    )


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
def test_a_hoist_is_a_slot_with_its_target_and_partner(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(TEXT, encoding="utf-8")
    location = _location()
    location["findings"] = [
        _finding(C58, 7, "hoist", expect={"to": ["ROOT.md", 0], "also": ["other/CLAUDE.md", 4]}),
    ]

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    (slot,) = reply["slots"]
    assert slot["op"] == "hoist" and reply["edits"] == []
    assert slot["to"] == str((tmp_path / "ROOT.md").resolve())
    assert slot["also"] == [str((tmp_path / "other/CLAUDE.md").resolve()), 4]
    assert reply["ops"]["hoist"] == (
        "Move this line into the file named by the plan and delete the partner's copy; change no words."
    )


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    ("text", "edit_before", "line", "expected"),
    [
        ("# T\n\nDup line.\n\nKeep.\n", "Dup line.", 3, "# T\n\n\nKeep.\n"),
        ("# T\n\nDup line.\n\nKeep.\n", "Dup line.\n", 3, "# T\n\nKeep.\n"),
        ("# T\r\n\r\nDup line.\r\n\r\nKeep.\r\n", "Dup line.", 3, "# T\r\n\r\n\r\nKeep.\r\n"),
        ("Dup line.\nKeep.\n", "Dup line.", 1, "Keep.\n"),
    ],
)
def test_a_deleting_edit_removes_its_line_break_too(text: str, edit_before: str, line: int, expected: str) -> None:
    """Applied as a literal `str.replace(before, after, 1)`, a dedupe edit leaves no extra empty line."""
    from reporails_cli.core.platform.dto.heal_plan import Edit, Plan

    lines = text.splitlines(keepends=True)
    plan = Plan((Edit("f.md", line, edit_before, None, "dedupe", C58),), (), ())
    (entry,) = remedy_brief._edit_entries(plan, {"f.md": lines}, {})
    assert entry["before"] in text
    assert text.replace(entry["before"], entry["after"], 1) == expected


@pytest.mark.unit
@pytest.mark.subsys_server
@requires_model
def test_a_refused_split_slot_carries_its_one_change_and_its_guide_line(tmp_path: Path) -> None:
    (tmp_path / "CLAUDE.md").write_text(
        "# Rules\n\nRun the tests, then fix every failure.\n\nHandle errors.\n", encoding="utf-8"
    )
    location = _location()
    location["findings"] = [
        _finding(C58, 3, "split"),
        _finding(C42, 5, "elaborate", members=[_finding(C42, 5, "together")]),
    ]

    reply = remedy_brief.build_remedy_brief(location, tmp_path)

    split, plain = reply["slots"]
    assert (split["op"], split["change"]) == ("split", "split-keep-sequence")
    assert "change" not in plain
    assert (
        reply["ops"]["split-keep-sequence"]
        == "Keep a step that starts with then in one sentence with the step before it."
    )
    assert set(reply["ops"]) == {"split", "elaborate", "split-keep-sequence"}


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.requires_model
@requires_model
def test_a_unicode_line_separator_does_not_shift_the_plan_or_its_check(tmp_path: Path) -> None:
    """A U+2028 inside an item is no line break: the dedupe lands on its own line and the check agrees."""
    from reporails_cli.core.pipeline.mapping import map_instruction_files

    file, other = tmp_path / "CLAUDE.md", tmp_path / "AGENTS.md"
    file.write_text(
        "# Demo\n\n- Run `pytest` before you commit.\u2028Keep it green.\n- Keep `main` deployable.\n"
        "- Use `ruff` for linting.\n- Write small modules.\n",
        encoding="utf-8",
    )
    other.write_text("# Other\n\n- Use `ruff` for linting.\n", encoding="utf-8")
    relation = {
        "rule": "CORE:C:0040",
        "file": "CLAUDE.md",
        "line": 5,
        "op": "dedupe",
        "expect": {"keep": ["AGENTS.md", 3]},
    }
    location = {**_location(), "findings": [], "relations": [relation]}
    project_map = map_instruction_files(tmp_path, [file, other], spawn_daemon=False)

    reply = remedy_brief.build_remedy_brief(location, tmp_path, project_map)

    assert [(e["line_start"], e["before"]) for e in reply["edits"]] == [(5, "- Use `ruff` for linting.\n")]
    text = file.read_text(encoding="utf-8").replace("- Use `ruff` for linting.\n", "")
    file.write_text(text, encoding="utf-8")
    fresh = map_instruction_files(tmp_path, [file], spawn_daemon=False)
    assert snapshots.check_conformance(file, fresh, text, tmp_path) == {"ok": True, "deviations": []}
