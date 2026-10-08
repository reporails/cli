"""`ails check --heal` fixes each finding at the place it names, lists decisions, and puts back a file that departs."""

from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.heal.keyed import KeyedResult
from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.pipeline.mapping import map_instruction_files
from reporails_cli.core.platform.dto.diagnostics import LocationFinding, RemediationWorkflow, WorkflowLocation
from reporails_cli.interfaces.cli.heal import _apply_keyed_fixes, _output_heal_results

pytestmark = [pytest.mark.unit, pytest.mark.subsys_heal]

DOC = """# Demo

Always run the **linter** before you commit.

Never edit **generated** files by hand.

Run build.sh before every commit.

Open settings.json and edit it.
"""


ALL = ((3, "unbold", "bold"), (7, "code", "format"), (9, "code", "format"))


class _Console:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def print(self, msg: str = "") -> None:
        self.lines.append(msg)


def _run(
    tmp_path: Path,
    *rows: tuple[int, str, str],
    text: str = DOC,
    dry_run: bool = False,
    suppressed: dict[Path, set[int]] | None = None,
    allowed: bool = True,
) -> tuple[Any, Path]:
    """Heal `CLAUDE.md` with a workflow of `(line, op, rule)` rows, each on the one atom of its line."""
    path = tmp_path / "CLAUDE.md"
    if not path.exists():
        path.write_bytes(text.encode())
    m = map_instruction_files(tmp_path, [path], spawn_daemon=False)
    items = tuple(LocationFinding(rule, str(path), line, _pi(m, line), op) for line, op, rule in rows)
    wf = RemediationWorkflow(locations=(WorkflowLocation(1, "main", "main", "always", (str(path),), "", items),))
    res = _apply_keyed_fixes(m, tmp_path, wf, dry_run, False, _Console(), [path] if allowed else [], suppressed or {})
    return res, path


def _pi(m: Any, line: int) -> int | None:
    return next((a.position_index for a in m.atoms if a.line == line), None)


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_bold_on_a_directive_becomes_italic_and_is_not_reported_again(tmp_path: Path) -> None:
    res, path = _run(tmp_path, (3, "unbold", "bold"), (7, "code", "format"))
    assert "Always run the *linter* before" in path.read_text()
    assert {f["rule_id"] for f in res.fixes} == {"bold", "format"}
    m = map_instruction_files(tmp_path, [path], spawn_daemon=False)
    assert not [f for f in run_client_checks(m) if f.rule == "bold"]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_format_row_wraps_only_its_own_line(tmp_path: Path) -> None:
    res, path = _run(tmp_path, (7, "code", "format"))
    lines = path.read_text().splitlines()
    assert "`build.sh`" in lines[6]
    assert "settings.json" in lines[8] and "`settings.json`" not in lines[8]
    assert "**linter**" in lines[2]
    assert [f["line"] for f in res.fixes] == [7]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_bold_on_a_constraint_is_fixed(tmp_path: Path) -> None:
    res, path = _run(tmp_path, (5, "unbold", "CORE:C:0058"))
    assert "Never edit *generated* files" in path.read_text()
    assert [f["line"] for f in res.fixes] == [5]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_no_workflow_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "CLAUDE.md"
    path.write_text(DOC)
    m = map_instruction_files(tmp_path, [path], spawn_daemon=False)
    res = _apply_keyed_fixes(m, tmp_path, None, False, False, _Console(), [path], {})
    assert res.fixes == [] and path.read_text() == DOC


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_second_run_changes_nothing_and_dry_run_writes_nothing(tmp_path: Path) -> None:
    path = tmp_path / "CLAUDE.md"
    path.write_bytes(DOC.replace("\n", "\r\n").encode())
    res, _ = _run(tmp_path, *ALL, dry_run=True)
    assert res.fixes
    assert path.read_bytes() == DOC.replace("\n", "\r\n").encode()
    _run(tmp_path, *ALL)
    once = path.read_bytes()
    assert b"\r\n" in once and b"\n" not in once.replace(b"\r\n", b"")
    res2, _ = _run(tmp_path, *ALL)
    assert res2.fixes == [] and path.read_bytes() == once


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_suppressed_line_and_files_outside_the_heal_set_are_untouched(tmp_path: Path) -> None:
    path = tmp_path / "CLAUDE.md"
    path.write_text(DOC)
    res, _ = _run(tmp_path, *ALL, suppressed={path.resolve(): {3, 7}})
    text = path.read_text()
    assert "**linter**" in text and "build.sh before" in text and "`settings.json`" in text
    assert [f["line"] for f in res.fixes] == [9]
    other = tmp_path / "sub"
    other.mkdir()
    (other / "CLAUDE.md").write_text(DOC)
    path.write_text(DOC)
    res, _ = _run(tmp_path, *ALL, allowed=False)
    assert res.fixes == [] and path.read_text() == DOC


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_split_is_written_and_a_category_op_is_a_decision(tmp_path: Path) -> None:
    text = "# Demo\n\nRun the tests; update the docs.\n\nKeep the code clear.\n"
    res, path = _run(tmp_path, (3, "split", "CORE:C:0058"), (5, "category", "CORE:C:0001"), text=text)
    assert "Run the tests. Update the docs." in path.read_text()
    assert "Keep the code clear." in path.read_text()
    assert [(f["line"], f["description"]) for f in res.fixes] == [(3, "Gave each instruction its own sentence")]
    assert [(d["line"], d["op"]) for d in res.decisions] == [(5, "category")]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_a_file_that_departs_from_its_plan_is_put_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The write also touches an unplanned line; the file is restored byte for byte."""
    import reporails_cli.core.heal.keyed as keyed

    original_apply = keyed.apply_edits

    def touching_neighbour(lines: Any, edits: Any) -> Any:
        body, where = original_apply(lines, edits)
        body[0] = body[0] + " extra"
        return body, where

    monkeypatch.setattr(keyed, "apply_edits", touching_neighbour)
    path = tmp_path / "CLAUDE.md"
    path.write_bytes(DOC.encode())
    res, _ = _run(tmp_path, (7, "code", "format"))
    assert path.read_bytes() == DOC.encode()
    assert res.fixes == []
    assert [(p["op"], p["rule"], p["line"]) for p in res.put_back] == [("outside", "", 1)]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_a_split_that_ends_a_sentence_partway_through_its_series_is_put_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The write follows its plan, but the rewrite check finds a sentence cut off its series."""
    import reporails_cli.core.heal.transforms as transforms
    from reporails_cli.core.platform.dto.heal_plan import Edit

    line = json.loads((Path(__file__).parents[1] / "fixtures" / "heal_split_defect_lines.json").read_text())[
        "claude_md_11"
    ]

    def series_cut(op: Any, atoms: Any, lines: Any) -> Edit:
        before = lines[op.line - 1].rstrip("\r\n")
        return Edit(op.file, op.line, before, before.replace("`), and write", "`). And write"), op.op, op.rule)

    monkeypatch.setitem(transforms.TRANSFORMS, "split", series_cut)
    text = f"# Demo\n\n{line}\n"
    res, path = _run(tmp_path, (3, "split", "CORE:C:0058"), text=text)
    assert path.read_text() == text
    assert res.fixes == []
    assert [(p["file"], p["check"]) for p in res.put_back] == [(str(path), "preservation:dangling_fragments")]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_output_lists_decisions_and_put_back() -> None:
    decisions = [{"file": "CLAUDE.md", "line": 5, "op": "category", "rule": "CORE:C:0001"}]
    put_back = [{"file": "CLAUDE.md", "op": "code", "rule": "format", "line": 7}]
    res = KeyedResult(decisions=decisions, put_back=put_back)
    out = _Console()
    _output_heal_results([], [], False, 1.0, "text", out, (), res)
    text = "\n".join(out.lines)
    assert "place needs a decision" in text and "CLAUDE.md:5  category  " in text
    assert "put back: CLAUDE.md (code format line 7)" in text
    buf = io.StringIO()
    with redirect_stdout(buf):
        _output_heal_results([], [], False, 1.0, "json", out, (), res)
    data = json.loads(buf.getvalue())
    assert data["decisions"] == decisions and data["summary"]["decisions_count"] == 1
    assert data["summary"]["put_back_count"] == 1


def _heal_cli(tmp_path: Path) -> Any:
    import logging

    from typer.testing import CliRunner

    from reporails_cli.interfaces.cli.main import app

    levels = {n: lg.level for n, lg in logging.root.manager.loggerDict.items() if isinstance(lg, logging.Logger)}
    try:
        return CliRunner().invoke(app, ["check", str(tmp_path), "--heal"])
    finally:  # the check run quiets the mapper's loggers; give them back
        for name, level in levels.items():
            logging.getLogger(name).setLevel(level)


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_with_the_server_unreachable_says_no_fixes_arrived_not_pro(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A signed-in run whose server cannot be reached changes nothing and does not ask for a Pro account."""
    path = tmp_path / "CLAUDE.md"
    path.write_text(DOC)
    monkeypatch.setenv("AILS_API_KEY", "k")
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    result = _heal_cli(tmp_path)
    assert path.read_text() == DOC
    assert "Pro account" not in result.output
    assert "sent no fixes" in result.output


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_signed_out_changes_nothing_and_points_to_login(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """With no key and no stored login, no file changes and the sign-in line is printed."""
    home = tmp_path / "home"
    home.mkdir()
    project = tmp_path / "proj"
    project.mkdir()
    path = project / "CLAUDE.md"
    path.write_text(DOC)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("AILS_API_KEY", raising=False)
    monkeypatch.setenv("AILS_SERVER_URL", "http://127.0.0.1:9")
    result = _heal_cli(project)
    assert path.read_text() == DOC
    assert "ails login" in result.output


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_for_a_free_tier_reply_prints_the_pro_line(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from reporails_cli.interfaces.cli import check_flow

    monkeypatch.setenv("AILS_API_KEY", "k")
    state = SimpleNamespace(
        inputs=SimpleNamespace(heal=True),
        pipeline=SimpleNamespace(lint_result=SimpleNamespace(workflow=None), funnel_error=None),
        render=SimpleNamespace(heal_authed=False),
        targets=SimpleNamespace(output_format="text"),
    )
    check_flow._flow_heal(state)
    assert "Pro account" in capsys.readouterr().out


def _hand_map(*files: Path) -> tuple[Any, RemediationWorkflow]:
    """A map with one `build.sh` atom on line 2 of each file, and a workflow with a `code` row on each."""
    from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap

    atoms = tuple(
        Atom(
            line=2,
            text="Run build.sh before every commit.",
            kind="paragraph",
            charge="IMPERATIVE",
            charge_value=1,
            modality="imperative",
            specificity="named",
            unformatted_code=["build.sh"],
            file_path=str(f),
        )
        for f in files
    )
    rmap = RulesetMap(schema_version="1", embedding_model="m", generated_at="now", files=(), atoms=atoms)
    items = tuple(LocationFinding("format", str(f), 2, 0, "code") for f in files)
    wf = RemediationWorkflow(locations=(WorkflowLocation(1, "main", "main", "always", (), "", items),))
    return rmap, wf


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_a_config_surface_file_is_never_written(tmp_path: Path) -> None:
    """A finding on a config surface (`.claude/settings.json`) gets no fix; the same row on `CLAUDE.md` does."""
    kept = tmp_path / "CLAUDE.md"
    kept.write_text("# Doc\nRun build.sh before every commit.\n")
    (tmp_path / ".claude").mkdir()
    config = tmp_path / ".claude" / "settings.json"
    config.write_text('{\n"note": "Run build.sh before every commit."\n}\n')
    before = config.read_bytes()
    rmap, wf = _hand_map(kept, config)
    res = _apply_keyed_fixes(rmap, tmp_path, wf, False, False, _Console(), [kept, config], {})
    assert config.read_bytes() == before
    assert "`build.sh`" in kept.read_text()
    assert [f["file_path"] for f in res.fixes] == [str(kept)]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.requires_model
def test_a_file_whose_imports_expand_is_never_written(tmp_path: Path) -> None:
    """Atom lines of an `@import`-bearing file count the imported lines, so a write would land on the wrong line."""
    kept = tmp_path / "CLAUDE.md"
    kept.write_text("# Doc\nRun build.sh before every commit.\n")
    (tmp_path / "frag.md").write_text("imported one\nimported two\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "frag.md").write_text("imported one\nimported two\n")
    importing = sub / "CLAUDE.md"
    importing.write_text("@frag.md\nRun build.sh before every commit.\n")
    before = importing.read_bytes()
    rmap, wf = _hand_map(kept, importing)
    res = _apply_keyed_fixes(rmap, tmp_path, wf, False, False, _Console(), [kept, importing], {})
    assert importing.read_bytes() == before
    assert "`build.sh`" in kept.read_text()
    assert [f["file_path"] for f in res.fixes] == [str(kept)]


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_takes_its_fixes_from_the_workflow_the_report_showed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A finding the report left out for that kind of file is not fixed or listed by `--heal`."""
    from types import SimpleNamespace

    from reporails_cli.interfaces.cli import check_flow

    path = tmp_path / "CLAUDE.md"
    path.write_text(DOC)
    raw = RemediationWorkflow(
        locations=(WorkflowLocation(1, "main", "main", "always", (str(path),), "", ()),),
    )
    shown = RemediationWorkflow(locations=())
    seen: list[Any] = []
    monkeypatch.setattr(check_flow, "_run_heal_pass", lambda *a, **k: seen.append(a[-1]))
    state = SimpleNamespace(
        inputs=SimpleNamespace(heal=True, dry_run=False),
        pipeline=SimpleNamespace(
            lint_result=SimpleNamespace(workflow=raw), funnel_error=None, ruleset_map=None, stage_timer=None
        ),
        render=SimpleNamespace(
            heal_authed=True, capability_paths=set(), result=SimpleNamespace(notices=(), workflow=shown)
        ),
        scope=SimpleNamespace(instruction_files=[path], effective_agent="claude"),
        targets=SimpleNamespace(single_path=None, target=tmp_path, output_format="text"),
    )
    check_flow._flow_heal(state)
    assert seen == [shown]
