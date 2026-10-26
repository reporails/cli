"""Folder values with slashes, and the paths imported text is read from."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.discovery import exclusions as exclusions_module
from reporails_cli.core.discovery.exclusions import RunExclusions, load_run_exclusions
from reporails_cli.core.pipeline.assemble import AssembleInputs, _imported_note, _imports_left_out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_trailing_slash_and_dot_prefix_normalize(tmp_path: Path) -> None:
    left_out = load_run_exclusions(tmp_path, ["rules/", "./docs/", "/", ""], None)
    assert left_out.record() == (("./docs", "rules"), ())
    assert left_out.prunes(str(tmp_path / "x" / "rules"), "rules", os.path.realpath(str(tmp_path / "x" / "rules")))
    assert left_out.leaves_out(tmp_path / "x" / "rules" / "a.md")
    assert left_out.leaves_out(tmp_path / "docs" / "a.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_path_form_value_is_relative_to_the_root(tmp_path: Path) -> None:
    path_form = load_run_exclusions(tmp_path, [".claude/rules"], None)
    assert path_form.leaves_out(tmp_path / ".claude" / "rules" / "a.md")
    assert not path_form.leaves_out(tmp_path / "docs" / "rules" / "b.md")
    assert not path_form.leaves_out(tmp_path / "x" / ".claude" / "rules" / "a.md")
    assert path_form.prunes(
        str(tmp_path / ".claude" / "rules"), "rules", os.path.realpath(str(tmp_path / ".claude" / "rules"))
    )
    assert not path_form.prunes(
        str(tmp_path / "docs" / "rules"), "rules", os.path.realpath(str(tmp_path / "docs" / "rules"))
    )
    assert not path_form.prunes(
        str(tmp_path / "x" / ".claude" / "rules"), "rules", os.path.realpath(str(tmp_path / "x" / ".claude" / "rules"))
    )
    name_form = load_run_exclusions(tmp_path, ["rules"], None)
    assert name_form.leaves_out(tmp_path / ".claude" / "rules" / "a.md")
    assert name_form.leaves_out(tmp_path / "docs" / "rules" / "b.md")
    assert name_form.prunes(
        str(tmp_path / "docs" / "rules"), "rules", os.path.realpath(str(tmp_path / "docs" / "rules"))
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_root_is_resolved_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    left_out = load_run_exclusions(tmp_path, ["ext"], None)
    calls: list[Path] = []
    real = exclusions_module.safe_resolve

    def spy(p: Path) -> Path:
        calls.append(p)
        return real(p)

    monkeypatch.setattr(exclusions_module, "safe_resolve", spy)
    for i in range(5):
        left_out.leaves_out(tmp_path / f"d{i}" / "a.md")
    assert calls.count(tmp_path) == 1


def _atom(file_path: Path, imported_from: str) -> SimpleNamespace:
    return SimpleNamespace(
        file_path=str(file_path), imported_from=imported_from, imported_line=3, text="Keep it small."
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_symlinked_importer_reads_the_source_next_to_the_real_file(tmp_path: Path) -> None:
    root = tmp_path.resolve()
    (root / "shared").mkdir()
    (root / "shared" / "CLAUDE.md").write_text("# P\n", encoding="utf-8")
    (root / "CLAUDE.md").symlink_to(root / "shared" / "CLAUDE.md")
    atom = _atom(root / "CLAUDE.md", "../ext/notes.md")
    inp = AssembleInputs(
        m_findings=[],
        content_findings=[],
        client_findings=[],
        ruleset_map=SimpleNamespace(atoms=[atom]),
        scan_root=root,
        filter_agents=None,
        effective_agent="claude",
        lint_result=None,
    )
    assert _imports_left_out(inp, RunExclusions.parse(root, ["ext"], ()))
    assert "(from ext/notes.md:3" in _imported_note(atom, root)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_covers_asks_every_folder_from_the_root_down(tmp_path: Path) -> None:
    excl = RunExclusions.parse(tmp_path, ["scratch", "pkg/docs"], ())
    assert excl.covers(tmp_path / "node_modules" / "x" / "a.md")
    assert excl.covers(tmp_path / "a" / "scratch" / "b" / "a.md")
    assert excl.covers(tmp_path / "pkg" / "docs" / "a.md")
    assert not excl.covers(tmp_path / "other" / "pkg" / "docs" / "a.md")
    assert not excl.covers(tmp_path / "pkg" / "keep" / "a.md")
    assert not excl.covers(tmp_path.parent / "node_modules" / "a.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_record_reports_each_folder_in_the_form_it_was_given(tmp_path: Path) -> None:
    excl = RunExclusions.parse(tmp_path, ["./docs", "pkg/docs", "scratch", "scratch/"], ())
    assert excl.record() == (("./docs", "pkg/docs", "scratch"), ())
    named = excl.with_named([tmp_path / "pkg" / "docs" / "a.md"])
    assert named.record(narrowed=True) == (("./docs", "scratch"), ())
    assert named.record() == (("./docs", "pkg/docs", "scratch"), ())
