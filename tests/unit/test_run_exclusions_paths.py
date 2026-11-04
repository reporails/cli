"""Folder values with slashes, and the paths imported text is read from."""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from reporails_cli.core.discovery import exclusions as exclusions_module
from reporails_cli.core.discovery.exclusions import (
    covers,
    exclusion_hits,
    leaves_out,
    load_run_exclusions,
    parse_run_exclusions,
    record_patterns,
    with_named,
)
from reporails_cli.core.pipeline.assemble import _imported_note, _imports_left_out
from reporails_cli.core.platform.dto.pipeline import AssembleInputs


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_trailing_slash_and_dot_prefix_normalize(tmp_path: Path) -> None:
    left_out = load_run_exclusions(tmp_path, ["rules/", "./docs/", "/", ""], None)
    assert record_patterns(left_out) == (("./docs", "rules"), ())
    assert left_out.prunes(str(tmp_path / "x" / "rules"), "rules", os.path.realpath(str(tmp_path / "x" / "rules")))
    assert leaves_out(left_out, tmp_path / "x" / "rules" / "a.md")
    assert leaves_out(left_out, tmp_path / "docs" / "a.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_path_form_value_is_relative_to_the_root(tmp_path: Path) -> None:
    path_form = load_run_exclusions(tmp_path, [".claude/rules"], None)
    assert leaves_out(path_form, tmp_path / ".claude" / "rules" / "a.md")
    assert not leaves_out(path_form, tmp_path / "docs" / "rules" / "b.md")
    assert not leaves_out(path_form, tmp_path / "x" / ".claude" / "rules" / "a.md")
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
    assert leaves_out(name_form, tmp_path / ".claude" / "rules" / "a.md")
    assert leaves_out(name_form, tmp_path / "docs" / "rules" / "b.md")
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
        leaves_out(left_out, tmp_path / f"d{i}" / "a.md")
    assert calls.count(tmp_path) == 0  # the root was resolved when the set was built


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
    assert _imports_left_out(inp, parse_run_exclusions(root, ["ext"], ()))
    assert "(from ext/notes.md:3" in _imported_note(atom, root)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_covers_asks_every_folder_from_the_root_down(tmp_path: Path) -> None:
    excl = parse_run_exclusions(tmp_path, ["scratch", "pkg/docs"], ())
    assert covers(excl, tmp_path / "node_modules" / "x" / "a.md")
    assert covers(excl, tmp_path / "a" / "scratch" / "b" / "a.md")
    assert covers(excl, tmp_path / "pkg" / "docs" / "a.md")
    assert not covers(excl, tmp_path / "other" / "pkg" / "docs" / "a.md")
    assert not covers(excl, tmp_path / "pkg" / "keep" / "a.md")
    assert not covers(excl, tmp_path.parent / "node_modules" / "a.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_record_reports_each_folder_in_the_form_it_was_given(tmp_path: Path) -> None:
    excl = parse_run_exclusions(tmp_path, ["./docs", "pkg/docs", "scratch", "scratch/"], ())
    assert record_patterns(excl) == (("./docs", "pkg/docs", "scratch"), ())
    named = with_named(excl, [tmp_path / "pkg" / "docs" / "a.md"])
    assert record_patterns(named, narrowed=True) == (("./docs", "scratch"), ())
    assert record_patterns(named) == (("./docs", "pkg/docs", "scratch"), ())


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_exclusion_hits_name_the_setting_the_value_and_the_config_file(tmp_path: Path) -> None:
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.yml").write_text("exclude_dirs: [hub]\nheal_exclude: ['**/CLAUDE.md']\n")
    (tmp_path / ".ails" / "config.local.yml").write_text("exclude_files: ['notes/*.md']\n")
    held, kept = tmp_path / "hub" / "CLAUDE.md", tmp_path / "docs" / "a.md"
    noted = tmp_path / "notes" / "b.md"
    found = exclusion_hits(tmp_path, [held, kept, noted])
    assert [(h.setting, h.value, h.config) for h in found[held]] == [
        ("exclude_dirs", "hub", ".ails/config.yml"),
        ("heal_exclude", "**/CLAUDE.md", ".ails/config.yml"),
    ]
    assert found[kept] == ()
    assert [(h.setting, h.value, h.config) for h in found[noted]] == [
        ("exclude_files", "notes/*.md", ".ails/config.local.yml")
    ]
