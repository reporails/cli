"""Folder values with slashes, and the paths imported text is read from."""

from __future__ import annotations

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
    assert left_out.dirs == frozenset({"rules", "docs"})
    assert left_out.record() == (("docs", "rules"), ())
    assert "rules" in left_out.walk_dirs
    assert left_out.leaves_out(tmp_path / "x" / "rules" / "a.md")
    assert left_out.leaves_out(tmp_path / "docs" / "a.md")


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_path_form_value_is_relative_to_the_root(tmp_path: Path) -> None:
    path_form = load_run_exclusions(tmp_path, [".claude/rules"], None)
    assert path_form.leaves_out(tmp_path / ".claude" / "rules" / "a.md")
    assert not path_form.leaves_out(tmp_path / "docs" / "rules" / "b.md")
    assert not path_form.leaves_out(tmp_path / "x" / ".claude" / "rules" / "a.md")
    assert ".claude/rules" not in path_form.walk_dirs
    assert ".claude/rules" not in path_form.feature_walk_dirs
    name_form = load_run_exclusions(tmp_path, ["rules"], None)
    assert name_form.leaves_out(tmp_path / ".claude" / "rules" / "a.md")
    assert name_form.leaves_out(tmp_path / "docs" / "rules" / "b.md")
    assert "rules" in name_form.walk_dirs


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
    assert _imports_left_out(inp, RunExclusions(root, dirs=frozenset({"ext"})))
    assert "(from ext/notes.md:3" in _imported_note(atom, root)
