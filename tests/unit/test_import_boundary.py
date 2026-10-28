"""An `@import` that resolves outside the project is left as written; one inside it, excluded or not, expands."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.mapper.imports import expand_imports, expand_imports_with_origins

SECRET = "TOP-SECRET-OUTSIDE-TEXT"
EXCLUDED = "EXCLUDED-FOLDER-TEXT"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    (tmp_path / "outside.md").write_text(f"{SECRET}\n", encoding="utf-8")
    (root / "ext").mkdir()
    (root / "ext" / "notes.md").write_text(f"{EXCLUDED}\n", encoding="utf-8")
    return root


def _expanded_both(content: str, source: Path) -> list[str]:
    """The text both expansion entry points produce for `content`, written into `source`."""
    source.write_text(content, encoding="utf-8")
    return [expand_imports(content, source), expand_imports_with_origins(content, source)[0]]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_relative_import_outside_the_project_is_left_as_written(project: Path) -> None:
    for expanded in _expanded_both("@../outside.md\n", project / "CLAUDE.md"):
        assert SECRET not in expanded
        assert "@../outside.md" in expanded


@pytest.mark.unit
@pytest.mark.subsys_map
def test_import_through_a_symlink_out_of_the_project_is_not_expanded(project: Path) -> None:
    (project / "link.md").symlink_to(project.parent / "outside.md")
    for expanded in _expanded_both("@link.md\n", project / "CLAUDE.md"):
        assert SECRET not in expanded


@pytest.mark.unit
@pytest.mark.subsys_map
def test_home_import_outside_the_project_is_not_expanded(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = project.parent / "home"
    home.mkdir()
    (home / "private.md").write_text(f"{SECRET}\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for expanded in _expanded_both("@~/private.md\n", project / "CLAUDE.md"):
        assert SECRET not in expanded


@pytest.mark.unit
@pytest.mark.subsys_map
def test_nested_import_cannot_climb_out_of_the_project(project: Path) -> None:
    (project / "docs").mkdir()
    (project / "docs" / "inner.md").write_text("@../../outside.md\n", encoding="utf-8")
    for expanded in _expanded_both("@docs/inner.md\n", project / "CLAUDE.md"):
        assert SECRET not in expanded


@pytest.mark.unit
@pytest.mark.subsys_map
def test_import_into_an_excluded_project_folder_still_expands(project: Path) -> None:
    """An `@import` into an excluded in-project folder still counts in the importing file."""
    for expanded in _expanded_both("@ext/notes.md\n", project / "CLAUDE.md"):
        assert EXCLUDED in expanded
