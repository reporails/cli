"""A file discovery finds outside the scan root still classifies.

Discovery already expands `~` when it globs a home-rooted file_type pattern
(`agent_discovery._glob_external`, `_glob_directory_entries`) — the auto-memory
notes under `~/.claude/projects/<id>/memory/`, the user-scope `~/.claude/CLAUDE.md`,
and another agent's home file all land in the file list the classifier receives.
Classification matched the raw `~` pattern against the file's absolute path
without expanding it, so every one of these discovered files fell through
every `file_type` and reached the wire untyped (`generic`). These tests
demonstrate the classifier now types them; a project-rooted file's
classification is unchanged.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import _first_matching_pattern, classify_files, load_file_types


@pytest.fixture
def home(monkeypatch, tmp_path) -> Path:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("USERPROFILE", str(home_dir))  # Path.home() reads USERPROFILE on Windows
    return home_dir


class TestFirstMatchingPatternExpandsHome:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_home_rooted_leaf_pattern_matches_the_absolute_path_it_found(self, home: Path) -> None:
        """`~/.claude/CLAUDE.md` matches the absolute path discovery expanded to find it."""
        rel_path = str(home / ".claude" / "CLAUDE.md")
        assert _first_matching_pattern(rel_path, ("~/.claude/CLAUDE.md",)) == "~/.claude/CLAUDE.md"

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_home_rooted_directory_glob_matches_an_entry_file_inside_it(self, home: Path) -> None:
        """A trailing-slash home pattern (`~/.claude/projects/*/memory/`) matches a note inside."""
        rel_path = str(home / ".claude" / "projects" / "proj-slug" / "memory" / "notes.md")
        patterns = ("~/.claude/projects/*/memory/",)
        assert _first_matching_pattern(rel_path, patterns) == "~/.claude/projects/*/memory/"

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_project_relative_path_is_unaffected_by_a_home_pattern_in_the_same_list(self) -> None:
        """A project file still matches its own project pattern first, home pattern present or not."""
        patterns = ("**/CLAUDE.md", "~/.claude/CLAUDE.md")
        assert _first_matching_pattern("CLAUDE.md", patterns) == "**/CLAUDE.md"


class TestClassifyFilesTypesHomeRootedFiles:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_home_memory_index_and_sibling_classify_with_the_right_loading(self, home: Path, tmp_path: Path) -> None:
        """The MEMORY.md index and a sibling note both type `memory`; only the index is eager."""
        project = tmp_path / "proj"
        project.mkdir()
        memory_dir = home / ".claude" / "projects" / "proj-slug" / "memory"
        memory_dir.mkdir(parents=True)
        index = memory_dir / "MEMORY.md"
        index.write_text("# Memory\n", encoding="utf-8")
        sibling = memory_dir / "notes.md"
        sibling.write_text("# Notes\n", encoding="utf-8")

        file_types = load_file_types("claude")
        classified = {cf.path: cf for cf in classify_files(project, [index, sibling], file_types)}

        assert classified[index].file_type == "memory"
        assert classified[index].properties.get("loading") == "session_start"
        assert classified[sibling].file_type == "memory"
        assert classified[sibling].properties.get("loading") == "on_demand"

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_user_scope_claude_md_classifies_as_main(self, home: Path, tmp_path: Path) -> None:
        """`~/.claude/CLAUDE.md` types `main`, the same file_type as the project root file."""
        project = tmp_path / "proj"
        project.mkdir()
        user_dir = home / ".claude"
        user_dir.mkdir()
        user_file = user_dir / "CLAUDE.md"
        user_file.write_text("# User memory\n", encoding="utf-8")

        file_types = load_file_types("claude")
        classified = classify_files(project, [user_file], file_types)

        assert len(classified) == 1
        assert classified[0].file_type == "main"

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_project_file_classification_is_unchanged(self, tmp_path: Path) -> None:
        """A regression guard: an in-project `CLAUDE.md` still types `main` after the home fix."""
        project = tmp_path / "proj"
        project.mkdir()
        main = project / "CLAUDE.md"
        main.write_text("# Project\n", encoding="utf-8")

        file_types = load_file_types("claude")
        classified = classify_files(project, [main], file_types)

        assert len(classified) == 1
        assert classified[0].file_type == "main"
