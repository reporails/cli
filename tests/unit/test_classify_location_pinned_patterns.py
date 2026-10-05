"""A location-pinned pattern anchors at the scan root, not the file's tail.

`PurePosixPath.match()` matches a relative pattern from the right: `.claude/CLAUDE.md`
also matched a deeper file like `pkg/.claude/CLAUDE.md`, because only the pattern's own
trailing components were compared. That let a nested project instruction file — which
should classify `child_instruction` / nested, loaded on demand for its own subtree —
win `main` / session_start / global instead, through a pattern that names a path other
than the one it actually sits on. A `~`-rooted pattern already resolves to an absolute
path before matching, and `PurePosixPath.match()` requires a whole-path match against
an absolute pattern, so it was already anchored; these tests pin that down alongside
the fix and cross-check every case against the mapper's own (already-anchored, fnmatch
based) registry match, so the two surfaces keep agreeing on a file's type and loading.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.mapper.inspect import _detect_file_loading, _load_registry


def _write(path: Path, text: str = "# Instructions\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def home(monkeypatch, tmp_path) -> Path:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    return home_dir


class TestNestedFileUnderAPinnedPatternIsNotTheProjectMain:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_nested_claude_md_classifies_child_instruction_not_main(self, tmp_path: Path) -> None:
        """`pkg/.claude/CLAUDE.md` types `child_instruction`, never `main`.

        `main`'s project-scope pattern `.claude/CLAUDE.md` names the file at the scan
        root; it must not also match the same tail two levels down.
        """
        project = tmp_path / "proj"
        nested = _write(project / "pkg" / ".claude" / "CLAUDE.md")

        file_types = load_file_types("claude")
        classified = classify_files(project, [nested], file_types)

        assert len(classified) == 1
        assert classified[0].file_type == "child_instruction"
        assert classified[0].properties.get("scope") == "nested"
        assert classified[0].properties.get("loading") == "on_demand"

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_nested_claude_md_agrees_with_the_mapper(self, tmp_path: Path) -> None:
        """classify and the mapper's registry match land on the same type and loading."""
        project = tmp_path / "proj"
        nested = _write(project / "pkg" / ".claude" / "CLAUDE.md")

        file_types = load_file_types("claude")
        classified = classify_files(project, [nested], file_types)
        loading, scope, _globs, agent, file_type = _detect_file_loading(nested, project, _load_registry())

        assert classified[0].file_type == file_type == "child_instruction"
        assert classified[0].properties.get("loading") == loading == "on_demand"
        assert classified[0].properties.get("scope") == scope == "nested"
        assert agent == "claude"


class TestRootPinnedPatternStillMatchesItsOwnFile:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_root_claude_md_via_dotclaude_path_classifies_main(self, tmp_path: Path) -> None:
        """`.claude/CLAUDE.md` sitting at the scan root itself still types `main`."""
        project = tmp_path / "proj"
        root_file = _write(project / ".claude" / "CLAUDE.md")

        file_types = load_file_types("claude")
        classified = classify_files(project, [root_file], file_types)

        assert len(classified) == 1
        assert classified[0].file_type == "main"
        assert classified[0].properties.get("loading") == "session_start"
        assert classified[0].properties.get("scope") == "global"

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_root_claude_md_agrees_with_the_mapper(self, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        root_file = _write(project / ".claude" / "CLAUDE.md")

        file_types = load_file_types("claude")
        classified = classify_files(project, [root_file], file_types)
        loading, scope, _globs, agent, file_type = _detect_file_loading(root_file, project, _load_registry())

        assert classified[0].file_type == file_type == "main"
        assert classified[0].properties.get("loading") == loading == "session_start"
        assert classified[0].properties.get("scope") == scope == "global"
        assert agent == "claude"


class TestHomeRootedPatternWinsOverAProjectPattern:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_home_claude_md_classifies_main_via_its_own_user_pattern(self, home: Path, tmp_path: Path) -> None:
        """`~/.claude/CLAUDE.md` types `main` with the properties `main` declares —
        never mistaken for an unrelated file just because a project pattern's tail
        happens to line up."""
        project = tmp_path / "proj"
        project.mkdir()
        user_file = _write(home / ".claude" / "CLAUDE.md")

        file_types = load_file_types("claude")
        classified = classify_files(project, [user_file], file_types)

        assert len(classified) == 1
        assert classified[0].file_type == "main"
        assert classified[0].properties.get("loading") == "session_start"
        assert classified[0].properties.get("scope") == "global"

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_home_claude_md_agrees_with_the_mapper(self, home: Path, tmp_path: Path) -> None:
        project = tmp_path / "proj"
        project.mkdir()
        user_file = _write(home / ".claude" / "CLAUDE.md")

        file_types = load_file_types("claude")
        classified = classify_files(project, [user_file], file_types)
        loading, scope, _globs, agent, file_type = _detect_file_loading(user_file, project, _load_registry())

        assert classified[0].file_type == file_type == "main"
        assert classified[0].properties.get("loading") == loading == "session_start"
        assert classified[0].properties.get("scope") == scope == "global"
        assert agent == "claude"


class TestDoubleStarSpansNestedFolders:
    """A `**` in a pinned pattern spans any number of folders, so a file nested deeper than
    the pattern's own depth is still claimed by the type that declares its folder."""

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    @pytest.mark.parametrize(
        ("rel", "expected"),
        [
            (".claude/agents/planner.md", "agents"),
            (".claude/agents/workflows/best-practice/deep.md", "agents"),
            (".claude/skills/api/SKILL.md", "skills"),
            (".claude/skills/api/nested/inner/SKILL.md", "skills"),
            (".claude/skills/api/references/notes.md", "skills"),
            (".claude/rules/frontend/react/hooks.md", "rules"),
        ],
    )
    def test_nested_file_is_claimed_by_its_folders_type(
        self, home: Path, tmp_path: Path, rel: str, expected: str
    ) -> None:
        path = _write(tmp_path / rel, "# Notes\n\nUse the shared client.\n")
        classified = classify_files(tmp_path, [path], load_file_types("claude", project_root=tmp_path))
        assert [c.file_type for c in classified] == [expected]
        assert _detect_file_loading(path, tmp_path, _load_registry())[4] == expected

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_a_folder_that_is_not_the_declared_one_stays_unclaimed(self, home: Path, tmp_path: Path) -> None:
        path = _write(tmp_path / "pkg/.claude/notes/workflows/deep.md", "# Notes\n")
        assert classify_files(tmp_path, [path], load_file_types("claude", project_root=tmp_path)) == []
