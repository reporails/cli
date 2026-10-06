"""A Windows path, written with forward slashes, matches the same patterns a POSIX path does."""

from __future__ import annotations

from pathlib import PureWindowsPath

import pytest

from reporails_cli.core.platform.utils.utils import config_pattern_matches, glob_matches


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("windows_rel", "pattern"),
    [
        (r".cursor\rules\a.mdc", ".cursor/rules/**/*.mdc"),
        (r"apps\web\.cursor\BUGBOT.md", "**/.cursor/BUGBOT.md"),
        (r".claude\skills\deploy\SKILL.md", ".claude/skills/*/SKILL.md"),
    ],
)
def test_a_windows_relative_path_matches_after_posix_conversion(windows_rel: str, pattern: str) -> None:
    posix = PureWindowsPath(windows_rel).as_posix()
    assert config_pattern_matches(posix, pattern)


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_home_pattern_matches_a_windows_drive_path_written_with_forward_slashes(monkeypatch) -> None:
    home = PureWindowsPath(r"C:\Users\runner")
    full = (home / ".claude" / "CLAUDE.md").as_posix()
    assert full == "C:/Users/runner/.claude/CLAUDE.md"
    assert glob_matches(full, "C:/Users/runner/.claude/CLAUDE.md")
    assert not glob_matches(full, "C:/Users/other/.claude/CLAUDE.md")
