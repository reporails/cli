"""Unit tests for symlinked instruction file detection.

Ensures that a symlinked instruction file pointing outside the project is
detected as present, and that the directory walk follows symlinked directories,
breaks cycles, dedupes shared targets and drops dangling links.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from reporails_cli.core.discovery.exclusions import DEFAULT_EXCLUDE_DIRS
from reporails_cli.core.discovery.features import detect_features_filesystem

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="symlinks require admin on Windows")


class TestSymlinkFeatureDetection:
    """Test symlink handling in detect_features_filesystem."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_symlinked_claude_md_detected_as_existing(self, tmp_path: Path) -> None:
        """Symlinked CLAUDE.md (external target) is detected as existing."""
        project = tmp_path / "project"
        project.mkdir()

        external = tmp_path / "shared" / "CLAUDE.md"
        external.parent.mkdir()
        external.write_text("# Shared Config\n")

        os.symlink(str(external), str(project / "CLAUDE.md"))

        features = detect_features_filesystem(project)

        assert features.has_instruction_file is True


class TestWalkGlobFollowsSymlinkedDirs:
    """Regression: `walk_glob` descends into symlinked directories.

    Files inside symlinked dirs must be visible to whole-repo discovery.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_finds_file_inside_symlinked_directory(self, tmp_path: Path) -> None:
        """A SKILL.md inside a directory symlink should appear in results."""
        from reporails_cli.core.discovery.walk import walk_glob

        # Canonical location outside the project
        canonical = tmp_path / "canonical" / "audit"
        canonical.mkdir(parents=True)
        (canonical / "SKILL.md").write_text("# Audit\n")

        # Project tree with a symlinked directory pointing at the canonical
        project = tmp_path / "project"
        skills_dir = project / ".claude" / "skills"
        skills_dir.mkdir(parents=True)
        os.symlink(str(canonical), str(skills_dir / "audit"))

        results = walk_glob(skills_dir, "SKILL.md", DEFAULT_EXCLUDE_DIRS)

        rel = [str(p.relative_to(project)) for p in results]
        assert ".claude/skills/audit/SKILL.md" in rel

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_breaks_symlink_cycle(self, tmp_path: Path) -> None:
        """An `a -> b -> a` directory cycle must terminate the walk."""
        from reporails_cli.core.discovery.walk import walk_glob

        root = tmp_path / "root"
        a = root / "a"
        b = root / "b"
        a.mkdir(parents=True)
        b.mkdir()
        (a / "SKILL.md").write_text("# A\n")

        # Cycle: a/loop -> b, b/loop -> a
        os.symlink(str(b), str(a / "loop"))
        os.symlink(str(a), str(b / "loop"))

        results = walk_glob(root, "SKILL.md", DEFAULT_EXCLUDE_DIRS)

        # Must find the file exactly once despite the cycle; must not hang.
        assert len(results) == 1
        assert results[0].name == "SKILL.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_dedupes_two_symlinks_to_same_target(self, tmp_path: Path) -> None:
        """Two surface paths symlinking to the same canonical dir → file
        appears once (canonical inode tracked in `visited_real`)."""
        from reporails_cli.core.discovery.walk import walk_glob

        canonical = tmp_path / "canonical" / "shared"
        canonical.mkdir(parents=True)
        (canonical / "SKILL.md").write_text("# Shared\n")

        project = tmp_path / "project"
        project.mkdir()
        os.symlink(str(canonical), str(project / "via_a"))
        os.symlink(str(canonical), str(project / "via_b"))

        results = walk_glob(project, "SKILL.md", DEFAULT_EXCLUDE_DIRS)

        assert len(results) == 1


class TestCiGlobSkipsDanglingSymlinks:
    """Regression: a dangling symlink in .claude/rules/ crashed `ails check .`
    (FileNotFoundError at mapper read) because ci_glob passed broken symlinks
    through discovery."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_exact_name_dangling_symlink_excluded(self, tmp_path: Path) -> None:
        """iterdir branch: dangling symlink matching the exact pattern → excluded."""
        from reporails_cli.core.discovery.agent_discovery import ci_glob

        os.symlink(str(tmp_path / "missing-target.md"), str(tmp_path / "CLAUDE.md"))

        assert ci_glob(tmp_path, "CLAUDE.md") == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_wildcard_dangling_symlink_excluded(self, tmp_path: Path) -> None:
        """glob branch: dangling symlink matching a wildcard pattern → excluded."""
        from reporails_cli.core.discovery.agent_discovery import ci_glob

        rules = tmp_path / ".claude" / "rules"
        rules.mkdir(parents=True)
        (rules / "real.md").write_text("# Real\n")
        os.symlink(str(tmp_path / "hub" / "gone.md"), str(rules / "dangling.md"))

        results = ci_glob(tmp_path, ".claude/rules/*.md")

        assert [p.name for p in results] == ["real.md"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_valid_symlink_kept(self, tmp_path: Path) -> None:
        """Valid symlink-to-file still discovered (symlink-follow preserved)."""
        from reporails_cli.core.discovery.agent_discovery import ci_glob

        target = tmp_path / "shared.md"
        target.write_text("# Shared\n")
        os.symlink(str(target), str(tmp_path / "CLAUDE.md"))

        results = ci_glob(tmp_path, "CLAUDE.md")

        assert [p.name for p in results] == ["CLAUDE.md"]
