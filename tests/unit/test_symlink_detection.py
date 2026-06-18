"""Unit tests for symlinked instruction file detection.

Ensures that instruction files which are symlinks pointing outside
the project are detected and their resolved paths collected for
regex engine extra targets.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from reporails_cli.core.discovery.features import (
    detect_features_filesystem,
    resolve_symlinked_files,
)

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="symlinks require admin on Windows")


class TestResolveSymlinkedFiles:
    """Test resolve_symlinked_files() helper."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_symlinks_returns_empty(self, tmp_path: Path) -> None:
        """Regular files → no resolved symlinks."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")

        result = resolve_symlinked_files(project)

        assert result == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_external_symlink_detected(self, tmp_path: Path) -> None:
        """CLAUDE.md symlink to file outside project → detected."""
        project = tmp_path / "project"
        project.mkdir()

        # Create target file outside project
        external = tmp_path / "shared" / "CLAUDE.md"
        external.parent.mkdir()
        external.write_text("# Shared Project Config\n")

        # Create symlink inside project
        os.symlink(str(external), str(project / "CLAUDE.md"))

        result = resolve_symlinked_files(project)

        assert len(result) == 1
        assert result[0] == external.resolve()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_internal_symlink_not_included(self, tmp_path: Path) -> None:
        """CLAUDE.md symlink to file within project → NOT included."""
        project = tmp_path / "project"
        project.mkdir()

        # Create target file inside project
        subdir = project / "templates"
        subdir.mkdir()
        (subdir / "CLAUDE.md").write_text("# Template\n")

        # Create symlink at root pointing to internal file
        os.symlink(str(subdir / "CLAUDE.md"), str(project / "CLAUDE.md"))

        result = resolve_symlinked_files(project)

        # Internal symlinks are handled by OpenGrep, so not included
        assert result == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_broken_symlink_ignored(self, tmp_path: Path) -> None:
        """Broken symlink → ignored, no crash."""
        project = tmp_path / "project"
        project.mkdir()

        # Create dangling symlink
        os.symlink("/nonexistent/path/CLAUDE.md", str(project / "CLAUDE.md"))

        result = resolve_symlinked_files(project)

        assert result == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_circular_symlink_warns(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
        """Circular symlink → skipped with warning log."""
        import logging

        project = tmp_path / "project"
        project.mkdir()

        # Create circular symlink: A -> B -> A
        a = project / "CLAUDE.md"
        b = project / "link_b"
        os.symlink(str(b), str(a))
        os.symlink(str(a), str(b))

        with caplog.at_level(logging.WARNING, logger="reporails_cli.core.platform.policy.applicability"):
            result = resolve_symlinked_files(project)

        assert result == []
        assert any("Circular symlink detected" in msg for msg in caplog.messages)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_instruction_files_returns_empty(self, tmp_path: Path) -> None:
        """Project with no instruction files → empty list."""
        project = tmp_path / "project"
        project.mkdir()

        result = resolve_symlinked_files(project)

        assert result == []


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

        assert features.has_claude_md is True
        assert features.has_instruction_file is True

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_resolved_symlinks_stored_in_features(self, tmp_path: Path) -> None:
        """External symlinks are stored in features.resolved_symlinks."""
        project = tmp_path / "project"
        project.mkdir()

        external = tmp_path / "shared" / "CLAUDE.md"
        external.parent.mkdir()
        external.write_text("# Shared Config\n")

        os.symlink(str(external), str(project / "CLAUDE.md"))

        features = detect_features_filesystem(project)

        assert len(features.resolved_symlinks) == 1
        assert features.resolved_symlinks[0] == external.resolve()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_symlinks_empty_resolved(self, tmp_path: Path) -> None:
        """Regular project has empty resolved_symlinks."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")

        features = detect_features_filesystem(project)

        assert features.resolved_symlinks == []


class TestRegexExtraTargets:
    """Test extra_targets parameter in regex run_validation."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_extra_targets_scanned(self, tmp_path: Path) -> None:
        """Extra targets should be included in the scan."""
        # Create a rule that matches "SHARED_CONTENT"
        yml_file = tmp_path / "test.yml"
        yml_file.write_text("""\
checks:
  - id: test.extra
    message: "Found shared content"
    severity: WARNING
    languages: [generic]
    pattern-regex: "SHARED_CONTENT"
    paths:
      include:
        - "**/*.md"
""")

        # Create main project
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Nothing here\n")

        # Create external file with matching content
        external = tmp_path / "shared" / "external.md"
        external.parent.mkdir()
        external.write_text("SHARED_CONTENT is here\n")

        from reporails_cli.core.lint.regex import run_validation

        sarif = run_validation(
            [yml_file],
            project,
            extra_targets=[external],
        )

        results = sarif.get("runs", [{}])[0].get("results", [])
        assert len(results) > 0, "Extra target file should be scanned and matched"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_extra_targets_none_is_noop(self, tmp_path: Path) -> None:
        """No extra_targets → only main target scanned."""
        yml_file = tmp_path / "test.yml"
        yml_file.write_text("""\
checks:
  - id: test.main
    message: "Found content"
    severity: WARNING
    languages: [generic]
    pattern-regex: "Hello"
    paths:
      include:
        - "**/*.md"
""")

        project = tmp_path / "project"
        project.mkdir()
        (project / "test.md").write_text("Hello World\n")

        from reporails_cli.core.lint.regex import run_validation

        sarif = run_validation([yml_file], project)

        results = sarif.get("runs", [{}])[0].get("results", [])
        assert len(results) > 0, "Main target should still be scanned"


class TestWalkGlobFollowsSymlinkedDirs:
    """Regression: `walk_glob` descends into symlinked directories.

    Files inside symlinked dirs must be visible to whole-repo discovery.
    """

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_finds_file_inside_symlinked_directory(self, tmp_path: Path) -> None:
        """A SKILL.md inside a directory symlink should appear in results."""
        from reporails_cli.core.discovery.agent_discovery import walk_glob

        # Canonical location outside the project
        canonical = tmp_path / "canonical" / "audit"
        canonical.mkdir(parents=True)
        (canonical / "SKILL.md").write_text("# Audit\n")

        # Project tree with a symlinked directory pointing at the canonical
        project = tmp_path / "project"
        skills_dir = project / ".claude" / "skills"
        skills_dir.mkdir(parents=True)
        os.symlink(str(canonical), str(skills_dir / "audit"))

        results = walk_glob(skills_dir, "SKILL.md", frozenset())

        rel = [str(p.relative_to(project)) for p in results]
        assert ".claude/skills/audit/SKILL.md" in rel

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_breaks_symlink_cycle(self, tmp_path: Path) -> None:
        """An `a -> b -> a` directory cycle must terminate the walk."""
        from reporails_cli.core.discovery.agent_discovery import walk_glob

        root = tmp_path / "root"
        a = root / "a"
        b = root / "b"
        a.mkdir(parents=True)
        b.mkdir()
        (a / "SKILL.md").write_text("# A\n")

        # Cycle: a/loop -> b, b/loop -> a
        os.symlink(str(b), str(a / "loop"))
        os.symlink(str(a), str(b / "loop"))

        results = walk_glob(root, "SKILL.md", frozenset())

        # Must find the file exactly once despite the cycle; must not hang.
        assert len(results) == 1
        assert results[0].name == "SKILL.md"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_dedupes_two_symlinks_to_same_target(self, tmp_path: Path) -> None:
        """Two surface paths symlinking to the same canonical dir → file
        appears once (canonical inode tracked in `visited_real`)."""
        from reporails_cli.core.discovery.agent_discovery import walk_glob

        canonical = tmp_path / "canonical" / "shared"
        canonical.mkdir(parents=True)
        (canonical / "SKILL.md").write_text("# Shared\n")

        project = tmp_path / "project"
        project.mkdir()
        os.symlink(str(canonical), str(project / "via_a"))
        os.symlink(str(canonical), str(project / "via_b"))

        results = walk_glob(project, "SKILL.md", frozenset())

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
