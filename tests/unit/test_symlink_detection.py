"""Unit tests for symlinked instruction file detection.

Ensures that instruction files which are symlinks pointing outside
the project are detected and their resolved paths collected for
regex engine extra targets.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from reporails_cli.core.applicability import (
    detect_features_filesystem,
    resolve_symlinked_files,
)


class TestResolveSymlinkedFiles:
    """Test resolve_symlinked_files() helper."""

    def test_no_symlinks_returns_empty(self, tmp_path: Path) -> None:
        """Regular files → no resolved symlinks."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")

        result = resolve_symlinked_files(project)

        assert result == []

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

    def test_broken_symlink_ignored(self, tmp_path: Path) -> None:
        """Broken symlink → ignored, no crash."""
        project = tmp_path / "project"
        project.mkdir()

        # Create dangling symlink
        os.symlink("/nonexistent/path/CLAUDE.md", str(project / "CLAUDE.md"))

        result = resolve_symlinked_files(project)

        assert result == []

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

        with caplog.at_level(logging.WARNING, logger="reporails_cli.core.applicability"):
            result = resolve_symlinked_files(project)

        assert result == []
        assert any("Circular symlink detected" in msg for msg in caplog.messages)

    def test_no_instruction_files_returns_empty(self, tmp_path: Path) -> None:
        """Project with no instruction files → empty list."""
        project = tmp_path / "project"
        project.mkdir()

        result = resolve_symlinked_files(project)

        assert result == []


class TestSymlinkFeatureDetection:
    """Test symlink handling in detect_features_filesystem."""

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

    def test_no_symlinks_empty_resolved(self, tmp_path: Path) -> None:
        """Regular project has empty resolved_symlinks."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")

        features = detect_features_filesystem(project)

        assert features.resolved_symlinks == []


class TestRegexExtraTargets:
    """Test extra_targets parameter in regex run_validation."""

    def test_extra_targets_scanned(self, tmp_path: Path) -> None:
        """Extra targets should be included in the scan."""
        # Create a rule that matches "SHARED_CONTENT"
        yml_file = tmp_path / "test.yml"
        yml_file.write_text("""\
rules:
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

        from reporails_cli.core.regex import run_validation

        sarif = run_validation(
            [yml_file],
            project,
            extra_targets=[external],
        )

        results = sarif.get("runs", [{}])[0].get("results", [])
        assert len(results) > 0, "Extra target file should be scanned and matched"

    def test_extra_targets_none_is_noop(self, tmp_path: Path) -> None:
        """No extra_targets → only main target scanned."""
        yml_file = tmp_path / "test.yml"
        yml_file.write_text("""\
rules:
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

        from reporails_cli.core.regex import run_validation

        sarif = run_validation([yml_file], project)

        results = sarif.get("runs", [{}])[0].get("results", [])
        assert len(results) > 0, "Main target should still be scanned"
