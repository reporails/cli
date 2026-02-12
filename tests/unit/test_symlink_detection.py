"""Unit tests for symlinked instruction file detection.

Ensures that instruction files which are symlinks pointing outside
the project are detected and their resolved paths collected for
OpenGrep extra targets.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

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


class TestOpenGrepExtraTargets:
    """Test extra_targets parameter in run_opengrep."""

    def test_extra_targets_appended_to_command(self, tmp_path: Path) -> None:
        """Extra targets are appended after the main target in the command."""
        from unittest.mock import MagicMock

        # Create a dummy yml file
        yml_file = tmp_path / "test.yml"
        yml_file.write_text("rules: []")

        # Create a dummy opengrep binary path
        opengrep_bin = tmp_path / "opengrep"
        opengrep_bin.write_text("#!/bin/sh\n")
        opengrep_bin.chmod(0o755)

        extra = Path("/some/external/file.md")

        with patch("reporails_cli.core.opengrep.runner.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            from reporails_cli.core.opengrep.runner import run_opengrep

            run_opengrep(
                [yml_file],
                tmp_path,
                opengrep_bin,
                extra_targets=[extra],
            )

            # Verify command includes extra target
            cmd = mock_run.call_args[0][0]
            assert str(extra) in cmd
            # Main target should come before extra target
            main_idx = cmd.index(str(tmp_path))
            extra_idx = cmd.index(str(extra))
            assert main_idx < extra_idx

    def test_extra_targets_none_is_noop(self, tmp_path: Path) -> None:
        """No extra_targets → command has single target only."""
        from unittest.mock import MagicMock

        yml_file = tmp_path / "test.yml"
        yml_file.write_text("rules: []")

        opengrep_bin = tmp_path / "opengrep"
        opengrep_bin.write_text("#!/bin/sh\n")
        opengrep_bin.chmod(0o755)

        with patch("reporails_cli.core.opengrep.runner.subprocess.run") as mock_run:
            mock_result = MagicMock()
            mock_result.returncode = 0
            mock_run.return_value = mock_result

            from reporails_cli.core.opengrep.runner import run_opengrep

            run_opengrep([yml_file], tmp_path, opengrep_bin)

            cmd = mock_run.call_args[0][0]
            # Only one path argument after all --config flags
            # The target should be the last element
            assert cmd[-1] == str(tmp_path)
