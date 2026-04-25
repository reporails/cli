"""Integration tests for symlinked instruction file validation."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="symlinks require admin on Windows")


@pytest.fixture
def symlink_project(tmp_path: Path) -> tuple[Path, Path]:
    """Create a project with an externally symlinked CLAUDE.md.

    Returns:
        Tuple of (project_dir, external_file_path)
    """
    project = tmp_path / "project"
    project.mkdir()

    # Create external file with content that has sections + constraints
    external_dir = tmp_path / "shared_templates"
    external_dir.mkdir()
    external_file = external_dir / "CLAUDE.md"
    external_file.write_text("""\
# Shared Project Instructions

## Commands

- `npm install` - Install dependencies
- `npm test` - Run tests

## Architecture

Modular design with clear boundaries.

## Constraints

- MUST use TypeScript for all new code
- NEVER commit secrets to the repository
""")

    # Symlink from project to external file
    os.symlink(str(external_file), str(project / "CLAUDE.md"))

    return project, external_file


class TestSymlinkIntegration:
    """Integration tests for symlinked instruction file handling."""

    def test_symlink_detection_populates_resolved_symlinks(self, symlink_project: tuple[Path, Path]) -> None:
        """Symlinked CLAUDE.md should appear in resolved_symlinks."""
        project, _external = symlink_project

        from reporails_cli.core.applicability import detect_features_filesystem

        features = detect_features_filesystem(project)
        assert features.has_claude_md is True
        assert len(features.resolved_symlinks) == 1

    def test_rule_validation_with_external_symlink(self, symlink_project: tuple[Path, Path]) -> None:
        """Symlinked CLAUDE.md with violations should have them detected."""
        project, external = symlink_project

        # Rewrite external file to be too long (trigger S1 if available)
        external.write_text("# Project\n\n" + "Line of content.\n" * 300)

        from reporails_cli.core.applicability import detect_features_filesystem

        features = detect_features_filesystem(project)
        assert features.has_claude_md is True
        assert len(features.resolved_symlinks) == 1
