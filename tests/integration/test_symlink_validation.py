"""Integration tests for symlinked instruction file validation.

Requires OpenGrep to be installed.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


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

    def test_capability_detection_with_external_symlink(self, symlink_project: tuple[Path, Path]) -> None:
        """Symlinked CLAUDE.md should have its content features detected."""
        project, _external = symlink_project

        from reporails_cli.bundled import get_capability_patterns_path
        from reporails_cli.core.applicability import detect_features_filesystem
        from reporails_cli.core.capability import detect_features_content
        from reporails_cli.core.regex import run_validation

        features = detect_features_filesystem(project)
        assert features.has_claude_md is True
        assert len(features.resolved_symlinks) == 1

        # Run capability detection with extra targets
        capability_patterns = get_capability_patterns_path()
        if not capability_patterns.exists():
            pytest.skip("Capability patterns not available")

        sarif = run_validation(
            [capability_patterns],
            project,
            extra_targets=features.resolved_symlinks,
        )

        content_features = detect_features_content(sarif)

        # The external file has sections and constraints
        assert content_features.has_sections is True
        assert content_features.has_explicit_constraints is True

    def test_rule_validation_with_external_symlink(self, symlink_project: tuple[Path, Path]) -> None:
        """Symlinked CLAUDE.md with violations should have them detected."""
        project, external = symlink_project

        # Rewrite external file to be too long (trigger S1 if available)
        external.write_text("# Project\n\n" + "Line of content.\n" * 300)

        from reporails_cli.core.applicability import detect_features_filesystem

        features = detect_features_filesystem(project)
        assert features.has_claude_md is True
        assert len(features.resolved_symlinks) == 1
