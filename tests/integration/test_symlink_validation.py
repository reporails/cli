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


_onnx_path = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
)
requires_model = pytest.mark.skipif(not _onnx_path.exists(), reason="Bundled ONNX model not available")


class TestSymlinkIntegration:
    """Integration tests for symlinked instruction file handling."""

    @pytest.mark.integration
    @pytest.mark.subsys_lint
    @requires_model
    def test_rule_validation_with_external_symlink(self, symlink_project: tuple[Path, Path]) -> None:
        """A CLAUDE.md symlinked to a file outside the project is checked and its violations reported."""
        from reporails_cli.core.lint.client_checks import run_client_checks
        from reporails_cli.core.mapper.models import get_models
        from reporails_cli.core.mapper.pipeline import map_ruleset

        project, external = symlink_project
        external.write_text("# Project\n\nRun build.sh before every commit.\n", encoding="utf-8")

        link = project / "CLAUDE.md"
        assert link.is_symlink()
        ruleset = map_ruleset([link], models=get_models(), root=project, cache_dir=None)
        reported = {f.line for f in run_client_checks(ruleset) if f.check_id == "format"}
        assert reported == {3}
