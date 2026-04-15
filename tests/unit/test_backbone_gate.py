"""Unit tests ensuring feature detection reflects actual project state.

Verifies that detect_features_filesystem populates display-only features
correctly for the feature summary.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.applicability import detect_features_filesystem


class TestFeatureDetection:
    """Verify filesystem feature detection for display purposes."""

    def test_no_backbone_yields_false(self, tmp_path: Path) -> None:
        """Project without .ails/backbone.yml → has_backbone is False."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")

        features = detect_features_filesystem(project)

        assert features.has_backbone is False

    def test_real_backbone_detected(self, tmp_path: Path) -> None:
        """Project with a real backbone.yml → has_backbone is True."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")

        ails_dir = project / ".ails"
        ails_dir.mkdir()
        (ails_dir / "backbone.yml").write_text("version: 2\nagents:\n  claude:\n    rules: .claude/rules/\n")

        features = detect_features_filesystem(project)

        assert features.has_backbone is True

    def test_abstracted_structure_detected(self, tmp_path: Path) -> None:
        """Project with .claude/rules/ → is_abstracted is True."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")
        rules_dir = project / ".claude" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "test.md").write_text("# Rule\n")

        features = detect_features_filesystem(project)

        assert features.is_abstracted is True

    def test_shared_files_detected(self, tmp_path: Path) -> None:
        """Project with shared/ directory → has_shared_files is True."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")
        (project / "shared").mkdir()

        features = detect_features_filesystem(project)

        assert features.has_shared_files is True

    def test_placeholder_backbone_not_detected_before_creation(self, tmp_path: Path) -> None:
        """Feature detection runs before backbone auto-creation."""
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")

        assert not (project / ".ails").exists()

        features = detect_features_filesystem(project)

        assert features.has_backbone is False
        assert not (project / ".ails" / "backbone.yml").exists()
