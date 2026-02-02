"""Unit tests ensuring backbone.yml detection reflects actual project state.

The backbone gate must NOT always evaluate to true — it should only be true
when the project already has a backbone.yml before validation runs.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.applicability import detect_features_filesystem
from reporails_cli.core.levels import determine_level_from_gates
from reporails_cli.core.models import DetectedFeatures, Level


class TestBackboneGateNotAlwaysTrue:
    """Verify backbone detection reflects actual project state."""

    def test_no_backbone_yields_false_gate(self, tmp_path: Path) -> None:
        """Project without .reporails/backbone.yml → has_backbone is False."""
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

        reporails_dir = project / ".reporails"
        reporails_dir.mkdir()
        (reporails_dir / "backbone.yml").write_text(
            "version: 2\nagents:\n  claude:\n    rules: .claude/rules/\n"
        )

        features = detect_features_filesystem(project)

        assert features.has_backbone is True

    def test_backbone_gate_does_not_affect_level_when_absent(
        self, tmp_path: Path
    ) -> None:
        """L4-level project without backbone should NOT reach L6."""
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_sections=True,
            has_imports=True,
            has_rules_dir=True,
            # No backbone, no shared files, no component count
        )
        level = determine_level_from_gates(features)

        assert level != Level.L6
        assert level == Level.L4

    def test_backbone_gate_grants_l6_with_real_backbone(self) -> None:
        """Full project with backbone → L6 when all other gates pass."""
        features = DetectedFeatures(
            has_instruction_file=True,
            has_explicit_constraints=True,
            has_sections=True,
            has_imports=True,
            has_rules_dir=True,
            component_count=3,
            has_shared_files=True,
            has_backbone=True,
        )
        level = determine_level_from_gates(features)

        assert level == Level.L6

    def test_placeholder_backbone_not_detected_before_creation(
        self, tmp_path: Path
    ) -> None:
        """Feature detection runs before backbone auto-creation.

        The .reporails/ directory should not exist before detection,
        so has_backbone must be False.
        """
        project = tmp_path / "project"
        project.mkdir()
        (project / "CLAUDE.md").write_text("# Project\n")

        # Ensure no .reporails directory
        assert not (project / ".reporails").exists()

        features = detect_features_filesystem(project)

        assert features.has_backbone is False
        # .reporails still doesn't exist (engine creates it, not detect_features)
        assert not (project / ".reporails" / "backbone.yml").exists()
