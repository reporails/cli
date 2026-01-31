"""Capability detection tests - level detection must be deterministic and correct.

The capability level (L1-L6) determines which rules are applied.
Detection must be consistent and based on actual project structure.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.models import Level


class TestFilesystemFeatureDetection:
    """Test Phase 1: filesystem-based feature detection."""

    def test_detect_instruction_file(self, level1_project: Path) -> None:
        """Detect presence of instruction file (CLAUDE.md)."""
        from reporails_cli.core.applicability import detect_features_filesystem

        features = detect_features_filesystem(level1_project)

        assert features.has_instruction_file, (
            f"Should detect CLAUDE.md in {level1_project}"
        )
        assert features.instruction_file_count >= 1

    def test_detect_rules_directory(self, level3_project: Path) -> None:
        """Detect presence of .claude/rules/ directory."""
        from reporails_cli.core.applicability import detect_features_filesystem

        features = detect_features_filesystem(level3_project)

        assert features.has_rules_dir, (
            f"Should detect .claude/rules/ in {level3_project}"
        )

    def test_detect_backbone(self, level5_project: Path) -> None:
        """Detect presence of .reporails/backbone.yml."""
        from reporails_cli.core.applicability import detect_features_filesystem

        features = detect_features_filesystem(level5_project)

        assert features.has_backbone, (
            f"Should detect backbone.yml in {level5_project}"
        )

    def test_empty_directory_has_no_features(self, tmp_path: Path) -> None:
        """Empty directory should have no features detected."""
        from reporails_cli.core.applicability import detect_features_filesystem

        features = detect_features_filesystem(tmp_path)

        assert not features.has_instruction_file
        assert not features.has_rules_dir
        assert not features.has_backbone
        assert features.instruction_file_count == 0


class TestContentFeatureDetection:
    """Test Phase 2: content-based feature detection via OpenGrep."""

    def test_detect_sections_in_content(
        self,
        level2_project: Path,
        opengrep_bin: Path,
    ) -> None:
        """Detect markdown sections (## headings) in content."""
        from reporails_cli.core.capability import detect_features_content
        from reporails_cli.core.opengrep import run_capability_detection

        sarif = run_capability_detection(level2_project)
        content_features = detect_features_content(sarif)

        assert content_features.has_sections, (
            "Should detect ## headings in CLAUDE.md"
        )

    def test_detect_explicit_constraints(
        self,
        level2_project: Path,
        opengrep_bin: Path,
    ) -> None:
        """Detect MUST/NEVER constraints in content."""
        from reporails_cli.core.capability import detect_features_content
        from reporails_cli.core.opengrep import run_capability_detection

        sarif = run_capability_detection(level2_project)
        content_features = detect_features_content(sarif)

        assert content_features.has_explicit_constraints, (
            "Should detect MUST/NEVER in level2 CLAUDE.md"
        )


class TestCapabilityLevelDetermination:
    """Test capability level determination from features."""

    def test_level1_minimal_project(self, level1_project: Path) -> None:
        """Level 1 project should be detected as L1 or L2."""
        from reporails_cli.core.applicability import detect_features_filesystem
        from reporails_cli.core.capability import (
            detect_features_content,
            determine_capability_level,
        )
        from reporails_cli.core.opengrep import run_capability_detection

        features = detect_features_filesystem(level1_project)
        sarif = run_capability_detection(level1_project)
        content_features = detect_features_content(sarif)

        result = determine_capability_level(features, content_features)

        # Minimal project should be L1 or L2
        assert result.level in (Level.L1, Level.L2), (
            f"Minimal project should be L1-L2, got {result.level}"
        )

    def test_level2_basic_project(self, level2_project: Path) -> None:
        """Level 2 project should be detected as L2 or L3."""
        from reporails_cli.core.applicability import detect_features_filesystem
        from reporails_cli.core.capability import (
            detect_features_content,
            determine_capability_level,
        )
        from reporails_cli.core.opengrep import run_capability_detection

        features = detect_features_filesystem(level2_project)
        sarif = run_capability_detection(level2_project)
        content_features = detect_features_content(sarif)

        result = determine_capability_level(features, content_features)

        # Basic project with sections should be at least L2
        assert result.level.value >= Level.L2.value, (
            f"Project with sections should be at least L2, got {result.level}"
        )

    def test_level3_structured_project(self, level3_project: Path) -> None:
        """Level 3 project should be detected as L3 or higher."""
        from reporails_cli.core.applicability import detect_features_filesystem
        from reporails_cli.core.capability import (
            detect_features_content,
            determine_capability_level,
        )
        from reporails_cli.core.opengrep import run_capability_detection

        features = detect_features_filesystem(level3_project)
        sarif = run_capability_detection(level3_project)
        content_features = detect_features_content(sarif)

        result = determine_capability_level(features, content_features)

        # Project with rules dir should be at least L3
        assert result.level.value >= Level.L3.value, (
            f"Project with .claude/rules/ should be at least L3, got {result.level}"
        )

    def test_level5_governed_project(self, level5_project: Path) -> None:
        """Level 5 project should be detected as L5 or L6."""
        from reporails_cli.core.applicability import detect_features_filesystem
        from reporails_cli.core.capability import (
            detect_features_content,
            determine_capability_level,
        )
        from reporails_cli.core.opengrep import run_capability_detection

        features = detect_features_filesystem(level5_project)
        sarif = run_capability_detection(level5_project)
        content_features = detect_features_content(sarif)

        result = determine_capability_level(features, content_features)

        # Project with backbone should be at least L4
        assert result.level.value >= Level.L4.value, (
            f"Project with backbone.yml should be at least L4, got {result.level}"
        )

    def test_missing_files_lowers_level(self, tmp_path: Path) -> None:
        """Missing expected files should result in lower level, not error."""
        from reporails_cli.core.applicability import detect_features_filesystem
        from reporails_cli.core.capability import (
            detect_features_content,
            determine_capability_level,
        )
        from reporails_cli.core.opengrep import run_capability_detection

        # Create minimal structure
        (tmp_path / "CLAUDE.md").write_text("# Test\n")

        features = detect_features_filesystem(tmp_path)
        sarif = run_capability_detection(tmp_path)
        content_features = detect_features_content(sarif)

        # Should not raise error
        result = determine_capability_level(features, content_features)

        assert result.level is not None, "Should determine a level even for minimal project"


class TestLevelDeterminism:
    """Test that level detection is deterministic."""

    def test_same_project_same_level(self, level3_project: Path) -> None:
        """Same project should always detect same level."""
        from reporails_cli.core.applicability import detect_features_filesystem
        from reporails_cli.core.capability import (
            detect_features_content,
            determine_capability_level,
        )
        from reporails_cli.core.opengrep import run_capability_detection

        results = []
        for _ in range(3):
            features = detect_features_filesystem(level3_project)
            sarif = run_capability_detection(level3_project)
            content_features = detect_features_content(sarif)
            result = determine_capability_level(features, content_features)
            results.append(result.level)

        assert len(set(results)) == 1, (
            f"Level detection should be deterministic, got different results: {results}"
        )

    def test_same_features_same_level(self, level3_project: Path) -> None:
        """Same features should always map to same level."""
        from reporails_cli.core.applicability import detect_features_filesystem
        from reporails_cli.core.capability import (
            detect_features_content,
            merge_content_features,
        )
        from reporails_cli.core.levels import determine_level_from_gates
        from reporails_cli.core.opengrep import run_capability_detection

        features = detect_features_filesystem(level3_project)
        sarif = run_capability_detection(level3_project)
        content_features = detect_features_content(sarif)
        merge_content_features(features, content_features)

        # Same features should always give same level
        levels = [determine_level_from_gates(features) for _ in range(5)]
        assert len(set(levels)) == 1, (
            f"Same features should give same level, got: {levels}"
        )
