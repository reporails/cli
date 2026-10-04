"""Applicability unit tests — filesystem feature detection."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestDetectFeaturesFilesystem:
    """Test detect_features_filesystem with real temp directories."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_empty_directory_no_features(self, tmp_path: Path) -> None:
        """Empty directory should detect no features."""
        from reporails_cli.core.discovery.features import detect_features_filesystem

        features = detect_features_filesystem(tmp_path)

        assert features.has_claude_md is False
        assert features.has_instruction_file is False
        assert features.instruction_file_count == 0
        assert features.is_abstracted is False
        assert features.has_backbone is False
        assert features.has_multiple_instruction_files is False

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_claude_md_only(self, tmp_path: Path) -> None:
        """CLAUDE.md at root should be detected."""
        from reporails_cli.core.discovery.features import detect_features_filesystem

        (tmp_path / "CLAUDE.md").write_text("# My Project\n", encoding="utf-8")

        features = detect_features_filesystem(tmp_path)

        assert features.has_claude_md is True
        assert features.has_instruction_file is True
        assert features.instruction_file_count == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_claude_rules_dir_is_abstracted(self, tmp_path: Path) -> None:
        """Presence of .claude/rules/ with content should set is_abstracted."""
        from reporails_cli.core.discovery.features import detect_features_filesystem

        rules_dir = tmp_path / ".claude" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "style.md").write_text("# Style\n", encoding="utf-8")
        # Also create CLAUDE.md so the project has an instruction file
        (tmp_path / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")

        features = detect_features_filesystem(tmp_path)

        assert features.is_abstracted is True
