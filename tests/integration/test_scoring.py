"""Scoring integration tests - test scoring through validation pipeline.

These tests require OpenGrep to be installed and use the full validation pipeline.
"""

from __future__ import annotations

from pathlib import Path


class TestValidationScoring:
    """Test scoring through validation pipeline."""

    def test_clean_project_scores_above_floor(self, level2_project: Path) -> None:
        """Level 2 project should score above the floor (not bottom-tier)."""
        from reporails_cli.core.engine import run_validation_sync

        result = run_validation_sync(level2_project, agent="claude")

        # A level 2 project (commands + architecture + constraints) won't ace
        # every content rule, but should clear the baseline
        assert result.score >= 5.0, (
            f"Level 2 project should score 5+, got {result.score}\n"
            f"Violations {result.violations}"
        )

    def test_score_reproducible_across_runs(self, level3_project: Path) -> None:
        """Same project should produce same score across runs."""
        from reporails_cli.core.engine import run_validation_sync

        scores = []
        for _ in range(3):
            result = run_validation_sync(level3_project, agent="claude")
            scores.append(result.score)

        assert len(set(scores)) == 1, (
            f"Score should be reproducible, got: {scores}"
        )

    def test_score_is_deterministic_for_same_content(self, tmp_path: Path) -> None:
        """Same content should produce same score across runs."""
        from reporails_cli.core.engine import run_validation_sync

        # Create project with content
        (tmp_path / "CLAUDE.md").write_text("""\
# Test Project

A test project.

## Commands

- `test` - Run tests

## Architecture

Simple architecture.
""")

        result1 = run_validation_sync(tmp_path, agent="claude")
        result2 = run_validation_sync(tmp_path, agent="claude")

        # Same content should give same score
        assert result1.score == result2.score, (
            f"Same content gave different scores: {result1.score} vs {result2.score}"
        )
