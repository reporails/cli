"""Integration tests for validation engine."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent

import pytest

from reporails_cli.core.engine import _discover_instruction_files, run_validation_sync
from reporails_cli.core.models import Level


class TestFindClaudeFiles:
    """Test _discover_instruction_files function."""

    def test_finds_root_claude_md(self) -> None:
        """Finds CLAUDE.md in root directory."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text("# Test")

            files = _discover_instruction_files(path)

            assert len(files) == 1
            assert files[0].name == "CLAUDE.md"

    def test_finds_claude_directory_files(self) -> None:
        """Finds .md files in .claude directory."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_dir = path / ".claude"
            claude_dir.mkdir()
            (claude_dir / "commands.md").write_text("# Commands")
            (claude_dir / "architecture.md").write_text("# Architecture")

            files = _discover_instruction_files(path)

            assert len(files) == 2

    def test_returns_empty_for_no_files(self) -> None:
        """Returns empty list when no CLAUDE.md found."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            files = _discover_instruction_files(path)

            assert files == []

    def test_handles_direct_file_path(self) -> None:
        """Handles direct path to CLAUDE.md."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text("# Test")

            files = _discover_instruction_files(claude_file)

            assert len(files) == 1


@pytest.mark.integration
class TestRunValidation:
    """Integration tests for run_validation."""

    def test_validates_empty_directory(self) -> None:
        """Handles directory without CLAUDE.md."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            result = run_validation_sync(path)

            assert result.score == 0
            assert result.rules_checked == 0

    def test_validates_simple_claude_md(self) -> None:
        """Validates a simple CLAUDE.md file."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text(
                dedent("""\
                # My Project

                ## Quick Start

                ```bash
                npm install
                npm run build
                ```

                ## Commands

                - `npm test` - Run tests
                - `npm run lint` - Run linter
            """)
            )

            result = run_validation_sync(path)

            # Should get a score (may have violations depending on rules)
            assert result.score >= 0
            assert result.score <= 100
            assert result.level in Level

    def test_generates_judgment_requests_for_semantic_rules(self) -> None:
        """Creates judgment requests for semantic rules."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text(
                dedent("""\
                # Test Project

                Just some content without clear philosophy or structure.
            """)
            )

            result = run_validation_sync(path)

            # Should have judgment requests for semantic rules
            # (depends on which semantic rules are defined)
            assert isinstance(result.judgment_requests, tuple)
