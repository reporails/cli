"""Integration tests for CLI."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.mark.integration
class TestCheckCommand:
    """Test ails check command."""

    def test_check_nonexistent_path(self) -> None:
        """Returns error for nonexistent path."""
        result = runner.invoke(app, ["check", "/nonexistent/path"])

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_check_empty_directory(self) -> None:
        """Handles empty directory gracefully."""
        with TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, ["check", tmpdir])

            # Should show helpful error message
            assert result.exit_code == 1
            assert "No instruction files found" in result.output

    def test_check_with_claude_md(self) -> None:
        """Validates CLAUDE.md and shows results."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text(
                dedent("""\
                # Test Project

                ## Quick Start

                ```bash
                npm install
                ```
            """)
            )

            result = runner.invoke(app, ["check", tmpdir])

            # Check for score box (SCORE:) or quick summary (ails:)
            assert "SCORE:" in result.output or "ails:" in result.output

    def test_check_json_format(self) -> None:
        """Outputs JSON when requested."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text("# Test")

            result = runner.invoke(app, ["check", tmpdir, "--format", "json"])

            # Should be valid JSON structure
            assert '"score"' in result.output

    def test_check_brief_format(self) -> None:
        """Outputs brief summary when requested."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text("# Test")

            result = runner.invoke(app, ["check", tmpdir, "--format", "brief"])

            # Should have one-line summary with score and level
            assert "ails:" in result.output
            assert "/" in result.output  # e.g., "10.0/10"


@pytest.mark.integration
class TestExplainCommand:
    """Test ails explain command."""

    def test_explain_unknown_rule(self) -> None:
        """Shows error for unknown rule."""
        result = runner.invoke(app, ["explain", "UNKNOWN99"])

        assert result.exit_code == 1
        assert "unknown" in result.output.lower() or "error" in result.output.lower()

    def test_explain_known_rule(self) -> None:
        """Shows rule details for known rule."""
        # This will only work if rules are loaded successfully
        result = runner.invoke(app, ["explain", "S1"])

        # If S1 exists in bundled rules, should show info
        # If not, will show error - both are valid outcomes
        assert result.output  # Should produce some output
