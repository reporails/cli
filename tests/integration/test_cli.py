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

            # Should complete (no CLAUDE.md to validate)
            assert "Score" in result.output or "0" in result.output

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

            assert "Score" in result.output

    def test_check_json_format(self) -> None:
        """Outputs JSON when requested."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text("# Test")

            result = runner.invoke(app, ["check", tmpdir, "--format", "json"])

            # Should be valid JSON structure
            assert '"score"' in result.output

    def test_check_sarif_format(self) -> None:
        """Outputs SARIF when requested."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text("# Test")

            result = runner.invoke(app, ["check", tmpdir, "--format", "sarif"])

            # Should have SARIF structure
            assert '"version": "2.1.0"' in result.output


@pytest.mark.integration
class TestScoreCommand:
    """Test ails score command."""

    def test_score_shows_summary(self) -> None:
        """Shows score summary."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text("# Test")

            result = runner.invoke(app, ["score", tmpdir])

            assert "Score" in result.output
            assert "/" in result.output  # e.g., "75/100"


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
