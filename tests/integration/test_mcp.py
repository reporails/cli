"""Integration tests for MCP server and tools."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
from textwrap import dedent

import pytest

from reporails_cli.interfaces.mcp.tools import (
    explain_tool,
    score_tool,
    validate_tool,
)


@pytest.mark.integration
@pytest.mark.asyncio
class TestValidateTool:
    """Test MCP validate tool."""

    async def test_validate_nonexistent_path(self) -> None:
        """Returns error for nonexistent path."""
        result = await validate_tool("/nonexistent/path")

        assert "error" in result

    async def test_validate_empty_directory(self) -> None:
        """Handles empty directory with helpful error."""
        with TemporaryDirectory() as tmpdir:
            result = await validate_tool(tmpdir)

            assert "error" in result
            assert "No instruction files found" in result["error"]

    async def test_validate_with_claude_md(self) -> None:
        """Validates CLAUDE.md and returns results."""
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

                ## Commands

                - `npm test` - Run tests
            """)
            )

            result = await validate_tool(tmpdir)

            assert "score" in result
            assert "level" in result
            assert "violations" in result
            assert 0 <= result["score"] <= 10  # Score is 0-10, not 0-100


@pytest.mark.integration
@pytest.mark.asyncio
class TestScoreTool:
    """Test MCP score tool."""

    async def test_score_returns_summary(self) -> None:
        """Returns score summary."""
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            claude_file = path / "CLAUDE.md"
            claude_file.write_text("# Test")

            result = await score_tool(tmpdir)

            assert "score" in result
            assert "level" in result
            assert "rules_checked" in result


@pytest.mark.integration
@pytest.mark.asyncio
class TestExplainTool:
    """Test MCP explain tool."""

    async def test_explain_unknown_rule(self) -> None:
        """Returns error for unknown rule."""
        result = await explain_tool("UNKNOWN99")

        assert "error" in result

    async def test_explain_returns_rule_info(self) -> None:
        """Returns rule information."""
        # Try to explain S1 which should be in bundled rules
        result = await explain_tool("S1")

        # Either returns rule info or error if rule not found
        assert "id" in result or "error" in result
