"""File classification integration tests.

Verifies that the classification engine correctly loads file types from
agent configs and produces usable classified file lists for downstream consumers.
"""

from __future__ import annotations

import pytest


class TestFileClassificationLoading:
    """Test that file_types load correctly from agent configs."""

    def test_load_claude_file_types(self) -> None:
        """Claude agent config should have file_types declarations."""
        from reporails_cli.core.bootstrap import get_agent_file_types

        file_types = get_agent_file_types("claude")
        if not file_types:
            pytest.skip("Framework not installed (no agent config available)")
        type_names = {ft.name for ft in file_types}
        assert "main" in type_names, "Claude config must declare 'main' file type"

    def test_load_unknown_agent_returns_empty(self) -> None:
        """Unknown agent should return empty list."""
        from reporails_cli.core.bootstrap import get_agent_file_types

        result = get_agent_file_types("nonexistent_agent_xyz")
        assert result == []

    def test_file_types_have_patterns(self) -> None:
        """Each file type must have at least one pattern."""
        from reporails_cli.core.bootstrap import get_agent_file_types

        file_types = get_agent_file_types("claude")
        if not file_types:
            pytest.skip("Framework not installed (no agent config available)")
        for ft in file_types:
            assert ft.patterns, f"File type '{ft.name}' has no patterns"

    def test_main_type_is_required(self) -> None:
        """The 'main' file type should be marked as required."""
        from reporails_cli.core.bootstrap import get_agent_file_types

        file_types = get_agent_file_types("claude")
        if not file_types:
            pytest.skip("Framework not installed (no agent config available)")
        main_types = [ft for ft in file_types if ft.name == "main"]
        assert main_types, "No 'main' file type found"
        assert main_types[0].required, "'main' file type should be required"

    def test_empty_string_agent_returns_empty(self) -> None:
        """Empty string agent should return empty list."""
        from reporails_cli.core.bootstrap import get_agent_file_types

        result = get_agent_file_types("")
        assert result == []
