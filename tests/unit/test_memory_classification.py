"""Memory + subagent_memory directory entries classify to their capability type (not `generic`)."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify import _parse_file_types, classify_files
from reporails_cli.core.discovery.agent_discovery import (
    categorize_file_type,
    discover_from_config,
    load_config_file_types,
)


@pytest.fixture
def memory_fixture(tmp_path: Path) -> Path:
    """Project with .claude/agent-memory/<agent>/MEMORY.md + local variant + CLAUDE.md."""
    (tmp_path / ".claude" / "agent-memory" / "foo").mkdir(parents=True)
    (tmp_path / ".claude" / "agent-memory" / "foo" / "MEMORY.md").write_text("# foo memory\n")
    (tmp_path / ".claude" / "agent-memory-local" / "bar").mkdir(parents=True)
    (tmp_path / ".claude" / "agent-memory-local" / "bar" / "MEMORY.md").write_text("# bar local memory\n")
    (tmp_path / "CLAUDE.md").write_text(
        "# Project\n\nSee [foo](.claude/agent-memory/foo/MEMORY.md) and "
        "[bar](.claude/agent-memory-local/bar/MEMORY.md).\n"
    )
    return tmp_path


class TestCategorizeFileType:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_trailing_slash_pattern_is_instruction_not_skip(self) -> None:
        """memory + subagent_memory directory-glob patterns must enumerate, not skip."""
        assert (
            categorize_file_type(
                [".claude/agent-memory/*/", "~/.claude/agent-memory/*/"],
                {"scope": "task_scoped"},
            )
            == "instruction"
        )

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_absolute_system_paths_still_skip(self) -> None:
        """Managed-config absolute paths remain skipped — unchanged behavior."""
        assert categorize_file_type(["/etc/claude-code/CLAUDE.md"], {"format": "freeform"}) == "skip"


class TestMemoryClassification:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_subagent_memory_files_classify_as_subagent_memory(self, memory_fixture: Path) -> None:
        """.claude/agent-memory/<agent>/*.md + .claude/agent-memory-local/<agent>/*.md
        receive file_type=subagent_memory, NOT generic.
        """
        result = discover_from_config(memory_fixture, "claude")
        assert result is not None
        instruction, _rule, _config = result

        fts = load_config_file_types("claude")
        assert fts is not None
        file_types = _parse_file_types(fts)
        classified = classify_files(memory_fixture, instruction, file_types, generic_scanning=True)

        memory_files = {
            cf.path.relative_to(memory_fixture).as_posix(): cf.file_type
            for cf in classified
            if cf.path.is_relative_to(memory_fixture)
        }

        assert memory_files.get(".claude/agent-memory/foo/MEMORY.md") == "subagent_memory"
        assert memory_files.get(".claude/agent-memory-local/bar/MEMORY.md") == "subagent_memory"
        # Sanity: no memory file should land in the generic bucket
        assert "generic" not in (
            memory_files.get(".claude/agent-memory/foo/MEMORY.md"),
            memory_files.get(".claude/agent-memory-local/bar/MEMORY.md"),
        )

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_main_still_classifies_to_main(self, memory_fixture: Path) -> None:
        """CLAUDE.md at project root still gets file_type=main — fix did not regress main routing."""
        result = discover_from_config(memory_fixture, "claude")
        assert result is not None
        instruction, _rule, _config = result

        fts = load_config_file_types("claude")
        assert fts is not None
        file_types = _parse_file_types(fts)
        classified = classify_files(memory_fixture, instruction, file_types, generic_scanning=False)

        root_claude = next(
            (
                cf
                for cf in classified
                if cf.path.is_relative_to(memory_fixture)
                and cf.path.relative_to(memory_fixture).as_posix() == "CLAUDE.md"
            ),
            None,
        )
        assert root_claude is not None
        assert root_claude.file_type == "main"
