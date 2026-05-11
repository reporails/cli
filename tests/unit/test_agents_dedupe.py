"""Unit tests for symlink + content-hash deduplication in `core/agents.py`.

Multi-agent projects often expose the same physical file via several agent
surfaces — `.claude/skills/` symlinked to `.agents/skills/`, or AGENTS.md
manually copied to CLAUDE.md so codex and Claude both load it. The dedup
pipeline collapses symlinked discoveries (correctness fix — they would
otherwise inflate the score) and reports same-directory content-hash
duplicates as display-only aliases (so AGENTS.md + CLAUDE.md still classify
under their respective agents but render as one row).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from reporails_cli.core.agents import (
    _dedupe_with_aliases,
    compute_same_dir_content_aliases,
    get_all_instruction_files,
    get_file_aliases,
)


class TestDedupeWithAliases:
    """Verify `_dedupe_with_aliases` collapses symlinks but leaves
    same-dir content-identical files in place."""

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks require admin on Windows")
    def test_symlinked_paths_collapse_to_one_canonical(self, tmp_path: Path) -> None:
        """A real file plus a symlink to it → one canonical + one alias."""
        real = tmp_path / ".agents" / "skills" / "x"
        real.mkdir(parents=True)
        skill = real / "SKILL.md"
        skill.write_text("# x\n")

        claude_dir = tmp_path / ".claude"
        claude_dir.mkdir()
        os.symlink(str(real.parent), str(claude_dir / "skills"))

        canonical, aliases = _dedupe_with_aliases([skill, claude_dir / "skills" / "x" / "SKILL.md"])

        assert canonical == [skill]
        assert aliases == {skill: [claude_dir / "skills" / "x" / "SKILL.md"]}

    def test_duplicate_identical_paths_collapse_without_self_alias(self, tmp_path: Path) -> None:
        """Same path discovered by multiple agents must not appear as its own alias."""
        f = tmp_path / "AGENTS.md"
        f.write_text("# x\n")

        canonical, aliases = _dedupe_with_aliases([f, f, f])

        assert canonical == [f]
        assert aliases == {}

    def test_same_dir_identical_content_not_deduped_at_discovery(self, tmp_path: Path) -> None:
        """AGENTS.md and CLAUDE.md with matching content stay separate at discovery —
        each must remain classifiable under its own agent's `main` file_type.
        Display layer collapses them via `compute_same_dir_content_aliases`."""
        body = "# Project\nLine.\n"
        (tmp_path / "AGENTS.md").write_text(body)
        (tmp_path / "CLAUDE.md").write_text(body)

        canonical, aliases = _dedupe_with_aliases([tmp_path / "AGENTS.md", tmp_path / "CLAUDE.md"])

        assert canonical == sorted([tmp_path / "AGENTS.md", tmp_path / "CLAUDE.md"])
        assert aliases == {}


class TestComputeSameDirContentAliases:
    """Verify display-time content-hash grouping is restricted to same parent dir."""

    def test_identical_content_same_dir_grouped(self, tmp_path: Path) -> None:
        body = "# X\nHello.\n"
        (tmp_path / "AGENTS.md").write_text(body)
        (tmp_path / "CLAUDE.md").write_text(body)

        result = compute_same_dir_content_aliases([tmp_path / "AGENTS.md", tmp_path / "CLAUDE.md"])

        assert result == {tmp_path / "AGENTS.md": [tmp_path / "CLAUDE.md"]}

    def test_identical_content_different_dirs_not_grouped(self, tmp_path: Path) -> None:
        """Same content in two different directories must not collapse —
        the files are independent surfaces that can diverge later."""
        body = "# X\nHello.\n"
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "f.md").write_text(body)
        (tmp_path / "b" / "f.md").write_text(body)

        result = compute_same_dir_content_aliases([tmp_path / "a" / "f.md", tmp_path / "b" / "f.md"])

        assert result == {}

    def test_differing_content_same_dir_not_grouped(self, tmp_path: Path) -> None:
        (tmp_path / "AGENTS.md").write_text("# A\n")
        (tmp_path / "CLAUDE.md").write_text("# B (different)\n")

        result = compute_same_dir_content_aliases([tmp_path / "AGENTS.md", tmp_path / "CLAUDE.md"])

        assert result == {}


class TestGetAllInstructionFilesIntegration:
    """End-to-end: discovery + dedup + alias cache for `get_all_instruction_files`."""

    @pytest.mark.skipif(sys.platform == "win32", reason="symlinks require admin on Windows")
    def test_symlinked_skill_discovered_once_aliases_populated(self, tmp_path: Path) -> None:
        """A skill symlinked across two agent surfaces collapses, alias cache populated."""
        (tmp_path / "AGENTS.md").write_text("# Main\n")
        (tmp_path / ".agents" / "skills" / "demo").mkdir(parents=True)
        (tmp_path / ".agents" / "skills" / "demo" / "SKILL.md").write_text("# demo\n")
        (tmp_path / ".claude").mkdir()
        os.symlink(str(tmp_path / ".agents" / "skills"), str(tmp_path / ".claude" / "skills"))
        (tmp_path / "CLAUDE.md").write_text("# Claude\n")

        files = get_all_instruction_files(tmp_path)
        aliases = get_file_aliases(tmp_path)

        skill_paths = [f for f in files if f.name == "SKILL.md"]
        assert len(skill_paths) == 1, f"Expected 1 SKILL.md after dedup, got {skill_paths}"

        canonical = skill_paths[0]
        assert canonical in aliases
        assert any("claude" in str(a) for a in aliases[canonical])
