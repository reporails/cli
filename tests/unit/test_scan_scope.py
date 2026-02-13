"""Tests for scan scope containment.

Verifies that `ails check /foo` only discovers and validates files inside /foo,
even when /foo is nested inside a larger project with .git or backbone markers.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.agents import (
    clear_agent_cache,
    detect_agents,
    get_all_instruction_files,
    get_all_scannable_files,
)
from reporails_cli.core.engine_helpers import _find_project_root


def _make_nested_project(tmp_path: Path) -> Path:
    """Create a parent project with a child subdirectory, each with instruction files.

    Structure:
        tmp/
        ├── .git/
        ├── CLAUDE.md              (parent)
        ├── .claude/rules/parent.md
        └── child/
            ├── CLAUDE.md          (child)
            └── .claude/rules/child.md

    Returns the child directory path.
    """
    # Parent project markers
    (tmp_path / ".git").mkdir()
    (tmp_path / "CLAUDE.md").write_text("# Parent instructions")
    (tmp_path / ".claude" / "rules").mkdir(parents=True)
    (tmp_path / ".claude" / "rules" / "parent.md").write_text("# Parent rule")

    # Child directory with its own instruction files
    child = tmp_path / "child"
    child.mkdir()
    (child / "CLAUDE.md").write_text("# Child instructions")
    (child / ".claude" / "rules").mkdir(parents=True)
    (child / ".claude" / "rules" / "child.md").write_text("# Child rule")

    return child


def _make_backbone_project(tmp_path: Path) -> Path:
    """Create a parent project with backbone.yml and a child subdirectory.

    Structure:
        tmp/
        ├── .git/
        ├── .reporails/backbone.yml
        ├── CLAUDE.md
        └── child/
            └── CLAUDE.md

    Returns the child directory path.
    """
    (tmp_path / ".git").mkdir()
    (tmp_path / ".reporails").mkdir()
    (tmp_path / ".reporails" / "backbone.yml").write_text("version: 3\n")
    (tmp_path / "CLAUDE.md").write_text("# Parent instructions")

    child = tmp_path / "child"
    child.mkdir()
    (child / "CLAUDE.md").write_text("# Child instructions")

    return child


class TestDetectAgentsScope:
    """Agent detection must only find files under the given root."""

    def setup_method(self) -> None:
        clear_agent_cache()

    def test_child_does_not_see_parent_files(self, tmp_path: Path) -> None:
        child = _make_nested_project(tmp_path)
        agents = detect_agents(child)

        all_files: list[Path] = []
        for a in agents:
            all_files.extend(a.instruction_files)
            all_files.extend(a.rule_files)
            all_files.extend(a.config_files)

        for f in all_files:
            assert str(f).startswith(str(child)), f"File outside child scope: {f}"

    def test_parent_sees_both(self, tmp_path: Path) -> None:
        _make_nested_project(tmp_path)
        agents = detect_agents(tmp_path)

        all_files: list[Path] = []
        for a in agents:
            all_files.extend(a.instruction_files)

        paths = {str(f) for f in all_files}
        assert any("child/CLAUDE.md" in p for p in paths), "Parent should see child files"
        assert any(p.endswith("tmp/CLAUDE.md") or "/CLAUDE.md" in p for p in paths)


class TestInstructionFilesScope:
    """get_all_instruction_files must only return files under the given root."""

    def setup_method(self) -> None:
        clear_agent_cache()

    def test_child_scope(self, tmp_path: Path) -> None:
        child = _make_nested_project(tmp_path)
        files = get_all_instruction_files(child)

        for f in files:
            assert str(f).startswith(str(child)), f"File outside child scope: {f}"

    def test_child_finds_its_own_files(self, tmp_path: Path) -> None:
        child = _make_nested_project(tmp_path)
        files = get_all_instruction_files(child)
        names = {f.name for f in files}

        assert "CLAUDE.md" in names
        assert "child.md" in names


class TestScannableFilesScope:
    """get_all_scannable_files must only return files under the given root."""

    def setup_method(self) -> None:
        clear_agent_cache()

    def test_child_scope(self, tmp_path: Path) -> None:
        child = _make_nested_project(tmp_path)
        files = get_all_scannable_files(child)

        for f in files:
            assert str(f).startswith(str(child)), f"File outside child scope: {f}"

    def test_child_does_not_include_parent_rules(self, tmp_path: Path) -> None:
        child = _make_nested_project(tmp_path)
        files = get_all_scannable_files(child)
        names = {f.name for f in files}

        assert "parent.md" not in names, "Parent rule file should not be in child scan"


class TestProjectRootVsScanRoot:
    """project_root can differ from scan_root, but scan must stay in scan_root."""

    def setup_method(self) -> None:
        clear_agent_cache()

    def test_project_root_above_scan_root(self, tmp_path: Path) -> None:
        """When project_root is above scan_root, file discovery still scoped to scan_root."""
        child = _make_backbone_project(tmp_path)

        project_root = _find_project_root(child)
        assert project_root == tmp_path, "project_root should walk up to backbone"

        # But file discovery must stay within child
        files = get_all_scannable_files(child)
        for f in files:
            assert str(f).startswith(str(child)), f"File outside scan scope: {f}"

    def test_project_root_equals_scan_root_when_no_parent(self, tmp_path: Path) -> None:
        """Standalone project: project_root == scan_root."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# Instructions")

        project_root = _find_project_root(tmp_path)
        assert project_root == tmp_path

        files = get_all_scannable_files(tmp_path)
        assert len(files) >= 1
        assert any(f.name == "CLAUDE.md" for f in files)


class TestPreDetectedAgentsBypass:
    """Pre-detected agents from a broader scope must not leak into narrower scans."""

    def setup_method(self) -> None:
        clear_agent_cache()

    def test_parent_agents_passed_to_child_scannable(self, tmp_path: Path) -> None:
        """Even if parent-scoped agents are passed, scannable files are from those agents."""
        child = _make_nested_project(tmp_path)

        # Detect at parent scope (the old bug)
        parent_agents = detect_agents(tmp_path)
        clear_agent_cache()

        # Pass parent agents to child-scoped call
        files = get_all_scannable_files(child, agents=parent_agents)

        # These files come from parent-detected agents — they WILL include parent files.
        # This is the documented API gap: if you pass agents from a different scope,
        # you get files from that scope. The fix is in the engine (don't pass wrong agents).
        parent_files = [f for f in files if not str(f).startswith(str(child))]
        assert len(parent_files) > 0, "Confirms parent agents leak (by design of agents param)"

    def test_engine_uses_scan_root_agents(self, tmp_path: Path) -> None:
        """The engine must detect agents at scan_root, not project_root."""
        child = _make_backbone_project(tmp_path)

        # This is what the engine should do (and now does)
        scan_root = child
        agents = detect_agents(scan_root)
        files = get_all_scannable_files(scan_root, agents=agents)

        for f in files:
            assert str(f).startswith(str(child)), f"File outside scan scope: {f}"
