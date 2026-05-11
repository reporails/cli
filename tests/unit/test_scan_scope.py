"""Tests for scan scope containment.

Verifies that `ails check /foo` discovers files matching the agent's actual
loading model: ancestor walk from /foo to project root for eager files
(main, override), descendant walk from /foo for nested per-subdirectory files.

External instruction surface files (~/..., absolute paths from config patterns)
are intentionally included by agent discovery — they are part of the instruction
surface even though they live outside the repo. Scope assertions filter these out.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.agents import (
    clear_agent_cache,
    detect_agents,
    get_all_instruction_files,
    get_all_scannable_files,
)
from reporails_cli.core.classification import classify_files, load_file_types
from reporails_cli.core.engine_helpers import _find_project_root


def _is_external(f: Path, scope: Path) -> bool:
    """True if f is an external instruction surface file (outside any tmp scope)."""
    return not str(f).startswith("/tmp/")


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
        ├── .ails/backbone.yml
        ├── CLAUDE.md
        └── child/
            └── CLAUDE.md

    Returns the child directory path.
    """
    (tmp_path / ".git").mkdir()
    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "backbone.yml").write_text("version: 3\n")
    (tmp_path / "CLAUDE.md").write_text("# Parent instructions")

    child = tmp_path / "child"
    child.mkdir()
    (child / "CLAUDE.md").write_text("# Child instructions")

    return child


class TestDetectAgentsScope:
    """Agent detection must only find files under the given root."""

    def setup_method(self) -> None:
        clear_agent_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_child_does_not_see_parent_files(self, tmp_path: Path) -> None:
        """Running from child does NOT surface parent files — cwd is project root.

        Per the cwd-as-project-root semantic, `ails check child/` treats `child/`
        as the project root. Parent files outside that subtree are out of scope,
        regardless of whether a `.git` exists higher up.
        """
        child = _make_nested_project(tmp_path)
        agents = detect_agents(child)

        all_files: list[Path] = []
        for a in agents:
            all_files.extend(a.instruction_files)
            all_files.extend(a.rule_files)
            all_files.extend(a.config_files)

        local_files = [f for f in all_files if not _is_external(f, child)]
        for f in local_files:
            assert str(f).startswith(str(child)), f"File outside child scope: {f}"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_parent_sees_hierarchical_files(self, tmp_path: Path) -> None:
        """Running from project root: root CLAUDE.md is main, descendant is nested."""
        _make_nested_project(tmp_path)
        agents = detect_agents(tmp_path)

        all_files: list[Path] = []
        for a in agents:
            all_files.extend(a.instruction_files)
            all_files.extend(a.rule_files)

        paths = {f.as_posix() for f in all_files}
        assert any(p.endswith("/CLAUDE.md") and "/child/" not in p for p in paths), "Should find root CLAUDE.md"
        assert any("/child/CLAUDE.md" in p for p in paths), "Should find child CLAUDE.md via descendant walk"


class TestInstructionFilesScope:
    """get_all_instruction_files returns files inside cwd's subtree only (cwd = project root)."""

    def setup_method(self) -> None:
        clear_agent_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_child_scope_bounded_by_target(self, tmp_path: Path) -> None:
        """From child, files outside cwd's subtree are NOT in scope."""
        child = _make_nested_project(tmp_path)
        files = get_all_instruction_files(child)

        # All non-external files must be under child (cwd is the project root).
        local_files = [f for f in files if not _is_external(f, child)]
        for f in local_files:
            assert str(f).startswith(str(child)), f"File outside child subtree: {f}"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_child_finds_own_files_only(self, tmp_path: Path) -> None:
        """From child, only child's own files surface — parent files are out of scope."""
        child = _make_nested_project(tmp_path)
        files = get_all_instruction_files(child)
        paths = {f.as_posix() for f in files}

        assert (tmp_path / "CLAUDE.md").as_posix() not in paths, (
            "Parent CLAUDE.md must NOT surface — cwd is project root"
        )
        assert any("/child/CLAUDE.md" in p for p in paths), "Child CLAUDE.md must surface"
        # child.md is in child/.claude/rules/ — path_scoped descendant, surfaces
        assert any(p.endswith("/child.md") for p in paths)


class TestScannableFilesScope:
    """get_all_scannable_files returns ancestor + descendant files of cwd, bounded by project root."""

    def setup_method(self) -> None:
        clear_agent_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_child_scope_bounded_by_project_root(self, tmp_path: Path) -> None:
        child = _make_nested_project(tmp_path)
        files = get_all_scannable_files(child)

        # External instruction surface files (~/...) are by-design outside the repo
        local_files = [f for f in files if not _is_external(f, child)]
        for f in local_files:
            assert str(f).startswith(str(tmp_path)), f"File outside project root: {f}"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_child_does_not_include_parent_rules(self, tmp_path: Path) -> None:
        """parent.md lives in tmp_path/.claude/rules/ — path_scoped descendant from child, not in scope."""
        child = _make_nested_project(tmp_path)
        files = get_all_scannable_files(child)
        names = {f.name for f in files}

        assert "parent.md" not in names, "Parent rule file should not be in child scan"


class TestProjectRootVsScanRoot:
    """Ancestor walk is bounded by project root; descendant walk anchors at scan_root."""

    def setup_method(self) -> None:
        clear_agent_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_project_root_above_scan_root(self, tmp_path: Path) -> None:
        """Backbone project root above child: ancestor walk reaches it, files outside it are excluded."""
        child = _make_backbone_project(tmp_path)

        project_root = _find_project_root(child)
        assert project_root == tmp_path, "project_root should walk up to backbone"

        # Ancestor walk reaches tmp_path/CLAUDE.md (the parent main file). External
        # surface files are by-design outside; everything else stays within tmp_path.
        files = get_all_scannable_files(child)
        local_files = [f for f in files if not _is_external(f, child)]
        for f in local_files:
            assert str(f).startswith(str(tmp_path)), f"File outside project root: {f}"
        names = {f.name for f in files}
        assert "CLAUDE.md" in names

    @pytest.mark.unit
    @pytest.mark.subsys_lint
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

    @pytest.mark.unit
    @pytest.mark.subsys_lint
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

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_engine_uses_scan_root_agents(self, tmp_path: Path) -> None:
        """The engine detects agents at scan_root; ancestor walk surfaces parent files within project root."""
        child = _make_backbone_project(tmp_path)

        scan_root = child
        agents = detect_agents(scan_root)
        files = get_all_scannable_files(scan_root, agents=agents)

        # Files must be within the project root (tmp_path = backbone root).
        # External instruction surface files (~/...) are by-design outside the repo.
        local_files = [f for f in files if not _is_external(f, child)]
        for f in local_files:
            assert str(f).startswith(str(tmp_path)), f"File outside project root: {f}"


def _classify_for_agent(scan_root: Path, files: list[Path], agent: str) -> dict[str, str]:
    """Classify files via the agent's config and return {filename → file_type} for inspection."""
    file_types = load_file_types(agent)
    classified = classify_files(scan_root, files, file_types)
    out: dict[str, str] = {}
    for cf in classified:
        out[cf.path.as_posix()] = cf.file_type
    return out


class TestAncestorWalkAndClassification:
    """Discovery and classification mirror agent loading model."""

    def setup_method(self) -> None:
        clear_agent_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_target_files_only_no_ancestor_walk(self, tmp_path: Path) -> None:
        """Cwd is project root: parent CLAUDE.md files are NOT surfaced."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# root")
        a = tmp_path / "a"
        a.mkdir()
        (a / "CLAUDE.md").write_text("# a")
        b = a / "b"
        b.mkdir()

        # Running from `b` — both ancestors are out of scope
        files = get_all_instruction_files(b)
        names = {f.as_posix() for f in files}
        assert (tmp_path / "CLAUDE.md").as_posix() not in names
        assert (a / "CLAUDE.md").as_posix() not in names

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_files_above_target_are_out_of_scope(self, tmp_path: Path) -> None:
        """A file above the target is excluded even if a `.git` lives between them."""
        (tmp_path / "CLAUDE.md").write_text("# outside")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "CLAUDE.md").write_text("# repo")
        a = repo / "a"
        a.mkdir()
        (a / "CLAUDE.md").write_text("# a")

        # Running from `a` — neither tmp_path/CLAUDE.md nor repo/CLAUDE.md surfaces
        files = get_all_instruction_files(a)
        names = {f.as_posix() for f in files}
        assert (a / "CLAUDE.md").as_posix() in names
        assert (repo / "CLAUDE.md").as_posix() not in names
        assert (tmp_path / "CLAUDE.md").as_posix() not in names

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_nested_classified_not_as_main(self, tmp_path: Path) -> None:
        """A descendant CLAUDE.md must classify as child_instruction, not main.

        Regression test for the activepieces bug: nested per-package CLAUDE.md
        was being tagged `main`, causing the size rule to fire against it.
        """
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# root")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "CLAUDE.md").write_text("# sub")

        files = get_all_instruction_files(tmp_path)
        types = _classify_for_agent(tmp_path, files, "claude")

        assert types[(tmp_path / "CLAUDE.md").as_posix()] == "main"
        assert types[(sub / "CLAUDE.md").as_posix()] == "child_instruction"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_sibling_tree_excluded_from_subdir_run(self, tmp_path: Path) -> None:
        """Running from a subdirectory: parent + sibling files are all out of scope."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# root")
        a = tmp_path / "a"
        a.mkdir()
        (a / "CLAUDE.md").write_text("# a")
        sibling = tmp_path / "sibling"
        sibling.mkdir()
        (sibling / "CLAUDE.md").write_text("# sibling")
        b = a / "b"
        b.mkdir()

        # Running from `b` — only `b` and below are in scope
        files = get_all_instruction_files(b)
        names = {f.as_posix() for f in files}
        assert (tmp_path / "CLAUDE.md").as_posix() not in names
        assert (a / "CLAUDE.md").as_posix() not in names, "Parent CLAUDE.md must NOT surface — cwd is project root"
        assert (sibling / "CLAUDE.md").as_posix() not in names

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_local_override_at_target(self, tmp_path: Path) -> None:
        """CLAUDE.local.md surfaces at cwd; ancestors are out of scope."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# root")
        (tmp_path / "CLAUDE.local.md").write_text("# root local")
        a = tmp_path / "a"
        a.mkdir()
        (a / "CLAUDE.md").write_text("# a")
        (a / "CLAUDE.local.md").write_text("# a local")

        # Running from `a` — only `a/CLAUDE.local.md` surfaces; tmp_path's is out of scope
        files = get_all_instruction_files(a)
        names = {f.as_posix() for f in files}
        assert (a / "CLAUDE.local.md").as_posix() in names
        assert (tmp_path / "CLAUDE.local.md").as_posix() not in names

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_activepieces_shape(self, tmp_path: Path) -> None:
        """Monorepo regression: root AGENTS.md is main; per-package files are nested.

        Mirrors specs/tmp/activepieces/ shape — the user-reported bug:
        running `ails check` at the root tagged every per-package CLAUDE.md
        as main, triggering false-positive size violations.
        """
        (tmp_path / ".git").mkdir()
        (tmp_path / "AGENTS.md").write_text("# root agents")
        # Activepieces has a CLAUDE.md → AGENTS.md symlink at root
        (tmp_path / "CLAUDE.md").symlink_to(tmp_path / "AGENTS.md")
        packages = tmp_path / "packages"
        packages.mkdir()
        for sub, leaf in [
            ("shared", "CLAUDE.md"),
            ("server", "AGENTS.md"),
            ("pieces", "CLAUDE.md"),
            ("web", "AGENTS.md"),
        ]:
            d = packages / sub
            d.mkdir()
            (d / leaf).write_text(f"# {sub}")
        engine = packages / "server" / "engine"
        engine.mkdir()
        (engine / "CLAUDE.md").write_text("# engine")

        files = get_all_instruction_files(tmp_path)

        # Codex sees AGENTS.md files: root as main, packages/server and packages/web as nested
        codex_types = _classify_for_agent(tmp_path, files, "codex")
        assert codex_types.get((tmp_path / "AGENTS.md").as_posix()) == "main"
        assert codex_types.get((packages / "server" / "AGENTS.md").as_posix()) == "nested_context"
        assert codex_types.get((packages / "web" / "AGENTS.md").as_posix()) == "nested_context"

        # Claude sees CLAUDE.md files: nested ones are child_instruction, not main
        claude_types = _classify_for_agent(tmp_path, files, "claude")
        nested_claude_paths = [
            packages / "shared" / "CLAUDE.md",
            packages / "pieces" / "CLAUDE.md",
            packages / "server" / "engine" / "CLAUDE.md",
        ]
        for p in nested_claude_paths:
            assert claude_types.get(p.as_posix()) == "child_instruction", f"{p} must NOT be classified as main"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_copilot_root_only_pattern(self, tmp_path: Path) -> None:
        """`.github/copilot-instructions.md` is project-root-only — resolved from cwd."""
        (tmp_path / ".git").mkdir()
        gh = tmp_path / ".github"
        gh.mkdir()
        (gh / "copilot-instructions.md").write_text("# repo")
        # Stray copilot-instructions.md in a subdirectory of cwd
        sub_gh = tmp_path / "sub" / ".github"
        sub_gh.mkdir(parents=True)
        (sub_gh / "copilot-instructions.md").write_text("# stray")

        # Running from tmp_path (the project root) — only tmp_path/.github/ surfaces
        files = get_all_scannable_files(tmp_path)
        names = {f.as_posix() for f in files}
        assert (gh / "copilot-instructions.md").as_posix() in names
        assert (sub_gh / "copilot-instructions.md").as_posix() not in names


class TestProjectConfigSurfaceAdjustments:
    """`.ails/config.yml` surface include/exclude + Codex fallback filenames."""

    def setup_method(self) -> None:
        clear_agent_cache()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_codex_fallback_filenames_surface(self, tmp_path: Path) -> None:
        """`agents.codex.fallback_filenames` adds candidate main files for codex.

        `.codex/config.toml` is required to make codex unambiguously detected —
        without it, the codex/generic disambiguation drops codex (per the
        `_disambiguate_codex_generic` heuristic) and the fallback patterns
        attached to the codex agent never fire. The fixture mirrors a real
        Codex-using project.
        """
        (tmp_path / ".git").mkdir()
        (tmp_path / "AGENTS.md").write_text("# main")
        (tmp_path / "TEAM_GUIDE.md").write_text("# fallback")
        codex_dir = tmp_path / ".codex"
        codex_dir.mkdir()
        (codex_dir / "config.toml").write_text("# codex marker\n")
        ails = tmp_path / ".ails"
        ails.mkdir()
        (ails / "config.yml").write_text(
            'schema_version: "0.1.0"\nagents:\n  codex:\n    fallback_filenames: ["TEAM_GUIDE.md"]\n'
        )

        file_types = load_file_types("codex", project_root=tmp_path)
        files = get_all_instruction_files(tmp_path)
        types = {cf.path.name: cf.file_type for cf in classify_files(tmp_path, files, file_types)}
        assert types.get("AGENTS.md") == "main"
        assert types.get("TEAM_GUIDE.md") == "main", "fallback filename must classify as main"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_surface_exclude_drops_files(self, tmp_path: Path) -> None:
        """`surfaces.<agent>.<ft>.exclude` filters out matching files."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# main")
        legacy = tmp_path / "legacy"
        legacy.mkdir()
        (legacy / "CLAUDE.md").write_text("# legacy")
        ails = tmp_path / ".ails"
        ails.mkdir()
        (ails / "config.yml").write_text(
            'schema_version: "0.1.0"\nsurfaces:\n  claude.child_instruction:\n    exclude: ["legacy/**"]\n'
        )

        files = get_all_instruction_files(tmp_path)
        names = {f.as_posix() for f in files}
        assert (tmp_path / "CLAUDE.md").as_posix() in names
        assert (legacy / "CLAUDE.md").as_posix() not in names, "exclude pattern must drop matching files"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_config_local_layered_overrides_committed(self, tmp_path: Path) -> None:
        """`.ails/config.local.yml` layers on top of `.ails/config.yml`."""
        (tmp_path / ".git").mkdir()
        (tmp_path / "CLAUDE.md").write_text("# main")
        keep = tmp_path / "keep"
        keep.mkdir()
        (keep / "CLAUDE.md").write_text("# keep")
        drop = tmp_path / "drop"
        drop.mkdir()
        (drop / "CLAUDE.md").write_text("# drop")

        ails = tmp_path / ".ails"
        ails.mkdir()
        # Committed config: no excludes
        (ails / "config.yml").write_text('schema_version: "0.1.0"\n')
        # Local override: exclude drop/
        (ails / "config.local.yml").write_text('surfaces:\n  claude.child_instruction:\n    exclude: ["drop/**"]\n')

        files = get_all_instruction_files(tmp_path)
        names = {f.as_posix() for f in files}
        assert (keep / "CLAUDE.md").as_posix() in names
        assert (drop / "CLAUDE.md").as_posix() not in names

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_exclude_unions_across_overlapping_surfaces(self, tmp_path: Path) -> None:
        """An exclude on one surface drops matches from sibling surfaces too.

        `cursor.rules` and `cursor.bugbot_rules` both glob `.cursor/rules/**/*.mdc`.
        Without unioning, `surfaces.cursor.rules.exclude: [**/draft/**]` drops the
        file from `cursor.rules` but `cursor.bugbot_rules` re-surfaces it. The
        agent-wide union closes the gap: any exclude declared anywhere for the
        agent applies to every surface of that agent.
        """
        from reporails_cli.core.agent_discovery import discover_from_config
        from reporails_cli.core.platform.config.config import get_project_config

        (tmp_path / ".git").mkdir()
        (tmp_path / "AGENTS.md").write_text("# main")
        cursor_dir = tmp_path / ".cursor"
        cursor_dir.mkdir()
        (cursor_dir / "config.yml").write_text("# cursor marker\n")
        rules_dir = cursor_dir / "rules"
        rules_dir.mkdir()
        (rules_dir / "keep.mdc").write_text("---\ndescription: keep\n---\n# keep")
        draft_dir = rules_dir / "draft"
        draft_dir.mkdir()
        (draft_dir / "draft.mdc").write_text("---\ndescription: draft\n---\n# draft")

        ails = tmp_path / ".ails"
        ails.mkdir()
        (ails / "config.yml").write_text(
            'schema_version: "0.1.0"\nsurfaces:\n  cursor.rules:\n    exclude: ["**/draft/**"]\n'
        )

        project_config = get_project_config(tmp_path)
        result = discover_from_config(tmp_path, "cursor", project_config=project_config)
        assert result is not None
        instructions, rules, _configs = result
        all_paths = {p.as_posix() for p in instructions + rules}
        assert (rules_dir / "keep.mdc").as_posix() in all_paths
        assert (draft_dir / "draft.mdc").as_posix() not in all_paths, (
            "exclude on cursor.rules must also drop the file from cursor.bugbot_rules"
        )
