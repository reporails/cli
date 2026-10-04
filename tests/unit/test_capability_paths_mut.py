"""Mutation-killing tests for core.classify.capability_paths.

Each test reddens when a specific injected operator bug returns (verified by
scripts/mutation_probe.py). See test_capability_paths.py for the plumbing suite.
Targets the pure location-filter helpers the higher-level tests don't reach.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.classify.capability_paths import (
    _decl_location_matches,
    _is_loose_leaf_pattern,
)
from reporails_cli.core.discovery.agent_discovery import is_excluded
from reporails_cli.core.platform.dto.models import FileTypeDeclaration


def _decl(scope: str, loading: str = "session_start") -> FileTypeDeclaration:
    return FileTypeDeclaration(
        name="t",
        patterns=("**/CLAUDE.md",),
        required=False,
        properties={"scope": scope, "loading": loading},
    )


# ── _decl_location_matches scope/loading gate (L289, L292, L293) ─────


class TestDeclLocationMatches:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_global_gate_requires_both_scope_and_loading(self, tmp_path: Path) -> None:
        # scope=global but loading!=session_start: the global loose-leaf clamp
        # must NOT apply, so a nested file still matches.
        # Kills L289 `and -> or`: `or` would enter the clamp on a loose-leaf
        # pattern and reject the nested file via in_ancestor_chain.
        nested = tmp_path / "sub" / "CLAUDE.md"
        assert _decl_location_matches(nested, _decl("global", "on_demand"), "**/CLAUDE.md", tmp_path) is True

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_global_session_start_non_loose_pattern_always_matches(self, tmp_path: Path) -> None:
        # scope=global + session_start with a NON-loose-leaf pattern falls
        # through to an unconditional match.
        # Kills L292 `return True -> False`.
        f = tmp_path / "anywhere.md"
        assert _decl_location_matches(f, _decl("global", "session_start"), ".claude/rules/git.md", tmp_path) is True

    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_nested_scope_rejects_root_level_file(self, tmp_path: Path) -> None:
        # A nested-scope declaration must reject a file sitting at the project
        # root (in the ancestor chain).
        # Kills L293 `== -> !=`: the mutant skips the nested branch and returns
        # the default True.
        root_file = tmp_path / "CLAUDE.md"
        assert _decl_location_matches(root_file, _decl("nested"), "**/CLAUDE.md", tmp_path) is False


# ── _is_loose_leaf_pattern (L305) ────────────────────────────────────


class TestLooseLeafPattern:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_pathed_pattern_is_not_loose_leaf(self) -> None:
        # A pattern with a directory separator is anchored, not loose-leaf.
        # Kills L305 `and -> or`: `or` returns True because "**" is absent even
        # though "/" is present.
        assert _is_loose_leaf_pattern("dir/foo.md") is False
        # Anchoring the positive side keeps the contract honest.
        assert _is_loose_leaf_pattern("CLAUDE.md") is True


# ── is_excluded out-of-tree path (L315) ───────────────────


class TestUnderExcludedDir:
    @pytest.mark.unit
    @pytest.mark.subsys_classify
    def test_path_outside_project_root_is_not_excluded(self, tmp_path: Path) -> None:
        # A path outside project_root can't be relativized; the ValueError path
        # must report "not excluded".
        # Kills L315 `return False -> True`.
        outside = Path("/totally/unrelated/elsewhere/file.md")
        assert is_excluded(outside, tmp_path, frozenset({"node_modules"})) is False
