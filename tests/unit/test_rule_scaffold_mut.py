"""Mutation-killing tests for core.lint.rule_scaffold.

Each test reddens when a specific injected operator bug returns (verified by
scripts/mutation_probe.py). See test_harness.py for the broader behavioral suite.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from reporails_cli.core.lint.rule_scaffold import (
    _scaffold_fail_fixture,
    _scaffold_fixture,
)
from reporails_cli.core.platform.dto.models import Check


def _c(d: dict) -> Check:
    """Wrap a scaffold-test check dict as a Check (id is required but unused by scaffolding)."""
    return Check.model_validate({"id": "CORE.S.0001.check", **d})


# ── git_marker: `and` guard (L95) ────────────────────────────────────


class TestGitMarkerGuard:
    """The git_marker action creates a marker ONLY when neither .git_marker
    nor .git already exists (an `and` of two negations)."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_marker_created_when_git_dir_present(self, tmp_path: Path) -> None:
        # Kills L95 `and -> or`: with `or`, a marker would be created even
        # though a real .git dir already satisfies git_tracked.
        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()
        (fixture_dir / ".git").mkdir()

        checks = [_c({"type": "mechanical", "check": "git_tracked"})]
        result = _scaffold_fixture(fixture_dir, checks, [])

        assert result is not None
        assert not (result / ".git_marker").exists()
        shutil.rmtree(result)


# ── _scaffold_file: exist_ok on an existing parent (L116) ────────────


class TestScaffoldFileTopLevelParent:
    """A top-level concrete file has tmp_dir itself as its parent, which
    already exists — so exist_ok must stay True."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_top_level_file_scaffold_succeeds(self, tmp_path: Path) -> None:
        # Kills L116 `exist_ok=True -> False`: mkdir on the already-existing
        # tmp_dir parent raises FileExistsError when exist_ok is False.
        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [_c({"type": "mechanical", "check": "file_exists", "args": {"path": "**/*.md"}})]
        result = _scaffold_fixture(fixture_dir, checks, [])

        assert result is not None
        assert (result / "scaffold.md").exists()
        shutil.rmtree(result)


# ── _scaffold_glob_count: exist_ok on an existing parent (L134) ──────


class TestScaffoldGlobCountParent:
    """glob_count files land directly in tmp_dir, whose parent already
    exists — exist_ok must stay True."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_glob_count_top_level_scaffold_succeeds(self, tmp_path: Path) -> None:
        # Kills L134 `exist_ok=True -> False`: creating scaffold_N.md under
        # the existing tmp_dir parent raises FileExistsError when False.
        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [_c({"type": "mechanical", "check": "glob_count", "args": {"pattern": "**/*.md", "min": 2}})]
        result = _scaffold_fixture(fixture_dir, checks, [])

        assert result is not None
        assert len(list(result.glob("**/*.md"))) >= 2
        shutil.rmtree(result)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_glob_count_deep_nested_creates_parents(self, tmp_path: Path) -> None:
        # Kills L134 `parents=True -> False`: a two-level-deep pattern places
        # scaffold_N.md under a/b, whose grandparent `a` is missing, so
        # mkdir(parents=False) raises FileNotFoundError.
        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [_c({"type": "mechanical", "check": "glob_count", "args": {"pattern": "a/b/**/*.md", "min": 2}})]
        result = _scaffold_fixture(fixture_dir, checks, [])

        assert result is not None
        assert len(list((result / "a" / "b").glob("*.md"))) >= 2
        shutil.rmtree(result)


# ── _scaffold_file_removal: recursive glob (L180) ────────────────────


class TestScaffoldFileRemovalRecursive:
    """file_absent pass-scaffolding removes a nested forbidden file via a
    recursive glob when it is not a plain top-level path."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_deeply_nested_file_removed(self, tmp_path: Path) -> None:
        # Kills L180 `recursive=True -> False`: a two-level-deep README only
        # matches `**/README.md` when the glob is recursive.
        fixture_dir = tmp_path / "fixture"
        nested = fixture_dir / "a" / "b"
        nested.mkdir(parents=True)
        (nested / "README.md").write_text("# nested")

        checks = [_c({"type": "mechanical", "check": "file_absent", "args": {"pattern": "**/README.md"}})]
        result = _scaffold_fixture(fixture_dir, checks, [])

        assert result is not None
        assert not (result / "a" / "b" / "README.md").exists()
        shutil.rmtree(result)


# ── _scaffold_filename_mismatch fallback (L263, L264) ────────────────


class TestFilenameMismatchFallback:
    """When no existing file can be renamed, the fallback fabricates an
    invalid-named file. Exercises the suffix default and mkdir args."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_fallback_no_suffix_uses_md_default_under_new_parent(self, tmp_path: Path) -> None:
        # Empty fixture -> fallback. A no-suffix, two-level pattern
        # (`a/b/c/**`) concretes to a suffixless base under a/b, so the `.md`
        # default applies and the grandparent `a` does not yet exist.
        # Kills L263 `or -> and`: `and` would yield an empty suffix, so the
        # file would be `_scaffold_invalid`, not `_scaffold_invalid.md`.
        # Kills L264 `parents=True -> False`: the missing `a` grandparent means
        # mkdir(parents=False) on a/b raises FileNotFoundError.
        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [
            _c(
                {
                    "type": "mechanical",
                    "check": "filename_matches_pattern",
                    "args": {"pattern": r"(?i)^CLAUDE\.md$", "path": "a/b/c/**"},
                }
            )
        ]
        result = _scaffold_fail_fixture(fixture_dir, checks, [])

        assert result is not None
        assert (result / "a" / "b" / "_scaffold_invalid.md").exists()
        shutil.rmtree(result)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_fallback_top_level_parent_exists(self, tmp_path: Path) -> None:
        # Empty fixture -> fallback with a top-level pattern: the fabricated
        # file's parent is tmp_dir itself, which already exists.
        # Kills L264 `exist_ok=True -> False`: mkdir on the existing tmp_dir
        # parent raises FileExistsError when exist_ok is False.
        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [
            _c(
                {
                    "type": "mechanical",
                    "check": "filename_matches_pattern",
                    "args": {"pattern": r"(?i)^CLAUDE\.md$", "path": "**/*.md"},
                }
            )
        ]
        result = _scaffold_fail_fixture(fixture_dir, checks, [])

        assert result is not None
        assert (result / "_scaffold_invalid.md").exists()
        shutil.rmtree(result)


# ── _scaffold_file_present: parents for a nested forbidden file (L294) ─


class TestScaffoldFilePresentNestedParent:
    """The fail-side file_present action creates a forbidden file; a nested
    path requires its parent directory to be created."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_nested_forbidden_file_created(self, tmp_path: Path) -> None:
        # Kills L294 `parents=True -> False`: the `a/b/` chain's grandparent
        # `a` does not exist, so mkdir(parents=False) raises FileNotFoundError.
        fixture_dir = tmp_path / "fixture"
        fixture_dir.mkdir()

        checks = [_c({"type": "mechanical", "check": "file_absent", "args": {"pattern": "a/b/forbidden.md"}})]
        result = _scaffold_fail_fixture(fixture_dir, checks, [])

        assert result is not None
        assert (result / "a" / "b" / "forbidden.md").exists()
        shutil.rmtree(result)
