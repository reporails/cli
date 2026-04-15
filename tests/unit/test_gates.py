"""Unit tests for project level determination and target existence gating.

Tests determine_project_level() — computes project level from file type
property divergence, and returns the set of present file types.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.levels import _property_depth, _type_exists, determine_project_level
from reporails_cli.core.models import ClassifiedFile, FileTypeDeclaration, Level


def _ft(
    name: str,
    patterns: tuple[str, ...] = ("**/CLAUDE.md",),
    **properties: str,
) -> FileTypeDeclaration:
    """Create a FileTypeDeclaration for testing."""
    return FileTypeDeclaration(name=name, patterns=patterns, properties=properties)


def _cf(
    name: str,
    path: str = "CLAUDE.md",
    **properties: str,
) -> ClassifiedFile:
    """Create a ClassifiedFile for testing."""
    return ClassifiedFile(path=Path(path), file_type=name, properties=properties)


# Baseline: format=freeform, cardinality=singleton, precedence=project,
#           loading=session_start, scope=global


class TestPropertyDepth:
    """Test _property_depth — count divergences from baseline."""

    def test_all_baseline_returns_zero(self) -> None:
        props = {
            "format": "freeform",
            "cardinality": "singleton",
            "precedence": "project",
            "loading": "session_start",
            "scope": "global",
        }
        assert _property_depth(props) == 0

    def test_empty_properties_returns_zero(self) -> None:
        assert _property_depth({}) == 0

    def test_one_divergence(self) -> None:
        assert _property_depth({"format": "frontmatter"}) == 1

    def test_two_divergences(self) -> None:
        props = {"format": "frontmatter", "scope": "path_scoped"}
        assert _property_depth(props) == 2

    def test_all_divergent(self) -> None:
        props = {
            "format": "frontmatter",
            "cardinality": "collection",
            "precedence": "managed",
            "loading": "on_demand",
            "scope": "path_scoped",
        }
        assert _property_depth(props) == 5

    def test_extra_properties_ignored(self) -> None:
        """Properties not in baseline don't count."""
        props = {"custom_axis": "whatever", "unknown": "value"}
        assert _property_depth(props) == 0


class TestTypeExists:
    """Test _type_exists — filesystem pattern matching."""

    def test_exact_file_exists(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Test\n")
        assert _type_exists(tmp_path, ("CLAUDE.md",)) is True

    def test_exact_file_missing(self, tmp_path: Path) -> None:
        assert _type_exists(tmp_path, ("CLAUDE.md",)) is False

    def test_glob_pattern_matches(self, tmp_path: Path) -> None:
        rules_dir = tmp_path / ".claude" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "style.md").write_text("# Style\n")
        assert _type_exists(tmp_path, (".claude/rules/**/*.md",)) is True

    def test_glob_pattern_no_match(self, tmp_path: Path) -> None:
        (tmp_path / ".claude").mkdir()
        assert _type_exists(tmp_path, (".claude/rules/**/*.md",)) is False

    def test_strips_dotslash_prefix(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Test\n")
        assert _type_exists(tmp_path, ("./CLAUDE.md",)) is True

    def test_multiple_patterns_any_match(self, tmp_path: Path) -> None:
        (tmp_path / "AGENTS.md").write_text("# Agents\n")
        assert _type_exists(tmp_path, ("CLAUDE.md", "AGENTS.md")) is True


class TestDetermineProjectLevel:
    """Test determine_project_level — level from property divergence."""

    def test_no_files_returns_l0(self, tmp_path: Path) -> None:
        level, present = determine_project_level(tmp_path, [], [])
        assert level == Level.L0
        assert present == set()

    def test_main_only_returns_l1(self, tmp_path: Path) -> None:
        """Main file with all-baseline properties → depth 0 → L1."""
        classified = [
            _cf(
                "main",
                format="freeform",
                cardinality="singleton",
                precedence="project",
                loading="session_start",
                scope="global",
            )
        ]
        level, present = determine_project_level(tmp_path, [], classified)
        assert level == Level.L1
        assert present == {"main"}

    def test_one_divergence_returns_l2(self, tmp_path: Path) -> None:
        """One property diverges → depth 1 → L2."""
        classified = [_cf("scoped_rule", format="frontmatter")]
        level, present = determine_project_level(tmp_path, [], classified)
        assert level == Level.L2
        assert present == {"scoped_rule"}

    def test_max_depth_across_types(self, tmp_path: Path) -> None:
        """Level is max depth across all present types + 1."""
        classified = [
            _cf("main"),  # depth 0
            _cf("scoped_rule", format="frontmatter", scope="path_scoped", loading="on_demand"),  # depth 3
        ]
        level, _ = determine_project_level(tmp_path, [], classified)
        assert level == Level.L4  # max(0, 3) + 1 = 4

    def test_capped_at_l6(self, tmp_path: Path) -> None:
        """Level caps at L6 even with 5+ divergences."""
        classified = [
            _cf(
                "extreme",
                format="schema_validated",
                cardinality="collection",
                precedence="managed",
                loading="on_demand",
                scope="path_scoped",
            )
        ]
        level, _ = determine_project_level(tmp_path, [], classified)
        assert level == Level.L6  # min(5+1, 6) = 6

    def test_filesystem_fallback(self, tmp_path: Path) -> None:
        """Types not in classified_files but present on disk are included."""
        (tmp_path / "CLAUDE.md").write_text("# Test\n")
        file_types = [
            _ft(
                "main",
                patterns=("CLAUDE.md",),
                format="freeform",
                cardinality="singleton",
                precedence="project",
                loading="session_start",
                scope="global",
            )
        ]
        level, present = determine_project_level(tmp_path, file_types, [])
        assert level == Level.L1
        assert "main" in present

    def test_filesystem_not_double_counted(self, tmp_path: Path) -> None:
        """A type already in classified_files is not re-checked on disk."""
        (tmp_path / "CLAUDE.md").write_text("# Test\n")
        classified = [_cf("main")]
        file_types = [_ft("main", patterns=("CLAUDE.md",), format="frontmatter")]
        # classified has depth=0 for "main"; file_types would give depth=1 but
        # should be skipped since "main" is already present
        level, _ = determine_project_level(tmp_path, file_types, classified)
        assert level == Level.L1  # depth 0 from classified, not 1 from file_types

    @pytest.mark.parametrize(
        "depth, expected_level",
        [
            (0, Level.L1),
            (1, Level.L2),
            (2, Level.L3),
            (3, Level.L4),
            (4, Level.L5),
            (5, Level.L6),
        ],
    )
    def test_depth_to_level_mapping(self, tmp_path: Path, depth: int, expected_level: Level) -> None:
        """depth N → Level L(N+1), capped at L6."""
        # Build properties with exactly `depth` divergences
        divergent_props: dict[str, str] = {}
        prop_overrides = [
            ("format", "frontmatter"),
            ("cardinality", "collection"),
            ("precedence", "managed"),
            ("loading", "on_demand"),
            ("scope", "path_scoped"),
        ]
        for i in range(depth):
            k, v = prop_overrides[i]
            divergent_props[k] = v
        classified = [_cf("test_type", **divergent_props)]
        level, _ = determine_project_level(tmp_path, [], classified)
        assert level == expected_level
