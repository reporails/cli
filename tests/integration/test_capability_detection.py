"""Project level determination tests - level detection must be deterministic and correct.

The project level (L1-L6) is computed from file type property divergence.
Detection must be consistent for the same set of classified files.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.levels import determine_project_level
from reporails_cli.core.models import ClassifiedFile, FileTypeDeclaration, Level


def _cf(
    name: str,
    path: str = "CLAUDE.md",
    **properties: str,
) -> ClassifiedFile:
    return ClassifiedFile(path=Path(path), file_type=name, properties=properties)


def _ft(
    name: str,
    patterns: tuple[str, ...] = ("**/CLAUDE.md",),
    **properties: str,
) -> FileTypeDeclaration:
    return FileTypeDeclaration(name=name, patterns=patterns, properties=properties)


class TestProjectLevelDetermination:
    """Test project level determination from file type properties."""

    def test_no_files_is_l0(self, tmp_path: Path) -> None:
        """No files → L0."""
        level, present = determine_project_level(tmp_path, [], [])
        assert level == Level.L0
        assert present == set()

    def test_main_only_is_l1(self, tmp_path: Path) -> None:
        """Main file with baseline properties → L1."""
        classified = [_cf("main")]
        level, _ = determine_project_level(tmp_path, [], classified)
        assert level == Level.L1

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
    def test_progressive_level(self, tmp_path: Path, depth: int, expected_level: Level) -> None:
        """depth N divergences → Level L(N+1)."""
        prop_overrides = [
            ("format", "frontmatter"),
            ("cardinality", "collection"),
            ("precedence", "managed"),
            ("loading", "on_demand"),
            ("scope", "path_scoped"),
        ]
        props: dict[str, str] = {}
        for i in range(depth):
            k, v = prop_overrides[i]
            props[k] = v
        classified = [_cf("test", **props)]
        level, _ = determine_project_level(tmp_path, [], classified)
        assert level == expected_level

    def test_max_depth_wins(self, tmp_path: Path) -> None:
        """Level is driven by the type with most divergences."""
        classified = [
            _cf("main"),  # depth 0
            _cf("scoped_rule", format="frontmatter"),  # depth 1
            _cf("skill", format="frontmatter", scope="task_scoped", loading="on_invocation"),  # depth 3
        ]
        level, _ = determine_project_level(tmp_path, [], classified)
        assert level == Level.L4  # max(0, 1, 3) + 1


class TestProjectLevelDeterminism:
    """Test that project level determination is deterministic."""

    def test_same_input_same_output(self, tmp_path: Path) -> None:
        """Same files always give same level."""
        classified = [
            _cf("main"),
            _cf("scoped_rule", format="frontmatter", scope="path_scoped"),
        ]
        results = [determine_project_level(tmp_path, [], classified) for _ in range(5)]
        levels = [r[0] for r in results]
        assert len(set(levels)) == 1
