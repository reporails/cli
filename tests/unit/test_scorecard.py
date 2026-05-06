"""Unit tests for formatters/text/scorecard.py — surface health computation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reporails_cli.formatters.text.scorecard import compute_surface_scores


@dataclass
class _FileRecord:
    path: str


@dataclass
class _RulesetMap:
    files: tuple[_FileRecord, ...]


@dataclass
class _Result:
    findings: tuple = ()
    per_file_analysis: tuple = ()


class TestComputeSurfaceScores:
    """Surface classification under absolute vs relative paths."""

    def test_root_main_file_with_absolute_path_classifies_as_main(self, tmp_path: Path) -> None:
        """A single root-level CLAUDE.md with an absolute mapper path tags `main`, not `nested`.

        `ruleset_map.files[*].path` carries an absolute path. Classifying it
        directly via `classify_file` would count its leading filesystem
        components and tag the file `nested`. The fix relativizes against
        `project_root` first, mirroring how findings are already keyed.
        """
        absolute_main = (tmp_path / "CLAUDE.md").as_posix()
        ruleset = _RulesetMap(files=(_FileRecord(path=absolute_main),))

        surfaces = compute_surface_scores(_Result(), ruleset_map=ruleset, project_root=tmp_path)

        names = {s.name: s.file_count for s in surfaces}
        assert names.get("Main") == 1
        assert "Nested" not in names, "root CLAUDE.md must not appear as a Nested surface"

    def test_subdirectory_main_file_classifies_as_nested(self, tmp_path: Path) -> None:
        """A `packages/web/CLAUDE.md` does belong in the Nested surface."""
        nested_path = (tmp_path / "packages" / "web" / "CLAUDE.md").as_posix()
        ruleset = _RulesetMap(files=(_FileRecord(path=nested_path),))

        surfaces = compute_surface_scores(_Result(), ruleset_map=ruleset, project_root=tmp_path)

        names = {s.name: s.file_count for s in surfaces}
        assert names.get("Nested") == 1
        assert "Main" not in names
