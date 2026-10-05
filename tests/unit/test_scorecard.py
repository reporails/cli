"""Unit tests for formatters/text/scorecard.py — surface health computation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from reporails_cli.formatters.text.scorecard import compute_surface_scores


@dataclass
class _FileRecord:
    path: str
    skill: str = ""


@dataclass
class _RulesetMap:
    files: tuple[_FileRecord, ...]


@dataclass
class _Result:
    findings: tuple = ()
    per_file_analysis: tuple = ()


class TestComputeSurfaceScores:
    """Surface classification under absolute vs relative paths."""

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
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

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_subdirectory_main_file_classifies_as_nested(self, tmp_path: Path) -> None:
        """A `packages/web/CLAUDE.md` does belong in the Nested surface."""
        nested_path = (tmp_path / "packages" / "web" / "CLAUDE.md").as_posix()
        ruleset = _RulesetMap(files=(_FileRecord(path=nested_path),))

        surfaces = compute_surface_scores(_Result(), ruleset_map=ruleset, project_root=tmp_path)

        names = {s.name: s.file_count for s in surfaces}
        assert names.get("Nested") == 1
        assert "Main" not in names

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_copilot_main_file_classifies_as_main_not_nested(self, tmp_path: Path) -> None:
        """Copilot's main file always lives one directory deep
        (`.github/copilot-instructions.md`) — a path-depth heuristic tuned for
        Claude's bare-root `CLAUDE.md` mis-reads that fixed location as `Nested`."""
        (tmp_path / ".github").mkdir()
        main_path = (tmp_path / ".github" / "copilot-instructions.md").as_posix()
        ruleset = _RulesetMap(files=(_FileRecord(path=main_path),))

        surfaces = compute_surface_scores(_Result(), ruleset_map=ruleset, project_root=tmp_path)

        names = {s.name: s.file_count for s in surfaces}
        assert names.get("Main") == 1
        assert "Nested" not in names

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_cursor_mdc_rule_file_gets_rules_surface(self, tmp_path: Path) -> None:
        """A Cursor `.mdc` rule file must group into the Rules surface, not fall
        back to the generic (un-bucketed) file tag."""
        rule_path = (tmp_path / ".cursor" / "rules" / "testing.mdc").as_posix()
        ruleset = _RulesetMap(files=(_FileRecord(path=rule_path),))

        surfaces = compute_surface_scores(_Result(), ruleset_map=ruleset, project_root=tmp_path)

        names = {s.name: s.file_count for s in surfaces}
        assert names.get("Rules") == 1

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_copilot_applyto_rule_file_gets_rules_surface(self, tmp_path: Path) -> None:
        """A Copilot `applyTo` instructions file lives under `.github/instructions/`,
        not Claude's `.../rules/` directory name — it must still group into Rules."""
        rule_path = (tmp_path / ".github" / "instructions" / "python.instructions.md").as_posix()
        ruleset = _RulesetMap(files=(_FileRecord(path=rule_path),))

        surfaces = compute_surface_scores(_Result(), ruleset_map=ruleset, project_root=tmp_path)

        names = {s.name: s.file_count for s in surfaces}
        assert names.get("Rules") == 1

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_gemini_root_file_gets_main_surface(self, tmp_path: Path) -> None:
        """An Antigravity project's root `GEMINI.md` is its Main surface, as `AGENTS.md` is."""
        ruleset = _RulesetMap(files=(_FileRecord(path=(tmp_path / "GEMINI.md").as_posix()),))

        surfaces = compute_surface_scores(_Result(), ruleset_map=ruleset, project_root=tmp_path)

        names = {s.name: s.file_count for s in surfaces}
        assert names.get("Main") == 1
        assert "Nested" not in names

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_gemini_nested_file_gets_nested_surface(self, tmp_path: Path) -> None:
        """A `GEMINI.md` in a subdirectory is a Nested copy, as a nested `AGENTS.md` is."""
        ruleset = _RulesetMap(files=(_FileRecord(path=(tmp_path / "pkg" / "GEMINI.md").as_posix()),))

        surfaces = compute_surface_scores(_Result(), ruleset_map=ruleset, project_root=tmp_path)

        names = {s.name: s.file_count for s in surfaces}
        assert names.get("Nested") == 1
        assert "Main" not in names


@dataclass
class _Quality:
    display_score: float


@dataclass
class _Stats:
    errors: int = 0
    warnings: int = 0
    infos: int = 0


@dataclass
class _Finding:
    severity: str
    rule: str = "CORE:R:0001"
    message: str = "example finding"
    convention: bool = False


@dataclass
class _VerdictResult:
    quality: _Quality | None
    stats: _Stats
    findings: tuple = ()


class TestVerdictCaption:
    """The 'worth fixing' caption must point at an error list that actually rendered."""

    def _capture(self, result: object) -> str:
        from reporails_cli.formatters.text.scorecard import _render_verdict_block, console

        with console.capture() as cap:
            _render_verdict_block(result, has_quality=True, n_atoms=0, elapsed_ms=0)
        # Collapse Rich soft-wrap newlines so the caption is matchable as one string.
        return " ".join(cap.get().split())

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_caption_shown_when_error_findings_listed(self) -> None:
        """A visible error finding -> the reconciling caption renders, whatever the score."""
        result = _VerdictResult(
            quality=_Quality(display_score=8.5),
            stats=_Stats(errors=2),
            findings=(_Finding(severity="error"),),
        )
        assert "An error is worth fixing" in self._capture(result)

    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_caption_suppressed_when_no_error_findings_listed(self) -> None:
        """Anon/free: stats count errors but they are gated out of the list -> no caption."""
        result = _VerdictResult(
            quality=_Quality(display_score=8.5),
            stats=_Stats(errors=2),  # stats count gated errors
            findings=(),  # but nothing rendered in the worklist below
        )
        out = self._capture(result)
        assert "worth fixing" not in out


class TestConventionsInFindingsLine:
    @pytest.mark.unit
    @pytest.mark.subsys_diagnostic
    def test_conventions_are_counted_apart_from_the_total(self) -> None:
        from reporails_cli.formatters.text.scorecard import _render_verdict_block, console

        result = _VerdictResult(
            quality=_Quality(display_score=8.5),
            stats=_Stats(warnings=3),
            findings=(
                _Finding(severity="warning"),
                _Finding(severity="warning", convention=True),
                _Finding(severity="warning", convention=True),
            ),
        )
        with console.capture() as cap:
            _render_verdict_block(result, has_quality=True, n_atoms=0, elapsed_ms=0)
        out = " ".join(cap.get().split())
        assert "Findings 1 total · 2 documentation conventions not present · -v to list them" in out
