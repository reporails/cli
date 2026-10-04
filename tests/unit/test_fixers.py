"""Tests for core/heal/fixers.py — SECTION_SUGGESTERS keyed on the rule each suggester serves.

A SEAM per mapping: feed `suggest_single_section` a `Violation` carrying the real rule id
the suggester is meant to serve, on a fixture the rule's own finding would fire on, and
assert the suggester fires (returns a `Suggestion` naming the missing section) — and that
it never writes to the file. The prior keys were stale — e.g. `CORE:C:0010` (Build And
Test Commands) pointed at the constraints fixer instead of the commands fixer — so this
also asserts the *old* keys no longer resolve to a suggester.

A second group covers which FILE a suggestion names. The underlying finding a suggester
receives is pinned wherever the project-wide content check happened to land (the first
matching file in sorted path order), which is not necessarily the project's main file.
A suggestion must name the file the rule's own `match.type` is about — its declared type
if the rule restricts one, otherwise the project's main instruction file — never the
finding's own (possibly unrelated) location.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.heal.fixers import SECTION_SUGGESTERS, suggest_single_section
from reporails_cli.core.platform.dto.models import (
    Category,
    ClassifiedFile,
    FileMatch,
    Rule,
    RuleType,
    Severity,
    Violation,
)


def _violation(rule_id: str, location: str) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title="test",
        location=location,
        message="test",
        severity=Severity.MEDIUM,
    )


def _main_type_rule(rule_id: str) -> Rule:
    return Rule(
        id=rule_id,
        title="test",
        category=Category.COHERENCE,
        type=RuleType.DETERMINISTIC,
        match=FileMatch(type="main"),
    )


def _project_wide_rule(rule_id: str) -> Rule:
    """A rule with no `type` restriction (`match: {format: freeform}` in the shipped
    definition) — matches any freeform file project-wide, not just the main file."""
    return Rule(
        id=rule_id,
        title="test",
        category=Category.COHERENCE,
        type=RuleType.DETERMINISTIC,
        match=FileMatch(format="freeform"),
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_build_and_test_commands_suggester_names_commands_section(tmp_path: Path) -> None:
    fpath = tmp_path / "CLAUDE.md"
    original = "# Project\n\nSome prose.\n"
    fpath.write_text(original, encoding="utf-8")
    classified = [ClassifiedFile(path=fpath, file_type="main")]
    rules = {"CORE:C:0010": _main_type_rule("CORE:C:0010")}

    result = suggest_single_section(_violation("CORE:C:0010", "CLAUDE.md"), tmp_path, classified, rules)

    assert result is not None
    assert result.section == "## Commands"
    assert result.file_path == "CLAUDE.md"
    assert "TODO" not in result.description
    assert fpath.read_text(encoding="utf-8") == original


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_explicit_prohibitions_suggester_names_constraints_section(tmp_path: Path) -> None:
    fpath = tmp_path / "CLAUDE.md"
    original = "# Project\n\nSome prose.\n"
    fpath.write_text(original, encoding="utf-8")
    classified = [ClassifiedFile(path=fpath, file_type="main")]
    rules = {"CORE:C:0019": _project_wide_rule("CORE:C:0019")}

    result = suggest_single_section(_violation("CORE:C:0019", "CLAUDE.md"), tmp_path, classified, rules)

    assert result is not None
    assert result.section == "## Constraints"
    assert result.file_path == "CLAUDE.md"
    assert "TODO" not in result.description
    assert fpath.read_text(encoding="utf-8") == original


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_testing_framework_documented_suggester_names_testing_section(tmp_path: Path) -> None:
    fpath = tmp_path / "CLAUDE.md"
    original = "# Project\n\nSome prose.\n"
    fpath.write_text(original, encoding="utf-8")
    classified = [ClassifiedFile(path=fpath, file_type="main")]
    rules = {"CORE:C:0005": _main_type_rule("CORE:C:0005")}

    result = suggest_single_section(_violation("CORE:C:0005", "CLAUDE.md"), tmp_path, classified, rules)

    assert result is not None
    assert result.section == "## Testing"
    assert result.file_path == "CLAUDE.md"
    assert "TODO" not in result.description
    assert fpath.read_text(encoding="utf-8") == original


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_layered_content_structure_suggester_names_headings(tmp_path: Path) -> None:
    fpath = tmp_path / "CLAUDE.md"
    original = "# Project\n\nSome prose with no level-2 headings.\n"
    fpath.write_text(original, encoding="utf-8")
    classified = [ClassifiedFile(path=fpath, file_type="main")]
    rules = {"CORE:S:0016": _project_wide_rule("CORE:S:0016")}

    result = suggest_single_section(_violation("CORE:S:0016", "CLAUDE.md"), tmp_path, classified, rules)

    assert result is not None
    assert "heading" in result.section.lower()
    assert result.file_path == "CLAUDE.md"
    assert "TODO" not in result.description
    assert fpath.read_text(encoding="utf-8") == original


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_directory_layout_documented_suggester_names_structure_section(tmp_path: Path) -> None:
    fpath = tmp_path / "CLAUDE.md"
    original = "# Project\n\nSome prose.\n"
    fpath.write_text(original, encoding="utf-8")
    classified = [ClassifiedFile(path=fpath, file_type="main")]
    rules = {"CORE:C:0035": _main_type_rule("CORE:C:0035")}

    result = suggest_single_section(_violation("CORE:C:0035", "CLAUDE.md"), tmp_path, classified, rules)

    assert result is not None
    assert result.section == "## Project Structure"
    assert result.file_path == "CLAUDE.md"
    assert "TODO" not in result.description
    assert fpath.read_text(encoding="utf-8") == original


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_stale_ids_no_longer_key_a_suggester() -> None:
    # The retired mismatched keys — CORE:C:0002/0003/0004/0015 never matched the
    # suggester they were paired with; they must not resolve to any suggester now either.
    for stale_id in ("CORE:C:0002", "CORE:C:0003", "CORE:C:0004", "CORE:C:0015"):
        assert stale_id not in SECTION_SUGGESTERS


# ---------------------------------------------------------------------------
# A project-wide content check pins its finding to the first matching file in
# sorted path order (`.claude/rules/style.md` sorts before `CLAUDE.md`), but a
# suggestion must still name the file the rule's own type is about, not the
# finding's incidental location.
# ---------------------------------------------------------------------------


def _two_file_project(tmp_path: Path) -> tuple[Path, Path, list[ClassifiedFile]]:
    main = tmp_path / "CLAUDE.md"
    main.write_text("# Project\n\nSome prose with no constraints or sub-headings.\n", encoding="utf-8")
    rules_dir = tmp_path / ".claude" / "rules"
    rules_dir.mkdir(parents=True)
    style = rules_dir / "style.md"
    style.write_text("# Style\n\nUse two-space indent.\n", encoding="utf-8")
    classified = [
        ClassifiedFile(path=style, file_type="rules"),
        ClassifiedFile(path=main, file_type="main"),
    ]
    return main, style, classified


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_constraints_suggestion_names_main_file_not_the_sorted_first_match(tmp_path: Path) -> None:
    main, style, classified = _two_file_project(tmp_path)
    rules = {"CORE:C:0019": _project_wide_rule("CORE:C:0019")}
    # The finding is pinned to `.claude/rules/style.md` — sorted before CLAUDE.md —
    # exactly what the underlying project-wide check would emit.
    violation = _violation("CORE:C:0019", ".claude/rules/style.md")

    result = suggest_single_section(violation, tmp_path, classified, rules)

    assert result is not None
    assert result.file_path == "CLAUDE.md"
    assert result.file_path != "style.md"
    assert result.file_path != str(style.relative_to(tmp_path))
    assert main.read_text(encoding="utf-8") == "# Project\n\nSome prose with no constraints or sub-headings.\n"
    assert style.read_text(encoding="utf-8") == "# Style\n\nUse two-space indent.\n"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_layered_structure_suggestion_names_main_file_not_the_sorted_first_match(tmp_path: Path) -> None:
    _main, style, classified = _two_file_project(tmp_path)
    rules = {"CORE:S:0016": _project_wide_rule("CORE:S:0016")}
    violation = _violation("CORE:S:0016", ".claude/rules/style.md")

    result = suggest_single_section(violation, tmp_path, classified, rules)

    assert result is not None
    assert result.file_path == "CLAUDE.md"
    assert result.file_path != "style.md"
    assert result.file_path != str(style.relative_to(tmp_path))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_suggestion_says_so_when_project_has_no_main_file(tmp_path: Path) -> None:
    style_dir = tmp_path / ".claude" / "rules"
    style_dir.mkdir(parents=True)
    style = style_dir / "style.md"
    style.write_text("# Style\n\nUse two-space indent.\n", encoding="utf-8")
    classified = [ClassifiedFile(path=style, file_type="rules")]
    rules = {"CORE:C:0019": _project_wide_rule("CORE:C:0019")}
    violation = _violation("CORE:C:0019", ".claude/rules/style.md")

    result = suggest_single_section(violation, tmp_path, classified, rules)

    assert result is not None
    # Says the target is absent instead of naming the unrelated rules file.
    assert "style.md" not in result.file_path
    assert "no" in result.file_path.lower()
