"""Unit tests for auto-fixers.

Tests cover:
- Each fixer adds its section when missing
- Each fixer is idempotent (no-op when section already present)
- apply_auto_fixes filters to fixable violations only
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.fixers import (
    apply_auto_fixes,
    apply_single_fix,
    describe_fix,
    fix_add_commands,
    fix_add_constraints,
    fix_add_sections,
    fix_add_structure,
    fix_add_testing,
    partition_violations,
)
from reporails_cli.core.models import Severity, Violation


def _make_violation(
    rule_id: str,
    file_path: str,
    message: str = "Missing section",
) -> Violation:
    return Violation(
        rule_id=rule_id,
        rule_title="Test Rule",
        location=f"{file_path}:1",
        message=message,
        severity=Severity.HIGH,
    )


# ---------------------------------------------------------------------------
# fix_add_constraints (CORE:C:0010)
# ---------------------------------------------------------------------------


class TestFixAddConstraints:
    def test_adds_section_when_missing(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nSome content.\n")
        v = _make_violation("CORE:C:0010", str(md))

        result = fix_add_constraints(v, tmp_path)

        assert result is not None
        assert "Constraints" in result.description
        content = md.read_text()
        assert "## Constraints" in content
        assert "TODO: Add project constraints" in content

    def test_idempotent_with_constraints_heading(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\n## Constraints\n\n- No secrets.\n")
        v = _make_violation("CORE:C:0010", str(md))

        result = fix_add_constraints(v, tmp_path)
        assert result is None

    def test_idempotent_with_pitfalls_heading(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\n## Pitfalls\n\n- Watch out.\n")
        v = _make_violation("CORE:C:0010", str(md))

        result = fix_add_constraints(v, tmp_path)
        assert result is None

    def test_returns_none_for_missing_file(self, tmp_path: Path) -> None:
        v = _make_violation("CORE:C:0010", str(tmp_path / "nonexistent.md"))
        result = fix_add_constraints(v, tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# fix_add_commands (CORE:C:0003)
# ---------------------------------------------------------------------------


class TestFixAddCommands:
    def test_adds_section_when_missing(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nSome content.\n")
        v = _make_violation("CORE:C:0003", str(md))

        result = fix_add_commands(v, tmp_path)

        assert result is not None
        assert "Commands" in result.description
        content = md.read_text()
        assert "## Commands" in content
        assert "```bash" in content

    def test_idempotent_with_inline_command(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nRun `npm install` to get started.\n")
        v = _make_violation("CORE:C:0003", str(md))

        result = fix_add_commands(v, tmp_path)
        assert result is None

    def test_idempotent_with_shell_prompt(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\n$ npm install\n")
        v = _make_violation("CORE:C:0003", str(md))

        result = fix_add_commands(v, tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# fix_add_testing (CORE:C:0004)
# ---------------------------------------------------------------------------


class TestFixAddTesting:
    def test_adds_section_when_missing(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nSome content.\n")
        v = _make_violation("CORE:C:0004", str(md))

        result = fix_add_testing(v, tmp_path)

        assert result is not None
        assert "Testing" in result.description
        content = md.read_text()
        assert "## Testing" in content
        assert "TODO: Add test commands" in content

    def test_idempotent_with_test_heading(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\n## Testing\n\n- Run pytest.\n")
        v = _make_violation("CORE:C:0004", str(md))

        result = fix_add_testing(v, tmp_path)
        assert result is None

    def test_idempotent_with_framework_mention(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nWe use pytest for all tests.\n")
        v = _make_violation("CORE:C:0004", str(md))

        result = fix_add_testing(v, tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# fix_add_sections (CORE:C:0015)
# ---------------------------------------------------------------------------


class TestFixAddSections:
    def test_adds_headings_when_none_exist(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nJust one big block of text with no sections.\n")
        v = _make_violation("CORE:C:0015", str(md))

        result = fix_add_sections(v, tmp_path)

        assert result is not None
        assert "Overview" in result.description
        content = md.read_text()
        assert "## Overview" in content
        assert "## Getting Started" in content

    def test_idempotent_with_existing_headings(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\n## Setup\n\nSome setup info.\n")
        v = _make_violation("CORE:C:0015", str(md))

        result = fix_add_sections(v, tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# fix_add_structure (CORE:C:0002)
# ---------------------------------------------------------------------------


class TestFixAddStructure:
    def test_adds_section_when_missing(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nSome content.\n")
        v = _make_violation("CORE:C:0002", str(md))

        result = fix_add_structure(v, tmp_path)

        assert result is not None
        assert "Project Structure" in result.description
        content = md.read_text()
        assert "## Project Structure" in content
        assert "```" in content

    def test_idempotent_with_structure_heading(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\n## Project Structure\n\n```\nsrc/\n```\n")
        v = _make_violation("CORE:C:0002", str(md))

        result = fix_add_structure(v, tmp_path)
        assert result is None

    def test_idempotent_with_path_references(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nCode is in src/ and tests are in tests/.\n")
        v = _make_violation("CORE:C:0002", str(md))

        result = fix_add_structure(v, tmp_path)
        assert result is None

    def test_idempotent_with_directory_heading(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\n## Directory Layout\n\nStuff here.\n")
        v = _make_violation("CORE:C:0002", str(md))

        result = fix_add_structure(v, tmp_path)
        assert result is None


# ---------------------------------------------------------------------------
# apply_auto_fixes
# ---------------------------------------------------------------------------


class TestApplyAutoFixes:
    def test_applies_fixable_violations(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nMinimal content.\n")

        violations = [
            _make_violation("CORE:C:0010", str(md)),
            _make_violation("CORE:C:0004", str(md)),
        ]

        results = apply_auto_fixes(violations, tmp_path)

        assert len(results) == 2
        content = md.read_text()
        assert "## Constraints" in content
        assert "## Testing" in content

    def test_skips_unfixable_violations(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n")

        violations = [
            _make_violation("CORE:S:0001", str(md)),  # No fixer registered
            _make_violation("CORE:C:0010", str(md)),
        ]

        results = apply_auto_fixes(violations, tmp_path)

        assert len(results) == 1
        assert results[0].rule_id == "CORE:C:0010"

    def test_empty_violations(self, tmp_path: Path) -> None:
        results = apply_auto_fixes([], tmp_path)
        assert results == []

    def test_relative_path_in_location(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n")
        v = _make_violation("CORE:C:0010", "CLAUDE.md")

        results = apply_auto_fixes([v], tmp_path)

        assert len(results) == 1
        assert results[0].file_path == "CLAUDE.md"


# ---------------------------------------------------------------------------
# partition_violations
# ---------------------------------------------------------------------------


class TestPartitionViolations:
    def test_splits_fixable_and_non_fixable(self, tmp_path: Path) -> None:
        fixable_v = _make_violation("CORE:C:0003", str(tmp_path / "CLAUDE.md"))
        non_fixable_v = _make_violation("CORE:S:0003", str(tmp_path / "CLAUDE.md"))

        fixable, non_fixable = partition_violations([fixable_v, non_fixable_v])

        assert len(fixable) == 1
        assert fixable[0].rule_id == "CORE:C:0003"
        assert len(non_fixable) == 1
        assert non_fixable[0].rule_id == "CORE:S:0003"

    def test_empty_list(self) -> None:
        fixable, non_fixable = partition_violations([])
        assert fixable == []
        assert non_fixable == []

    def test_all_fixable(self, tmp_path: Path) -> None:
        violations = [
            _make_violation("CORE:C:0003", str(tmp_path / "CLAUDE.md")),
            _make_violation("CORE:C:0010", str(tmp_path / "CLAUDE.md")),
        ]
        fixable, non_fixable = partition_violations(violations)
        assert len(fixable) == 2
        assert len(non_fixable) == 0

    def test_all_non_fixable(self, tmp_path: Path) -> None:
        violations = [
            _make_violation("CORE:S:0003", str(tmp_path / "CLAUDE.md")),
            _make_violation("CORE:S:0005", str(tmp_path / "CLAUDE.md")),
        ]
        fixable, non_fixable = partition_violations(violations)
        assert len(fixable) == 0
        assert len(non_fixable) == 2


# ---------------------------------------------------------------------------
# describe_fix
# ---------------------------------------------------------------------------


class TestDescribeFix:
    def test_returns_description_for_fixable(self) -> None:
        v = _make_violation("CORE:C:0003", "CLAUDE.md")
        desc = describe_fix(v)
        assert desc is not None
        assert "Commands" in desc

    def test_returns_none_for_non_fixable(self) -> None:
        v = _make_violation("CORE:S:0003", "CLAUDE.md")
        desc = describe_fix(v)
        assert desc is None


# ---------------------------------------------------------------------------
# apply_single_fix
# ---------------------------------------------------------------------------


class TestApplySingleFix:
    def test_applies_fix(self, tmp_path: Path) -> None:
        md = tmp_path / "CLAUDE.md"
        md.write_text("# My Project\n\nSome content.\n")
        v = _make_violation("CORE:C:0010", str(md))

        result = apply_single_fix(v, tmp_path)

        assert result is not None
        assert "Constraints" in result.description

    def test_returns_none_for_unknown_rule(self, tmp_path: Path) -> None:
        v = _make_violation("CORE:S:0003", str(tmp_path / "CLAUDE.md"))
        result = apply_single_fix(v, tmp_path)
        assert result is None
