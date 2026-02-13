"""Unit tests for the mechanical check runner."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.mechanical.checks import (
    _safe_float,
    byte_size,
    content_absent,
    directory_exists,
    file_exists,
    git_tracked,
    line_count,
)
from reporails_cli.core.mechanical.runner import run_mechanical_checks
from reporails_cli.core.models import Category, Check, Rule, RuleType, Severity


def _vars(instruction_files: list[str] | None = None) -> dict[str, str | list[str]]:
    return {"instruction_files": instruction_files or ["**/CLAUDE.md"]}


class TestFileExists:
    def test_file_found(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = file_exists(tmp_path, {}, _vars())
        assert result.passed

    def test_file_not_found(self, tmp_path: Path) -> None:
        result = file_exists(tmp_path, {}, _vars())
        assert not result.passed


class TestDirectoryExists:
    def test_exists(self, tmp_path: Path) -> None:
        (tmp_path / ".claude" / "rules").mkdir(parents=True)
        result = directory_exists(tmp_path, {"path": ".claude/rules"}, {})
        assert result.passed

    def test_missing(self, tmp_path: Path) -> None:
        result = directory_exists(tmp_path, {"path": ".claude/rules"}, {})
        assert not result.passed


class TestGitTracked:
    def test_git_dir_present(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        result = git_tracked(tmp_path, {}, {})
        assert result.passed

    def test_no_git(self, tmp_path: Path) -> None:
        result = git_tracked(tmp_path, {}, {})
        assert not result.passed


class TestLineCount:
    def test_within_bounds(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("line1\nline2\nline3\n")
        result = line_count(tmp_path, {"max": 10}, _vars())
        assert result.passed

    def test_exceeds_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("\n".join(f"line{i}" for i in range(50)))
        result = line_count(tmp_path, {"max": 10}, _vars())
        assert not result.passed


class TestByteSize:
    def test_within_bounds(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("small")
        result = byte_size(tmp_path, {"max": 1000}, _vars())
        assert result.passed

    def test_exceeds_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("x" * 1000)
        result = byte_size(tmp_path, {"max": 100}, _vars())
        assert not result.passed


class TestContentAbsent:
    def test_pattern_absent(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, _vars())
        assert result.passed

    def test_pattern_present(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# FORBIDDEN content here")
        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, _vars())
        assert not result.passed

    def test_invalid_regex_returns_failure(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = content_absent(tmp_path, {"pattern": "[invalid"}, _vars())
        assert not result.passed
        assert "invalid regex" in result.message


class TestRunMechanicalChecks:
    """Test the runner that dispatches rules to check functions."""

    def _rule(self, rule_id: str, check_name: str, args: dict | None = None) -> Rule:
        return Rule(
            id=rule_id,
            title=f"Rule {rule_id}",
            category=Category.STRUCTURE,
            type=RuleType.MECHANICAL,
            level="L1",
            targets="{{instruction_files}}",
            checks=[
                Check(
                    id=f"{rule_id}:check:0001",
                    severity=Severity.CRITICAL,
                    type="mechanical",
                    check=check_name,
                    args=args,
                ),
            ],
        )

    def test_passing_check_no_violations(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        rules = {"CORE:S:0001": self._rule("CORE:S:0001", "file_exists")}
        vars = _vars()
        violations = run_mechanical_checks(rules, tmp_path, vars)
        assert len(violations) == 0

    def test_failing_check_produces_violation(self, tmp_path: Path) -> None:
        rules = {"CORE:S:0001": self._rule("CORE:S:0001", "file_exists")}
        vars = _vars()
        violations = run_mechanical_checks(rules, tmp_path, vars)
        assert len(violations) == 1
        assert violations[0].rule_id == "CORE:S:0001"
        assert violations[0].severity == Severity.CRITICAL
        assert violations[0].check_id == "CORE:S:0001:check:0001"

    def test_unknown_check_skipped(self, tmp_path: Path) -> None:
        rules = {"CORE:S:0001": self._rule("CORE:S:0001", "nonexistent_check")}
        violations = run_mechanical_checks(rules, tmp_path, {})
        assert len(violations) == 0

    def test_multiple_rules(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        # file_exists passes, git_tracked fails (no .git)
        rules = {
            "CORE:S:0001": self._rule("CORE:S:0001", "file_exists"),
            "CORE:S:0004": self._rule("CORE:S:0004", "git_tracked"),
        }
        violations = run_mechanical_checks(rules, tmp_path, _vars())
        assert len(violations) == 1
        assert violations[0].rule_id == "CORE:S:0004"


class TestSafeFloat:
    """Tests for _safe_float type coercion helper."""

    def test_string_number(self) -> None:
        assert _safe_float("100") == 100.0

    def test_int_value(self) -> None:
        assert _safe_float(42) == 42.0

    def test_float_value(self) -> None:
        assert _safe_float(3.14) == 3.14

    def test_invalid_string_returns_default(self) -> None:
        assert _safe_float("invalid") == float("inf")

    def test_invalid_string_custom_default(self) -> None:
        assert _safe_float("abc", 0.0) == 0.0

    def test_none_returns_default(self) -> None:
        assert _safe_float(None) == float("inf")

    def test_none_custom_default(self) -> None:
        assert _safe_float(None, 0.0) == 0.0


class TestTypeSafetyInChecks:
    """Verify mechanical checks handle string args from YAML without crashing."""

    def test_byte_size_string_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("short")
        result = byte_size(tmp_path, {"max": "100"}, _vars())
        assert result.passed

    def test_byte_size_invalid_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("short")
        result = byte_size(tmp_path, {"max": "invalid"}, _vars())
        # invalid → float("inf"), so any file passes
        assert result.passed

    def test_line_count_string_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("line1\nline2\n")
        result = line_count(tmp_path, {"max": "100"}, _vars())
        assert result.passed

    def test_line_count_invalid_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("line1\nline2\n")
        result = line_count(tmp_path, {"max": "invalid"}, _vars())
        assert result.passed
