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
from reporails_cli.core.mechanical.runner import (
    _matches_any_pattern,
    bind_instruction_files,
    resolve_location,
    run_mechanical_checks,
)
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
        assert result.location == "CLAUDE.md:0"


class TestByteSize:
    def test_within_bounds(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("small")
        result = byte_size(tmp_path, {"max": 1000}, _vars())
        assert result.passed

    def test_exceeds_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("x" * 1000)
        result = byte_size(tmp_path, {"max": 100}, _vars())
        assert not result.passed
        assert result.location == "CLAUDE.md:0"


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


class TestContentAbsentMultiFile:
    """content_absent scanning across multiple instruction files."""

    def test_pattern_found_in_one_of_two_files(self, tmp_path: Path) -> None:
        """Fails when forbidden pattern appears in any file."""
        (tmp_path / "CLAUDE.md").write_text("# Clean content")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "bad.md").write_text("# Has FORBIDDEN pattern")
        vars = {"instruction_files": ["CLAUDE.md", ".claude/rules/bad.md"]}

        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, vars)

        assert not result.passed
        assert "bad.md" in result.message

    def test_pattern_absent_in_all_files(self, tmp_path: Path) -> None:
        """Passes when forbidden pattern absent from all files."""
        (tmp_path / "CLAUDE.md").write_text("# Clean")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "also_clean.md").write_text("# Also clean")
        vars = {"instruction_files": ["CLAUDE.md", ".claude/rules/also_clean.md"]}

        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, vars)

        assert result.passed

    def test_pattern_found_in_all_files(self, tmp_path: Path) -> None:
        """Fails on first match (short-circuit) when all files contain pattern."""
        (tmp_path / "CLAUDE.md").write_text("# Has FORBIDDEN")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "also_bad.md").write_text("# Also FORBIDDEN")
        vars = {"instruction_files": ["CLAUDE.md", ".claude/rules/also_bad.md"]}

        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, vars)

        assert not result.passed
        # Short-circuits on first match — reports the first offending file
        assert "CLAUDE.md" in result.message

    def test_regex_pattern_across_files(self, tmp_path: Path) -> None:
        """Regex pattern (not just literal) works across multiple files."""
        (tmp_path / "CLAUDE.md").write_text("# Section\nAll fine here.")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "risky.md").write_text("# Rules\napi_key = sk-12345")
        vars = {"instruction_files": ["CLAUDE.md", ".claude/rules/risky.md"]}

        result = content_absent(tmp_path, {"pattern": r"api_key\s*=\s*\S+"}, vars)

        assert not result.passed
        assert "risky.md" in result.message

    def test_empty_files_pass(self, tmp_path: Path) -> None:
        """Empty instruction files pass content_absent (no content to match)."""
        (tmp_path / "CLAUDE.md").write_text("")
        (tmp_path / "AGENTS.md").write_text("")
        vars = {"instruction_files": ["CLAUDE.md", "AGENTS.md"]}

        result = content_absent(tmp_path, {"pattern": "anything"}, vars)

        assert result.passed


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

    def test_check_location_overrides_rule_location(self, tmp_path: Path) -> None:
        """Size checks should use the violating file's path, not the rule-level location."""
        (tmp_path / "CLAUDE.md").write_text("short")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "big.md").write_text("\n".join(f"line{i}" for i in range(50)))
        rules = {"CORE:S:0005": self._rule("CORE:S:0005", "line_count", {"max": 10})}
        vars = {
            "instruction_files": ["CLAUDE.md", ".claude/rules/big.md"],
            "main_instruction_file": ["CLAUDE.md"],
        }
        violations = run_mechanical_checks(rules, tmp_path, vars)
        assert len(violations) == 1
        assert violations[0].location == ".claude/rules/big.md:0"


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


class TestMatchesAnyPattern:
    """Tests for _matches_any_pattern glob helper."""

    def test_exact_match(self) -> None:
        assert _matches_any_pattern("CLAUDE.md", ["CLAUDE.md"])

    def test_double_star_glob(self) -> None:
        assert _matches_any_pattern("CLAUDE.md", ["**/CLAUDE.md"])

    def test_nested_path_matches_double_star(self) -> None:
        assert _matches_any_pattern("docs/CLAUDE.md", ["**/CLAUDE.md"])

    def test_no_match(self) -> None:
        assert not _matches_any_pattern(".claude/skills/SKILL.md", ["**/CLAUDE.md"])

    def test_multiple_patterns(self) -> None:
        assert _matches_any_pattern("foo.md", ["*.txt", "*.md"])

    def test_empty_patterns(self) -> None:
        assert not _matches_any_pattern("CLAUDE.md", [])


class TestBindInstructionFiles:
    """Tests for bind_instruction_files main_instruction_file binding."""

    def test_binds_main_instruction_file(self, tmp_path: Path) -> None:
        files = [tmp_path / "CLAUDE.md", tmp_path / ".claude" / "rules" / "foo.md"]
        vars = {
            "instruction_files": ["**/CLAUDE.md", "**/.claude/rules/*.md"],
            "main_instruction_file": ["**/CLAUDE.md"],
        }
        result = bind_instruction_files(vars, tmp_path, files)
        assert result["instruction_files"] == ["CLAUDE.md", ".claude/rules/foo.md"]
        assert result["main_instruction_file"] == ["CLAUDE.md"]

    def test_main_excludes_skill_files(self, tmp_path: Path) -> None:
        files = [
            tmp_path / ".claude" / "skills" / "integrations" / "SKILL.md",
            tmp_path / "CLAUDE.md",
        ]
        vars = {
            "instruction_files": ["**/CLAUDE.md", "**/.claude/skills/**/*.md"],
            "main_instruction_file": ["**/CLAUDE.md"],
        }
        result = bind_instruction_files(vars, tmp_path, files)
        assert result["main_instruction_file"] == ["CLAUDE.md"]

    def test_no_main_pattern_leaves_unchanged(self, tmp_path: Path) -> None:
        files = [tmp_path / "CLAUDE.md"]
        vars = {"instruction_files": ["**/CLAUDE.md"]}
        result = bind_instruction_files(vars, tmp_path, files)
        assert "main_instruction_file" not in result

    def test_no_instruction_files_returns_original(self) -> None:
        vars = {"instruction_files": ["**/CLAUDE.md"], "main_instruction_file": ["**/CLAUDE.md"]}
        result = bind_instruction_files(vars, Path("/tmp"), None)
        assert result is vars

    def test_main_pattern_as_string(self, tmp_path: Path) -> None:
        files = [tmp_path / "CLAUDE.md"]
        vars = {
            "instruction_files": ["**/CLAUDE.md"],
            "main_instruction_file": "**/CLAUDE.md",
        }
        result = bind_instruction_files(vars, tmp_path, files)
        assert result["main_instruction_file"] == ["CLAUDE.md"]

    def test_no_main_match_keeps_original_patterns(self, tmp_path: Path) -> None:
        files = [tmp_path / ".claude" / "rules" / "foo.md"]
        vars = {
            "instruction_files": ["**/.claude/rules/*.md"],
            "main_instruction_file": ["**/CLAUDE.md"],
        }
        result = bind_instruction_files(vars, tmp_path, files)
        # No files matched the main pattern, so it stays as original
        assert result["main_instruction_file"] == ["**/CLAUDE.md"]


class TestResolveLocationMainFile:
    """Tests for resolve_location preferring main_instruction_file."""

    def _rule_with_targets(self, targets: str) -> Rule:
        return Rule(
            id="CORE:C:0001",
            title="Test rule",
            category=Category.CONTENT,
            type=RuleType.MECHANICAL,
            level="L1",
            targets=targets,
            checks=[],
        )

    def test_prefers_main_instruction_file(self, tmp_path: Path) -> None:
        rule = self._rule_with_targets("{{instruction_files}}")
        vars = {
            "instruction_files": [".claude/skills/integrations/SKILL.md", "CLAUDE.md"],
            "main_instruction_file": ["CLAUDE.md"],
        }
        assert resolve_location(tmp_path, rule, vars) == "CLAUDE.md:0"

    def test_prefers_main_for_main_target(self, tmp_path: Path) -> None:
        rule = self._rule_with_targets("{{main_instruction_file}}")
        vars = {
            "instruction_files": [".claude/skills/SKILL.md", "CLAUDE.md"],
            "main_instruction_file": ["CLAUDE.md"],
        }
        assert resolve_location(tmp_path, rule, vars) == "CLAUDE.md:0"

    def test_falls_back_without_main(self, tmp_path: Path) -> None:
        (tmp_path / ".claude" / "skills").mkdir(parents=True)
        (tmp_path / ".claude" / "skills" / "SKILL.md").write_text("")
        rule = self._rule_with_targets("{{instruction_files}}")
        vars = {"instruction_files": [".claude/skills/SKILL.md", "CLAUDE.md"]}
        # Falls through to generic resolution, picks first from list
        assert resolve_location(tmp_path, rule, vars) == ".claude/skills/SKILL.md:0"

    def test_no_targets_returns_dot(self, tmp_path: Path) -> None:
        rule = self._rule_with_targets("")
        vars = {"main_instruction_file": ["CLAUDE.md"]}
        assert resolve_location(tmp_path, rule, vars) == ".:0"

    def test_non_instruction_target_unchanged(self, tmp_path: Path) -> None:
        (tmp_path / ".reporails").mkdir()
        (tmp_path / ".reporails" / "config.yml").write_text("")
        rule = self._rule_with_targets(".reporails/config.yml")
        vars = {"main_instruction_file": ["CLAUDE.md"]}
        assert resolve_location(tmp_path, rule, vars) == ".reporails/config.yml:0"
