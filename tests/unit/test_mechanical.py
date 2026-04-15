"""Unit tests for the mechanical check runner."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.mechanical.checks import (
    MECHANICAL_CHECKS,
    _safe_float,
    byte_size,
    content_absent,
    directory_exists,
    file_exists,
    git_tracked,
    line_count,
)
from reporails_cli.core.mechanical.checks_advanced import (
    _scope_dir_from_glob,
    check_import_targets_exist,
    count_at_least,
    count_at_most,
    file_absent,
    filename_matches_pattern,
)
from reporails_cli.core.mechanical.runner import (
    resolve_location,
    run_mechanical_checks,
)
from reporails_cli.core.models import Category, Check, ClassifiedFile, FileMatch, Rule, RuleType, Severity


def _cf(root: Path, *rel_paths: str, file_type: str = "main") -> list[ClassifiedFile]:
    """Create ClassifiedFile list from relative paths."""
    return [ClassifiedFile(path=root / p, file_type=file_type) for p in rel_paths]


def _cf_mixed(root: Path, *specs: tuple[str, str]) -> list[ClassifiedFile]:
    """Create ClassifiedFile list from (rel_path, file_type) tuples."""
    return [ClassifiedFile(path=root / p, file_type=ft) for p, ft in specs]


class TestFileExists:
    def test_file_found(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = file_exists(tmp_path, {}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed

    def test_file_not_found(self, tmp_path: Path) -> None:
        result = file_exists(tmp_path, {}, _cf(tmp_path, "CLAUDE.md"))
        assert not result.passed


class TestDirectoryExists:
    def test_exists(self, tmp_path: Path) -> None:
        (tmp_path / ".claude" / "rules").mkdir(parents=True)
        result = directory_exists(tmp_path, {"path": ".claude/rules"}, [])
        assert result.passed

    def test_missing(self, tmp_path: Path) -> None:
        result = directory_exists(tmp_path, {"path": ".claude/rules"}, [])
        assert not result.passed


class TestGitTracked:
    def test_git_dir_present(self, tmp_path: Path) -> None:
        (tmp_path / ".git").mkdir()
        result = git_tracked(tmp_path, {}, [])
        assert result.passed

    def test_no_git(self, tmp_path: Path) -> None:
        result = git_tracked(tmp_path, {}, [])
        assert not result.passed


class TestLineCount:
    def test_within_bounds(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("line1\nline2\nline3\n")
        result = line_count(tmp_path, {"max": 10}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed

    def test_exceeds_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("\n".join(f"line{i}" for i in range(50)))
        result = line_count(tmp_path, {"max": 10}, _cf(tmp_path, "CLAUDE.md"))
        assert not result.passed
        assert result.location == "CLAUDE.md:0"


class TestByteSize:
    def test_within_bounds(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("small")
        result = byte_size(tmp_path, {"max": 1000}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed

    def test_exceeds_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("x" * 1000)
        result = byte_size(tmp_path, {"max": 100}, _cf(tmp_path, "CLAUDE.md"))
        assert not result.passed
        assert result.location == "CLAUDE.md:0"


class TestContentAbsent:
    def test_pattern_absent(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed

    def test_pattern_present(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# FORBIDDEN content here")
        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, _cf(tmp_path, "CLAUDE.md"))
        assert not result.passed

    def test_invalid_regex_returns_failure(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = content_absent(tmp_path, {"pattern": "[invalid"}, _cf(tmp_path, "CLAUDE.md"))
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
        classified = _cf_mixed(
            tmp_path,
            ("CLAUDE.md", "main"),
            (".claude/rules/bad.md", "scoped_rule"),
        )
        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, classified)
        assert not result.passed
        assert "bad.md" in result.message

    def test_pattern_absent_in_all_files(self, tmp_path: Path) -> None:
        """Passes when forbidden pattern absent from all files."""
        (tmp_path / "CLAUDE.md").write_text("# Clean")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "also_clean.md").write_text("# Also clean")
        classified = _cf_mixed(
            tmp_path,
            ("CLAUDE.md", "main"),
            (".claude/rules/also_clean.md", "scoped_rule"),
        )
        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, classified)
        assert result.passed

    def test_pattern_found_in_all_files(self, tmp_path: Path) -> None:
        """Fails on first match (short-circuit) when all files contain pattern."""
        (tmp_path / "CLAUDE.md").write_text("# Has FORBIDDEN")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "also_bad.md").write_text("# Also FORBIDDEN")
        classified = _cf_mixed(
            tmp_path,
            ("CLAUDE.md", "main"),
            (".claude/rules/also_bad.md", "scoped_rule"),
        )
        result = content_absent(tmp_path, {"pattern": "FORBIDDEN"}, classified)
        assert not result.passed
        assert "CLAUDE.md" in result.message

    def test_regex_pattern_across_files(self, tmp_path: Path) -> None:
        """Regex pattern (not just literal) works across multiple files."""
        (tmp_path / "CLAUDE.md").write_text("# Section\nAll fine here.")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "risky.md").write_text("# Rules\napi_key = sk-12345")
        classified = _cf_mixed(
            tmp_path,
            ("CLAUDE.md", "main"),
            (".claude/rules/risky.md", "scoped_rule"),
        )
        result = content_absent(tmp_path, {"pattern": r"api_key\s*=\s*\S+"}, classified)
        assert not result.passed
        assert "risky.md" in result.message

    def test_empty_files_pass(self, tmp_path: Path) -> None:
        """Empty instruction files pass content_absent (no content to match)."""
        (tmp_path / "CLAUDE.md").write_text("")
        (tmp_path / "AGENTS.md").write_text("")
        classified = _cf(tmp_path, "CLAUDE.md", "AGENTS.md")
        result = content_absent(tmp_path, {"pattern": "anything"}, classified)
        assert result.passed


class TestRunMechanicalChecks:
    """Test the runner that dispatches rules to check functions."""

    def _rule(self, rule_id: str, check_name: str, args: dict | None = None) -> Rule:
        return Rule(
            id=rule_id,
            title=f"Rule {rule_id}",
            category=Category.STRUCTURE,
            type=RuleType.MECHANICAL,
            severity=Severity.CRITICAL,
            match=FileMatch(),
            checks=[
                Check(
                    id=f"{rule_id}:check:0001",
                    type="mechanical",
                    check=check_name,
                    args=args,
                ),
            ],
        )

    def test_passing_check_no_violations(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        rules = {"CORE:S:0001": self._rule("CORE:S:0001", "file_exists")}
        classified = _cf(tmp_path, "CLAUDE.md")
        violations = run_mechanical_checks(rules, tmp_path, classified)
        assert len(violations) == 0

    def test_failing_check_produces_violation(self, tmp_path: Path) -> None:
        rules = {"CORE:S:0001": self._rule("CORE:S:0001", "file_exists")}
        classified = _cf(tmp_path, "CLAUDE.md")
        violations = run_mechanical_checks(rules, tmp_path, classified)
        assert len(violations) == 1
        assert violations[0].rule_id == "CORE:S:0001"
        assert violations[0].severity == Severity.CRITICAL
        assert violations[0].check_id == "CORE:S:0001:check:0001"

    def test_unknown_check_skipped(self, tmp_path: Path) -> None:
        rules = {"CORE:S:0001": self._rule("CORE:S:0001", "nonexistent_check")}
        violations = run_mechanical_checks(rules, tmp_path, [])
        assert len(violations) == 0

    def test_multiple_rules(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        # file_exists passes, git_tracked fails (no .git)
        rules = {
            "CORE:S:0001": self._rule("CORE:S:0001", "file_exists"),
            "CORE:S:0004": self._rule("CORE:S:0004", "git_tracked"),
        }
        classified = _cf(tmp_path, "CLAUDE.md")
        violations = run_mechanical_checks(rules, tmp_path, classified)
        assert len(violations) == 1
        assert violations[0].rule_id == "CORE:S:0004"

    def test_check_location_overrides_rule_location(self, tmp_path: Path) -> None:
        """Size checks should use the violating file's path, not the rule-level location."""
        (tmp_path / "CLAUDE.md").write_text("short")
        sub = tmp_path / ".claude" / "rules"
        sub.mkdir(parents=True)
        (sub / "big.md").write_text("\n".join(f"line{i}" for i in range(50)))
        rules = {"CORE:S:0005": self._rule("CORE:S:0005", "line_count", {"max": 10})}
        classified = _cf_mixed(
            tmp_path,
            ("CLAUDE.md", "main"),
            (".claude/rules/big.md", "scoped_rule"),
        )
        violations = run_mechanical_checks(rules, tmp_path, classified)
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
        result = byte_size(tmp_path, {"max": "100"}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed

    def test_byte_size_invalid_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("short")
        result = byte_size(tmp_path, {"max": "invalid"}, _cf(tmp_path, "CLAUDE.md"))
        # invalid → float("inf"), so any file passes
        assert result.passed

    def test_line_count_string_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("line1\nline2\n")
        result = line_count(tmp_path, {"max": "100"}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed

    def test_line_count_invalid_max(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("line1\nline2\n")
        result = line_count(tmp_path, {"max": "invalid"}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed


class TestResolveLocationMainFile:
    """Tests for resolve_location using classified files."""

    def _rule_with_match(self, match: FileMatch | None) -> Rule:
        return Rule(
            id="CORE:C:0001",
            title="Test rule",
            category=Category.COHERENCE,
            type=RuleType.MECHANICAL,
            match=match,
            checks=[],
        )

    def test_prefers_main_classified_file(self, tmp_path: Path) -> None:
        rule = self._rule_with_match(FileMatch())  # match-all
        classified = _cf_mixed(
            tmp_path,
            (".claude/skills/integrations/SKILL.md", "skill"),
            ("CLAUDE.md", "main"),
        )
        assert resolve_location(rule, classified) == "CLAUDE.md:0"

    def test_prefers_main_for_main_match(self, tmp_path: Path) -> None:
        rule = self._rule_with_match(FileMatch(type="main"))
        classified = _cf_mixed(
            tmp_path,
            (".claude/skills/SKILL.md", "skill"),
            ("CLAUDE.md", "main"),
        )
        assert resolve_location(rule, classified) == "CLAUDE.md:0"

    def test_falls_back_without_main(self, tmp_path: Path) -> None:
        rule = self._rule_with_match(FileMatch())  # match-all
        classified = _cf_mixed(
            tmp_path,
            (".claude/skills/SKILL.md", "skill"),
            (".claude/rules/foo.md", "scoped_rule"),
        )
        # No main type — falls back to first classified file
        assert resolve_location(rule, classified) == "SKILL.md:0"

    def test_no_match_returns_dot(self) -> None:
        rule = self._rule_with_match(None)
        classified = _cf(Path("/tmp"), "CLAUDE.md")
        assert resolve_location(rule, classified) == ".:0"

    def test_config_type_resolves_to_settings(self, tmp_path: Path) -> None:
        rule = self._rule_with_match(FileMatch(type="config"))
        classified = _cf_mixed(
            tmp_path,
            (".claude/settings.json", "config"),
            ("CLAUDE.md", "main"),
        )
        assert resolve_location(rule, classified) == "settings.json:0"


# ---------------------------------------------------------------------------
# count_at_most, count_at_least, check_import_targets_exist,
# filename_matches_pattern
# ---------------------------------------------------------------------------


class TestCountAtMost:
    def test_within_threshold(self, tmp_path: Path) -> None:
        result = count_at_most(tmp_path, {"threshold": 3, "items": ["a", "b"]}, [])
        assert result.passed

    def test_at_threshold(self, tmp_path: Path) -> None:
        result = count_at_most(tmp_path, {"threshold": 2, "items": ["a", "b"]}, [])
        assert result.passed

    def test_exceeds_threshold(self, tmp_path: Path) -> None:
        result = count_at_most(tmp_path, {"threshold": 1, "items": ["a", "b", "c"]}, [])
        assert not result.passed
        assert "exceeds" in result.message

    def test_empty_list_passes(self, tmp_path: Path) -> None:
        result = count_at_most(tmp_path, {"threshold": 0}, [])
        assert result.passed

    def test_default_threshold_zero(self, tmp_path: Path) -> None:
        result = count_at_most(tmp_path, {"items": ["a"]}, [])
        assert not result.passed


class TestCountAtLeast:
    def test_meets_minimum(self, tmp_path: Path) -> None:
        result = count_at_least(tmp_path, {"threshold": 2, "items": ["a", "b", "c"]}, [])
        assert result.passed

    def test_at_minimum(self, tmp_path: Path) -> None:
        result = count_at_least(tmp_path, {"threshold": 2, "items": ["a", "b"]}, [])
        assert result.passed

    def test_below_minimum(self, tmp_path: Path) -> None:
        result = count_at_least(tmp_path, {"threshold": 3, "items": ["a"]}, [])
        assert not result.passed
        assert "below" in result.message

    def test_empty_list_fails_default(self, tmp_path: Path) -> None:
        result = count_at_least(tmp_path, {}, [])
        assert not result.passed

    def test_default_threshold_one(self, tmp_path: Path) -> None:
        result = count_at_least(tmp_path, {"items": ["a"]}, [])
        assert result.passed


class TestCheckImportTargetsExist:
    def test_all_imports_resolve(self, tmp_path: Path) -> None:
        (tmp_path / "rules.md").write_text("# Rules")
        (tmp_path / "config.md").write_text("# Config")
        result = check_import_targets_exist(tmp_path, {"import_paths": ["@rules.md", "@config.md"]}, [])
        assert result.passed

    def test_missing_import(self, tmp_path: Path) -> None:
        (tmp_path / "rules.md").write_text("# Rules")
        result = check_import_targets_exist(tmp_path, {"import_paths": ["@rules.md", "@missing.md"]}, [])
        assert not result.passed
        assert "missing.md" in result.message

    def test_empty_imports_pass(self, tmp_path: Path) -> None:
        result = check_import_targets_exist(tmp_path, {}, [])
        assert result.passed

    def test_no_metadata_key_pass(self, tmp_path: Path) -> None:
        result = check_import_targets_exist(tmp_path, {"threshold": 5}, [])
        assert result.passed


class TestFilenameMatchesPattern:
    def test_matches(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = filename_matches_pattern(tmp_path, {"pattern": r"^[A-Z]+\.md$"}, _cf(tmp_path, "CLAUDE.md"))
        assert result.passed

    def test_no_match(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = filename_matches_pattern(tmp_path, {"pattern": r"^[a-z]+\.md$"}, _cf(tmp_path, "CLAUDE.md"))
        assert not result.passed
        assert "does not match" in result.message

    def test_no_pattern_fails(self, tmp_path: Path) -> None:
        result = filename_matches_pattern(tmp_path, {}, _cf(tmp_path, "CLAUDE.md"))
        assert not result.passed

    def test_invalid_regex_fails(self, tmp_path: Path) -> None:
        (tmp_path / "CLAUDE.md").write_text("# Hello")
        result = filename_matches_pattern(tmp_path, {"pattern": "[invalid"}, _cf(tmp_path, "CLAUDE.md"))
        assert not result.passed
        assert "invalid regex" in result.message


class TestFileAbsent:
    def test_file_not_present_passes(self, tmp_path: Path) -> None:
        result = file_absent(tmp_path, {"pattern": "README.md"}, [])
        assert result.passed

    def test_file_present_fails(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# README")
        result = file_absent(tmp_path, {"pattern": "README.md"}, [])
        assert not result.passed
        assert "Forbidden" in result.message

    def test_glob_pattern_no_match_passes(self, tmp_path: Path) -> None:
        result = file_absent(tmp_path, {"pattern": "**/*.lock"}, [])
        assert result.passed

    def test_glob_pattern_match_fails(self, tmp_path: Path) -> None:
        (tmp_path / "package-lock.json").write_text("{}")
        result = file_absent(tmp_path, {"pattern": "**/*.json"}, [])
        assert not result.passed

    def test_no_pattern_fails(self, tmp_path: Path) -> None:
        result = file_absent(tmp_path, {}, [])
        assert not result.passed
        assert "no pattern" in result.message


class TestMatchTypeScoping:
    """Checks respect rule.match.type via injected _match_type arg."""

    def test_filename_matches_pattern_scoped_to_main_file(self, tmp_path: Path) -> None:
        """Bug fix: CORE:S:0004 — should only check main_instruction_file, not all files."""
        (tmp_path / "CLAUDE.md").write_text("# Main")
        (tmp_path / ".claude" / "rules").mkdir(parents=True)
        (tmp_path / ".claude" / "rules" / "core-rules.md").write_text("# Rules")
        classified = _cf_mixed(
            tmp_path,
            ("CLAUDE.md", "main"),
            (".claude/rules/core-rules.md", "scoped_rule"),
        )
        # With _match_type scoping to main, only CLAUDE.md is checked
        args = {"pattern": r"(?i)^(CLAUDE|AGENTS)\.md$", "_match_type": "main"}
        result = filename_matches_pattern(tmp_path, args, classified)
        assert result.passed

    def test_filename_matches_pattern_unscoped_leaks(self, tmp_path: Path) -> None:
        """Without _match_type, filename_matches_pattern falls back to all classified files."""
        (tmp_path / "CLAUDE.md").write_text("# Main")
        (tmp_path / ".claude" / "rules").mkdir(parents=True)
        (tmp_path / ".claude" / "rules" / "core-rules.md").write_text("# Rules")
        classified = _cf_mixed(
            tmp_path,
            ("CLAUDE.md", "main"),
            (".claude/rules/core-rules.md", "scoped_rule"),
        )
        # Without _match_type, falls back to all classified files — core-rules.md fails regex
        args = {"pattern": r"(?i)^(CLAUDE|AGENTS)\.md$"}
        result = filename_matches_pattern(tmp_path, args, classified)
        assert not result.passed
        assert "core-rules.md" in result.message

    def test_file_absent_scoped_ignores_root_readme(self, tmp_path: Path) -> None:
        """Bug fix: CLAUDE:S:0001 — README.md at root should not trigger file_absent in skills."""
        (tmp_path / "README.md").write_text("# Project readme")
        skills = tmp_path / ".claude" / "skills" / "test-skill"
        skills.mkdir(parents=True)
        (skills / "SKILL.md").write_text("# Skill")
        args = {"pattern": "README.md", "_match_type": "skill"}
        classified = [ClassifiedFile(path=skills / "SKILL.md", file_type="skill")]
        result = file_absent(tmp_path, args, classified)
        assert result.passed

    def test_file_absent_scoped_catches_readme_in_skills(self, tmp_path: Path) -> None:
        """file_absent with scope detects README.md inside skills directory."""
        skills = tmp_path / ".claude" / "skills" / "test-skill"
        skills.mkdir(parents=True)
        (skills / "SKILL.md").write_text("# Skill")
        (skills / "README.md").write_text("# Bad")
        args = {"pattern": "README.md", "_match_type": "skill"}
        classified = [ClassifiedFile(path=skills / "SKILL.md", file_type="skill")]
        result = file_absent(tmp_path, args, classified)
        assert not result.passed
        assert "README.md" in result.message

    def test_file_absent_unscoped_finds_root_readme(self, tmp_path: Path) -> None:
        """Without _match_type, file_absent searches from project root (original behavior)."""
        (tmp_path / "README.md").write_text("# Project")
        result = file_absent(tmp_path, {"pattern": "README.md"}, [])
        assert not result.passed

    def test_explicit_path_overrides_targets(self, tmp_path: Path) -> None:
        """Explicit args.path takes priority over classified files."""
        (tmp_path / "CLAUDE.md").write_text("# Main")
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "notes.md").write_text("# Notes")
        classified = _cf(tmp_path, "CLAUDE.md")
        # path points to docs/ — path arg wins over classified files
        args = {"pattern": r"^CLAUDE\.md$", "path": "docs/**/*.md"}
        result = filename_matches_pattern(tmp_path, args, classified)
        assert not result.passed
        assert "notes.md" in result.message


class TestScopeDirFromGlob:
    """Unit tests for _scope_dir_from_glob helper."""

    def test_skills_dir_glob(self) -> None:
        assert _scope_dir_from_glob(".claude/skills/**/*.md") == ".claude/skills"

    def test_wildcard_at_start(self) -> None:
        assert _scope_dir_from_glob("**/CLAUDE.md") == ""

    def test_no_glob(self) -> None:
        assert _scope_dir_from_glob("docs/README.md") == "docs/README.md"

    def test_single_dir(self) -> None:
        assert _scope_dir_from_glob("src/*.py") == "src"

    def test_empty(self) -> None:
        assert _scope_dir_from_glob("") == ""


class TestAliases:
    """Signal catalog aliases map to existing probes."""

    def test_glob_match_is_file_exists(self) -> None:
        assert MECHANICAL_CHECKS["glob_match"] is MECHANICAL_CHECKS["file_exists"]

    def test_max_line_count_is_line_count(self) -> None:
        assert MECHANICAL_CHECKS["max_line_count"] is MECHANICAL_CHECKS["line_count"]

    def test_glob_count_is_file_count(self) -> None:
        assert MECHANICAL_CHECKS["glob_count"] is MECHANICAL_CHECKS["file_count"]
