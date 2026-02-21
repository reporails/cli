"""Rule validation tests - ensure the regex engine correctly handles various rule formats.

Tests that the regex engine handles all supported pattern operators
and gracefully skips unsupported ones.
"""

from __future__ import annotations

from pathlib import Path

from tests.conftest import create_temp_rule_file


class TestPatternOperators:
    """Test that all pattern operators are handled correctly."""

    def test_pattern_regex_matches(self, tmp_path: Path) -> None:
        """Simple pattern-regex should match content."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-simple
    message: "Found a TODO comment"
    severity: WARNING
    languages: [generic]
    pattern-regex: "TODO"
    paths:
      include:
        - "**/*.md"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("# TODO: Fix this\n")

        result = run_validation([rule_path], tmp_path)

        results = result["runs"][0]["results"]
        assert len(results) > 0, "pattern-regex should find TODO"

    def test_pattern_either_matches_any(self, tmp_path: Path) -> None:
        """pattern-either should match if any sub-pattern matches."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-either
    message: "Found test framework"
    severity: WARNING
    languages: [generic]
    pattern-either:
      - pattern-regex: "(?i)pytest"
      - pattern-regex: "(?i)jest"
      - pattern-regex: "(?i)mocha"
    paths:
      include:
        - "**/*.md"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("## Testing\n\nWe use jest for testing.\n")

        result = run_validation([rule_path], tmp_path)

        results = result["runs"][0]["results"]
        assert len(results) > 0, "pattern-either should match 'jest'"

    def test_patterns_block_with_not_regex(self, tmp_path: Path) -> None:
        """patterns block with pattern-not-regex (AND + negation)."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-patterns-and
    message: "File has content but no Commands section"
    severity: WARNING
    languages: [generic]
    patterns:
      - pattern-regex: "."
      - pattern-not-regex: "## Commands"
    paths:
      include:
        - "**/*.md"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)

        # File WITHOUT ## Commands → should match (negation passes)
        (tmp_path / "no-commands.md").write_text("# Project\n\nSome content.\n")

        result = run_validation([rule_path], tmp_path)

        results = result["runs"][0]["results"]
        assert len(results) > 0, "patterns block should match file without ## Commands"

    def test_patterns_block_negation_suppresses(self, tmp_path: Path) -> None:
        """patterns block with pattern-not-regex should NOT match when negation hits."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-neg-suppresses
    message: "Missing commands"
    severity: WARNING
    languages: [generic]
    patterns:
      - pattern-regex: "."
      - pattern-not-regex: "## Commands"
    paths:
      include:
        - "**/*.md"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)

        # File WITH ## Commands → negation should suppress match
        (tmp_path / "has-commands.md").write_text("# Project\n\n## Commands\n\n- npm install\n")

        result = run_validation([rule_path], tmp_path)

        results = result["runs"][0]["results"]
        assert len(results) == 0, "pattern-not-regex should suppress match when ## Commands exists"

    def test_no_pattern_operator_skipped(self, tmp_path: Path) -> None:
        """Rule with no recognized pattern operator should be skipped."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-no-pattern
    message: "No pattern"
    severity: WARNING
    languages: [generic]
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("# Test\n")

        result = run_validation([rule_path], tmp_path)

        # Should not crash, just return empty
        assert isinstance(result, dict)


class TestPathFiltering:
    """Test that path include filters work correctly."""

    def test_path_filter_includes_matching(self, tmp_path: Path) -> None:
        """Files matching path include patterns should be scanned."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-path
    message: "Found in md"
    severity: WARNING
    languages: [generic]
    pattern-regex: "Hello"
    paths:
      include:
        - "**/*.md"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("Hello World\n")
        (tmp_path / "test.txt").write_text("Hello World\n")

        result = run_validation([rule_path], tmp_path)

        results = result["runs"][0]["results"]
        # Should find in .md but not .txt
        uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results]
        assert any(".md" in u for u in uris), "Should match .md file"
        assert not any(".txt" in u for u in uris), "Should not match .txt file"

    def test_no_path_filter_scans_all_md(self, tmp_path: Path) -> None:
        """Rules without path filters should scan all markdown files."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-no-filter
    message: "Found"
    severity: WARNING
    languages: [generic]
    pattern-regex: "Hello"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("Hello\n")

        result = run_validation([rule_path], tmp_path)

        results = result["runs"][0]["results"]
        assert len(results) > 0


class TestLineNumbers:
    """Test that line numbers are correctly reported."""

    def test_line_number_accuracy(self, tmp_path: Path) -> None:
        """Line numbers in SARIF results should be accurate."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-lines
    message: "Found TODO"
    severity: WARNING
    languages: [generic]
    pattern-regex: "TODO"
    paths:
      include:
        - "**/*.md"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("# Title\n\nSome text.\n\nTODO: Fix this\n")

        result = run_validation([rule_path], tmp_path)

        results = result["runs"][0]["results"]
        assert len(results) == 1
        line = results[0]["locations"][0]["physicalLocation"]["region"]["startLine"]
        assert line == 5, f"TODO is on line 5, got {line}"
