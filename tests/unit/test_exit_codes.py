"""Regex engine behavior tests - ensure the regex engine handles edge cases correctly.

The regex engine must:
- Return valid SARIF structure for all inputs
- Return empty results for non-matching rules
- Return results for matching rules
- Handle invalid/missing rules gracefully
"""

from __future__ import annotations

from pathlib import Path

from tests.conftest import create_temp_rule_file


class TestRegexEngineResults:
    """Test that regex engine returns correct results."""

    def test_no_findings_returns_empty_results(
        self,
        tmp_path: Path,
    ) -> None:
        """No matches should return valid SARIF with empty results."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: wont-match
    message: "Won't find this"
    severity: WARNING
    languages: [generic]
    pattern-regex: "XYZZY_IMPOSSIBLE_STRING_12345"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("# Hello World\n")

        result = run_validation([rule_path], tmp_path)

        assert "runs" in result
        runs = result.get("runs", [])
        if runs:
            results = runs[0].get("results", [])
            assert isinstance(results, list)
            assert len(results) == 0

    def test_findings_returned_correctly(
        self,
        tmp_path: Path,
    ) -> None:
        """Matching patterns should return SARIF results."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: finds-hello
    message: "Found hello"
    severity: WARNING
    languages: [generic]
    pattern-regex: "Hello"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("# Hello World\n")

        result = run_validation([rule_path], tmp_path)

        assert "runs" in result
        runs = result.get("runs", [])
        assert runs
        results = runs[0].get("results", [])
        assert len(results) > 0, "Expected findings in SARIF output"

    def test_invalid_rule_handled_gracefully(
        self,
        tmp_path: Path,
    ) -> None:
        """Invalid/incomplete rules should not crash, just be skipped."""
        from reporails_cli.core.regex import run_validation

        bad_yaml = """\
rules:
  - id: bad-rule
    # Missing message, severity, pattern
"""
        rule_path = create_temp_rule_file(tmp_path, bad_yaml)
        (tmp_path / "test.md").write_text("# Test\n")

        result = run_validation([rule_path], tmp_path)

        assert isinstance(result, dict), "Should return dict even on invalid rules"
        assert "runs" in result

    def test_no_files_matched_is_not_error(
        self,
        tmp_path: Path,
    ) -> None:
        """'No files matched' should not be treated as an error."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: rust-only
    message: "Rust check"
    severity: WARNING
    languages: [generic]
    pattern-regex: "fn main"
    paths:
      include:
        - "**/*.rs"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "readme.md").write_text("# No Rust here\n")

        result = run_validation([rule_path], tmp_path)

        assert "runs" in result
        # Should succeed, just with no results for .rs filter on .md files


class TestSARIFOutputFormat:
    """Test that SARIF output has the correct structure."""

    def test_sarif_has_correct_structure(
        self,
        tmp_path: Path,
    ) -> None:
        """SARIF output must have runs[].tool.driver.rules[] and runs[].results[]."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-structure
    message: "Found TODO"
    severity: WARNING
    languages: [generic]
    pattern-regex: "TODO"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("# TODO: Add more tests\n")

        result = run_validation([rule_path], tmp_path)

        assert "runs" in result
        runs = result["runs"]
        assert len(runs) == 1

        run = runs[0]
        assert "tool" in run
        assert "driver" in run["tool"]
        assert "rules" in run["tool"]["driver"]
        assert "results" in run

        # Check result structure
        for r in run["results"]:
            assert "ruleId" in r
            assert "message" in r
            assert "text" in r["message"]
            assert "locations" in r
            loc = r["locations"][0]["physicalLocation"]
            assert "artifactLocation" in loc
            assert "region" in loc
            assert "startLine" in loc["region"]

    def test_sarif_rule_definitions_present(
        self,
        tmp_path: Path,
    ) -> None:
        """SARIF tool.driver.rules[] must have matching definitions for results."""
        from reporails_cli.core.regex import run_validation

        rule_yaml = """\
rules:
  - id: test-defs
    message: "Match"
    severity: WARNING
    languages: [generic]
    pattern-regex: "Hello"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("Hello World\n")

        result = run_validation([rule_path], tmp_path)

        run = result["runs"][0]
        rule_defs = {r["id"] for r in run["tool"]["driver"]["rules"]}
        result_rule_ids = {r["ruleId"] for r in run["results"]}

        # Every result's ruleId should have a matching rule definition
        assert result_rule_ids.issubset(rule_defs)
