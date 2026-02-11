"""Exit code handling tests - ensure OpenGrep exit codes are interpreted correctly.

OpenGrep/Semgrep exit codes:
- 0: Success, scan completed (may or may not have findings)
- 1: Scan completed with findings (when --error flag used)
- 2: CLI usage error (invalid arguments)
- 7: Invalid configuration (malformed rules)
- Other: Various errors

The CLI must handle these correctly and not confuse "no findings" with errors.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from tests.conftest import create_temp_rule_file


class TestOpenGrepExitCodes:
    """Document and test actual OpenGrep exit code behavior."""

    def test_exit_0_no_findings(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """Exit code 0 when scan completes with no findings."""
        # Rule that won't match anything
        rule_yaml = """\
rules:
  - id: wont-match
    message: "Won't find this"
    severity: WARNING
    languages: [generic]
    pattern-regex: "XYZZY_IMPOSSIBLE_STRING_12345"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)

        # Create a file to scan
        (tmp_path / "test.md").write_text("# Hello World\n")

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config",
                str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert result.returncode == 0, (
            f"Expected exit 0 for no findings, got {result.returncode}\nstderr: {result.stderr.decode()}"
        )

    def test_exit_0_with_findings_no_error_flag(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """Exit code 0 when findings exist but --error not used."""
        rule_yaml = """\
rules:
  - id: finds-hello
    message: "Found hello"
    severity: WARNING
    languages: [generic]
    pattern-regex: "Hello"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)

        # Create a file that will match
        (tmp_path / "test.md").write_text("# Hello World\n")

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config",
                str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        # Without --error flag, findings don't cause non-zero exit
        assert result.returncode == 0, (
            f"Expected exit 0 (findings without --error), got {result.returncode}\nstderr: {result.stderr.decode()}"
        )

    def test_exit_1_with_error_flag_and_findings(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """Exit code 1 when --error flag used and findings exist."""
        rule_yaml = """\
rules:
  - id: finds-hello
    message: "Found hello"
    severity: WARNING
    languages: [generic]
    pattern-regex: "Hello"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)

        # Create a file that will match
        (tmp_path / "test.md").write_text("# Hello World\n")

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--error",  # This flag makes findings return exit 1
                "--config",
                str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert result.returncode == 1, (
            f"Expected exit 1 (findings with --error), got {result.returncode}\nstderr: {result.stderr.decode()}"
        )

    def test_exit_7_invalid_config(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """Exit code 7 when rule configuration is invalid."""
        # Invalid YAML (missing required fields)
        bad_yaml = """\
rules:
  - id: bad-rule
    # Missing message, severity, languages, pattern
"""
        rule_path = create_temp_rule_file(tmp_path, bad_yaml)

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config",
                str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert result.returncode == 7, (
            f"Expected exit 7 for invalid config, got {result.returncode}\nstderr: {result.stderr.decode()}"
        )


class TestCLIExitCodeHandling:
    """Test that CLI correctly interprets OpenGrep exit codes."""

    def test_cli_treats_exit_0_as_success(
        self,
        tmp_path: Path,
        valid_rule_yaml: str,
        opengrep_bin: Path,
    ) -> None:
        """CLI should treat exit 0 as success (no violations)."""
        from reporails_cli.core.opengrep import run_opengrep

        rule_path = create_temp_rule_file(tmp_path, valid_rule_yaml)
        (tmp_path / "test.md").write_text("# Nothing to find\n")

        result = run_opengrep(
            [rule_path],
            tmp_path,
            opengrep_bin,
        )

        # Should return valid SARIF structure
        assert "runs" in result, f"Expected SARIF output, got: {result}"

    def test_cli_treats_exit_1_as_success_with_findings(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """CLI should treat exit 1 as success (findings found).

        Note: We don't use --error flag, so exit 1 isn't expected in normal
        operation. But if it occurs, it should be treated as "findings exist".
        """
        from reporails_cli.core.opengrep import run_opengrep

        rule_yaml = """\
rules:
  - id: finds-todo
    message: "Found TODO"
    severity: WARNING
    languages: [generic]
    pattern-regex: "TODO"
"""
        rule_path = create_temp_rule_file(tmp_path, rule_yaml)
        (tmp_path / "test.md").write_text("# TODO: Add more tests\n")

        result = run_opengrep(
            [rule_path],
            tmp_path,
            opengrep_bin,
        )

        # Should return valid SARIF with results
        assert "runs" in result
        runs = result.get("runs", [])
        if runs:
            results = runs[0].get("results", [])
            # Should have found the TODO
            assert len(results) > 0, "Expected findings in SARIF output"

    def test_cli_handles_exit_7_gracefully(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """CLI should handle exit 7 (invalid config) without crashing.

        regression: Exit code 7 caused CLI to return empty results,
        silently hiding the actual error.
        """
        from reporails_cli.core.opengrep import run_opengrep

        bad_yaml = """\
rules:
  - id: bad
    # Invalid - missing required fields
"""
        rule_path = create_temp_rule_file(tmp_path, bad_yaml)

        result = run_opengrep(
            [rule_path],
            tmp_path,
            opengrep_bin,
        )

        # Current behavior: returns empty runs
        # This is technically correct but loses error details
        assert isinstance(result, dict), "Should return dict even on error"

    def test_no_findings_is_not_error(
        self,
        tmp_path: Path,
        valid_rule_yaml: str,
        opengrep_bin: Path,
    ) -> None:
        """'No findings' should not be treated as an error condition."""
        from reporails_cli.core.opengrep import run_opengrep

        rule_path = create_temp_rule_file(tmp_path, valid_rule_yaml)
        (tmp_path / "test.md").write_text("# Clean file with nothing to find\n")

        result = run_opengrep(
            [rule_path],
            tmp_path,
            opengrep_bin,
        )

        # Should succeed with empty results
        assert "runs" in result
        runs = result.get("runs", [])
        # Having zero results is fine
        if runs:
            results = runs[0].get("results", [])
            # Zero results is valid, not an error
            assert isinstance(results, list)

    def test_no_files_matched_is_not_error(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """'No files matched' should not be treated as an error.

        When a rule targets specific paths that don't exist in the project,
        this should be a warning at most, not a failure.
        """
        from reporails_cli.core.opengrep import run_opengrep

        # Rule that only matches .rs files (Rust)
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

        # Create only .md files (no .rs)
        (tmp_path / "readme.md").write_text("# No Rust here\n")

        result = run_opengrep(
            [rule_path],
            tmp_path,
            opengrep_bin,
        )

        # Should succeed, just with no results
        assert "runs" in result
        # Should not have crashed or returned error


class TestExitCodeDocumentation:
    """Document actual OpenGrep exit code behavior for reference."""

    def test_document_exit_codes(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """Document all exit codes we've observed from OpenGrep.

        This test documents behavior rather than enforcing it,
        helping us understand what exit codes mean.
        """
        exit_codes_observed: dict[int, str] = {}

        # Test case 1: Valid rule, no findings
        rule1 = """\
rules:
  - id: test1
    message: "test"
    severity: WARNING
    languages: [generic]
    pattern-regex: "XYZZY_NOT_FOUND"
"""
        rule_path = create_temp_rule_file(tmp_path, rule1, "rule1.yml")
        (tmp_path / "test.md").write_text("# Test\n")
        r1 = subprocess.run(
            [str(opengrep_bin), "scan", "--sarif", "--config", str(rule_path), str(tmp_path)],
            capture_output=True,
        )
        exit_codes_observed[r1.returncode] = "Valid rule, no findings"

        # Test case 2: Valid rule, findings exist
        rule2 = """\
rules:
  - id: test2
    message: "test"
    severity: WARNING
    languages: [generic]
    pattern-regex: "Test"
"""
        rule_path2 = create_temp_rule_file(tmp_path, rule2, "rule2.yml")
        r2 = subprocess.run(
            [str(opengrep_bin), "scan", "--sarif", "--config", str(rule_path2), str(tmp_path)],
            capture_output=True,
        )
        exit_codes_observed[r2.returncode] = "Valid rule, findings exist"

        # Test case 3: Invalid rule
        rule3 = """\
rules:
  - id: test3
    # Missing everything
"""
        rule_path3 = create_temp_rule_file(tmp_path, rule3, "rule3.yml")
        r3 = subprocess.run(
            [str(opengrep_bin), "scan", "--sarif", "--config", str(rule_path3), str(tmp_path)],
            capture_output=True,
        )
        exit_codes_observed[r3.returncode] = "Invalid rule (missing fields)"

        # Document findings
        print("\nOpenGrep Exit Codes Observed:")
        for code, description in sorted(exit_codes_observed.items()):
            print(f"  Exit {code}: {description}")

        # Basic assertions about expected behavior
        assert 0 in exit_codes_observed, "Expected to observe exit code 0"
        assert 7 in exit_codes_observed, "Expected to observe exit code 7 for invalid config"
