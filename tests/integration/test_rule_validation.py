"""Rule validation tests - ensure we correctly identify valid vs invalid rules.

The CLI must agree with what semgrep/opengrep actually accepts.
If our validation disagrees with semgrep, we're wrong.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from tests.conftest import create_temp_rule_file


class TestOpenGrepSchemaValidation:
    """Test that we correctly identify valid vs invalid OpenGrep rule schemas."""

    def test_valid_simple_rule_accepted(
        self,
        tmp_path: Path,
        valid_rule_yaml: str,
        opengrep_bin: Path,
    ) -> None:
        """A simple valid rule should be accepted by OpenGrep."""
        rule_path = create_temp_rule_file(tmp_path, valid_rule_yaml)

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config", str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        # Exit code 0 or 1 (findings) is success
        assert result.returncode in (0, 1), (
            f"Valid rule rejected by OpenGrep (exit {result.returncode}):\n"
            f"stderr: {result.stderr.decode()}\n"
            f"Rule:\n{valid_rule_yaml}"
        )

    def test_valid_patterns_block_rule_accepted(
        self,
        tmp_path: Path,
        valid_rule_with_patterns_yaml: str,
        opengrep_bin: Path,
    ) -> None:
        """A rule using patterns: block should be accepted."""
        rule_path = create_temp_rule_file(tmp_path, valid_rule_with_patterns_yaml)

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config", str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert result.returncode in (0, 1), (
            f"Valid patterns rule rejected (exit {result.returncode}):\n"
            f"stderr: {result.stderr.decode()}\n"
            f"Rule:\n{valid_rule_with_patterns_yaml}"
        )

    def test_toplevel_pattern_not_regex_rejected(
        self,
        tmp_path: Path,
        invalid_toplevel_pattern_not_regex_yaml: str,
        opengrep_bin: Path,
    ) -> None:
        """pattern-not-regex at top level is INVALID and must be rejected.

        regression: This was the root cause of the "6 invalid rules" issue.
        pattern-not-regex requires a patterns: block wrapper.
        """
        rule_path = create_temp_rule_file(tmp_path, invalid_toplevel_pattern_not_regex_yaml)

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--output", str(tmp_path / "out.sarif"),
                "--config", str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        # Should return error exit code (7 = invalid config)
        # OR produce SARIF with error notifications
        if result.returncode in (0, 1):
            # Check SARIF for errors
            sarif_path = tmp_path / "out.sarif"
            if sarif_path.exists():
                sarif = json.loads(sarif_path.read_text())
                runs = sarif.get("runs", [])
                if runs:
                    notifications = (
                        runs[0]
                        .get("invocations", [{}])[0]
                        .get("toolExecutionNotifications", [])
                    )
                    has_schema_error = any(
                        "InvalidRuleSchemaError" in n.get("descriptor", {}).get("id", "")
                        for n in notifications
                    )
                    assert has_schema_error, (
                        "OpenGrep accepted invalid top-level pattern-not-regex!\n"
                        f"This schema should be rejected:\n{invalid_toplevel_pattern_not_regex_yaml}"
                    )
        else:
            # Non-zero exit code is expected for invalid config
            assert result.returncode == 7, (
                f"Expected exit code 7 for invalid config, got {result.returncode}"
            )

    def test_correct_pattern_not_regex_in_patterns_block(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """pattern-not-regex INSIDE patterns: block should be accepted.

        This is the correct way to use pattern-not-regex.
        """
        correct_yaml = """\
rules:
  - id: test-correct-pattern-not
    message: "Missing required section"
    severity: WARNING
    languages: [generic]
    patterns:
      - pattern-regex: "."
      - pattern-not-regex: "## Commands"
    paths:
      include:
        - "**/*.md"
"""
        rule_path = create_temp_rule_file(tmp_path, correct_yaml)

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config", str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert result.returncode in (0, 1), (
            f"Correct pattern-not-regex in patterns block rejected:\n"
            f"stderr: {result.stderr.decode()}"
        )


class TestRuleMissingFields:
    """Test that rules with missing required fields are handled correctly."""

    def test_missing_id_rejected(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """Rule without id field should be rejected."""
        bad_yaml = """\
rules:
  - message: "No id"
    severity: WARNING
    languages: [generic]
    pattern-regex: "test"
"""
        rule_path = create_temp_rule_file(tmp_path, bad_yaml)

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config", str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert result.returncode not in (0, 1), (
            f"Rule without 'id' should be rejected, but got exit {result.returncode}"
        )

    def test_missing_message_rejected(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """Rule without message field should be rejected."""
        bad_yaml = """\
rules:
  - id: no-message
    severity: WARNING
    languages: [generic]
    pattern-regex: "test"
"""
        rule_path = create_temp_rule_file(tmp_path, bad_yaml)

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config", str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert result.returncode not in (0, 1), (
            f"Rule without 'message' should be rejected, but got exit {result.returncode}"
        )

    def test_missing_pattern_rejected(
        self,
        tmp_path: Path,
        opengrep_bin: Path,
    ) -> None:
        """Rule without any pattern field should be rejected."""
        bad_yaml = """\
rules:
  - id: no-pattern
    message: "No pattern"
    severity: WARNING
    languages: [generic]
"""
        rule_path = create_temp_rule_file(tmp_path, bad_yaml)

        result = subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--config", str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert result.returncode not in (0, 1), (
            f"Rule without pattern should be rejected, but got exit {result.returncode}"
        )


class TestSARIFErrorReporting:
    """Test that OpenGrep SARIF output contains useful error information."""

    def test_sarif_contains_error_details(
        self,
        tmp_path: Path,
        invalid_toplevel_pattern_not_regex_yaml: str,
        opengrep_bin: Path,
    ) -> None:
        """SARIF output should contain details about validation errors."""
        rule_path = create_temp_rule_file(tmp_path, invalid_toplevel_pattern_not_regex_yaml)
        sarif_path = tmp_path / "output.sarif"

        subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--output", str(sarif_path),
                "--config", str(rule_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        assert sarif_path.exists(), "SARIF output file not created"

        sarif = json.loads(sarif_path.read_text())
        runs = sarif.get("runs", [])
        assert runs, "SARIF has no runs"

        # Check for error notifications
        notifications = (
            runs[0]
            .get("invocations", [{}])[0]
            .get("toolExecutionNotifications", [])
        )

        error_messages = [
            n.get("message", {}).get("text", "")
            for n in notifications
            if n.get("level") == "error"
        ]

        assert error_messages, (
            "SARIF should contain error notifications for invalid rule"
        )

        # Error should mention the rule ID or schema issue
        combined_errors = " ".join(error_messages)
        assert "invalid" in combined_errors.lower() or "schema" in combined_errors.lower(), (
            f"Error messages should mention invalid schema: {error_messages}"
        )


class TestCLIRuleValidation:
    """Test that CLI correctly handles rule validation results."""

    def test_cli_handles_mixed_valid_invalid_rules(
        self,
        tmp_path: Path,
        valid_rule_yaml: str,
        invalid_toplevel_pattern_not_regex_yaml: str,
        opengrep_bin: Path,
    ) -> None:
        """CLI should handle mix of valid and invalid rules gracefully.

        When some rules are invalid:
        - Valid rules should still run
        - Invalid rules should be reported (not silently skipped)
        - Overall result should indicate partial success
        """
        valid_path = create_temp_rule_file(tmp_path, valid_rule_yaml, "valid.yml")
        invalid_path = create_temp_rule_file(
            tmp_path, invalid_toplevel_pattern_not_regex_yaml, "invalid.yml"
        )

        sarif_path = tmp_path / "output.sarif"

        subprocess.run(
            [
                str(opengrep_bin),
                "scan",
                "--sarif",
                "--output", str(sarif_path),
                "--config", str(valid_path),
                "--config", str(invalid_path),
                str(tmp_path),
            ],
            capture_output=True,
        )

        # When mixing valid and invalid, OpenGrep returns exit code 7
        # but still processes valid rules

        sarif = json.loads(sarif_path.read_text())
        runs = sarif.get("runs", [])

        # Should have notifications about the invalid rule
        notifications = (
            runs[0]
            .get("invocations", [{}])[0]
            .get("toolExecutionNotifications", [])
        )

        has_errors = any(n.get("level") == "error" for n in notifications)
        assert has_errors, (
            "Should report error for invalid rule in mixed config"
        )
