"""End-to-end CLI tests — exercise ails commands via Typer CliRunner.

Covers the update-related CLI surface:
  - ails version (shows recommended line)
  - ails check --no-update-check (flag accepted, prompt skipped)
  - ails check -f json (JSON output parseable)
  - ails update --check (framework + recommended sections)
  - ails update (default: both rules + recommended)
  - ails update --recommended (recommended-only path)
  - ails update --version X (rules-only, no recommended)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


def _rules_installed() -> bool:
    """Check if rules framework is installed."""
    from reporails_cli.core.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(
    not _rules_installed(),
    reason="Rules framework not installed",
)


# ---------------------------------------------------------------------------
# ails version
# ---------------------------------------------------------------------------


class TestVersionCommand:
    def test_shows_all_component_lines(self) -> None:
        """ails version should show CLI, Framework, Recommended, OpenGrep, Install."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0, result.output
        assert "CLI:" in result.output
        assert "Framework:" in result.output
        assert "Recommended:" in result.output
        assert "OpenGrep:" in result.output
        assert "Install:" in result.output

    def test_shows_recommended_version(self) -> None:
        """Recommended line should include installed + bundled versions."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0, result.output
        # Should show either a version or "not installed"
        for line in result.output.splitlines():
            if "Recommended:" in line:
                assert "bundled:" in line or "not installed" in line
                break
        else:
            raise AssertionError("Recommended line not found in version output")


# ---------------------------------------------------------------------------
# ails check
# ---------------------------------------------------------------------------


class TestCheckCommand:
    @requires_rules
    def test_no_update_check_flag_accepted(self, level2_project: Path) -> None:
        """--no-update-check should be a valid flag that doesn't error."""
        result = runner.invoke(app, [
            "check", str(level2_project),
            "--no-update-check",
            "-q",
            "-f", "text",
        ])
        assert result.exit_code == 0, result.output

    def test_json_output_parseable(self, level2_project: Path) -> None:
        """JSON output should be valid JSON with expected keys."""
        result = runner.invoke(app, [
            "check", str(level2_project),
            "-f", "json",
            "--no-update-check",
        ])
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "score" in data
        assert "level" in data
        assert "violations" in data

    @requires_rules
    def test_text_output_has_score(self, level2_project: Path) -> None:
        """Text output should contain score line."""
        result = runner.invoke(app, [
            "check", str(level2_project),
            "--no-update-check",
            "-q",
            "-f", "text",
        ])
        assert result.exit_code == 0, result.output
        assert "SCORE:" in result.output or "/ 10" in result.output

    def test_compact_output_works(self, level2_project: Path) -> None:
        """Compact format should produce output."""
        result = runner.invoke(app, [
            "check", str(level2_project),
            "-f", "compact",
            "--no-update-check",
        ])
        assert result.exit_code == 0, result.output
        assert len(result.output.strip()) > 0

    def test_missing_path_errors(self) -> None:
        """Non-existent path should produce error and exit 1."""
        result = runner.invoke(app, [
            "check", "/tmp/definitely-not-a-real-path-xyz",
            "--no-update-check",
        ])
        assert result.exit_code == 1

    def test_no_instruction_files_message(self, tmp_path: Path) -> None:
        """Empty directory should report no instruction files."""
        result = runner.invoke(app, [
            "check", str(tmp_path),
            "--no-update-check",
        ])
        assert result.exit_code == 0
        assert "No instruction files found" in result.output

    @requires_rules
    def test_strict_mode_exits_1_on_violations(self, level2_project: Path) -> None:
        """--strict should exit 1 when violations exist."""
        # Use level2 — more rules apply, more likely to have violations
        result = runner.invoke(app, [
            "check", str(level2_project),
            "--strict",
            "--no-update-check",
            "-f", "json",
        ])
        # If rules apply and violations exist, exit 1; otherwise check score
        data = json.loads(result.output)
        if data.get("violations"):
            assert result.exit_code == 1
        else:
            # No violations = clean project, exit 0 is correct
            assert result.exit_code == 0

    def test_pre_run_prompt_skipped_in_json_format(self, level2_project: Path) -> None:
        """JSON format should not trigger update prompt (even without --no-update-check)."""
        # CliRunner is non-TTY so prompt would be skipped anyway,
        # but json format adds another guard
        result = runner.invoke(app, [
            "check", str(level2_project),
            "-f", "json",
        ])
        assert result.exit_code == 0, result.output
        # Output should be valid JSON (no prompt text mixed in)
        data = json.loads(result.output)
        assert "score" in data


# ---------------------------------------------------------------------------
# ails update --check
# ---------------------------------------------------------------------------


class TestUpdateCheckCommand:
    def test_shows_framework_and_recommended_sections(self) -> None:
        """--check should display both Framework and Recommended sections."""
        result = runner.invoke(app, ["update", "--check"])
        assert result.exit_code == 0, result.output
        assert "Framework:" in result.output
        assert "Recommended:" in result.output
        assert "Installed:" in result.output
        assert "Latest:" in result.output

    def test_shows_up_to_date_when_current(self) -> None:
        """When all components are current, should say up to date."""
        with (
            patch(
                "reporails_cli.core.bootstrap.get_installed_version",
                return_value="0.3.1",
            ),
            patch(
                "reporails_cli.core.init.get_latest_version",
                return_value="0.3.1",
            ),
            patch(
                "reporails_cli.core.bootstrap.get_installed_recommended_version",
                return_value="0.1.0",
            ),
            patch(
                "reporails_cli.core.init.get_latest_recommended_version",
                return_value="0.1.0",
            ),
        ):
            result = runner.invoke(app, ["update", "--check"])

        assert result.exit_code == 0, result.output
        assert "up to date" in result.output.lower()


# ---------------------------------------------------------------------------
# ails update (default path)
# ---------------------------------------------------------------------------


class TestUpdateDefaultCommand:
    def test_updates_both_rules_and_recommended(self) -> None:
        """Default ails update should attempt both rules and recommended."""
        mock_rules_result = MagicMock(
            updated=True,
            previous_version="0.2.0",
            new_version="0.3.0",
            rule_count=100,
            message="Updated.",
        )
        mock_rec_result = MagicMock(
            updated=True,
            previous_version="0.0.9",
            new_version="0.1.0",
            rule_count=10,
            message="Updated.",
        )

        with (
            patch("reporails_cli.core.init.update_rules", return_value=mock_rules_result),
            patch("reporails_cli.core.init.update_recommended", return_value=mock_rec_result) as mock_rec,
        ):
            result = runner.invoke(app, ["update"])

        assert result.exit_code == 0, result.output
        assert "framework" in result.output.lower()
        assert "recommended" in result.output.lower()
        mock_rec.assert_called_once()

    def test_version_flag_skips_recommended(self) -> None:
        """ails update --version X should only update rules, not recommended."""
        mock_rules_result = MagicMock(
            updated=True,
            previous_version="0.2.0",
            new_version="0.3.0",
            rule_count=100,
            message="Updated.",
        )

        with (
            patch("reporails_cli.core.init.update_rules", return_value=mock_rules_result),
            patch("reporails_cli.core.init.update_recommended") as mock_rec,
        ):
            result = runner.invoke(app, ["update", "--version", "0.3.0"])

        assert result.exit_code == 0, result.output
        mock_rec.assert_not_called()

    def test_already_current_shows_message(self) -> None:
        """When already at latest, should show already-current messages."""
        mock_rules_result = MagicMock(
            updated=False,
            previous_version="0.3.0",
            new_version="0.3.0",
            rule_count=0,
            message="Already at version 0.3.0.",
        )
        mock_rec_result = MagicMock(
            updated=False,
            previous_version="0.1.0",
            new_version="0.1.0",
            rule_count=0,
            message="Recommended already at version 0.1.0.",
        )

        with (
            patch("reporails_cli.core.init.update_rules", return_value=mock_rules_result),
            patch("reporails_cli.core.init.update_recommended", return_value=mock_rec_result),
        ):
            result = runner.invoke(app, ["update"])

        assert result.exit_code == 0, result.output
        assert "Already at version" in result.output


# ---------------------------------------------------------------------------
# ails update --recommended
# ---------------------------------------------------------------------------


class TestUpdateRecommendedCommand:
    def test_recommended_flag_only_updates_recommended(self) -> None:
        """--recommended should only update recommended, not rules."""
        mock_rec_result = MagicMock(
            updated=True,
            previous_version="0.0.9",
            new_version="0.1.0",
            rule_count=10,
            message="Updated.",
        )

        with (
            patch("reporails_cli.core.init.update_recommended", return_value=mock_rec_result),
            patch("reporails_cli.core.init.update_rules") as mock_rules,
        ):
            result = runner.invoke(app, ["update", "--recommended"])

        assert result.exit_code == 0, result.output
        assert "recommended" in result.output.lower()
        mock_rules.assert_not_called()

    def test_recommended_already_current(self) -> None:
        """When recommended is current, should show message."""
        mock_rec_result = MagicMock(
            updated=False,
            previous_version="0.1.0",
            new_version="0.1.0",
            rule_count=0,
            message="Recommended already at version 0.1.0.",
        )

        with patch("reporails_cli.core.init.update_recommended", return_value=mock_rec_result):
            result = runner.invoke(app, ["update", "--recommended"])

        assert result.exit_code == 0, result.output
        assert "already at version" in result.output.lower()

    def test_recommended_force_flag(self) -> None:
        """--recommended --force should pass force=True."""
        mock_rec_result = MagicMock(
            updated=True,
            previous_version="0.1.0",
            new_version="0.1.0",
            rule_count=10,
            message="Updated.",
        )

        with patch("reporails_cli.core.init.update_recommended", return_value=mock_rec_result) as mock_rec:
            result = runner.invoke(app, ["update", "--recommended", "--force"])

        assert result.exit_code == 0, result.output
        mock_rec.assert_called_once_with(force=True)


# ---------------------------------------------------------------------------
# ails update --force (default path)
# ---------------------------------------------------------------------------


class TestUpdateForceCommand:
    def test_force_updates_both(self) -> None:
        """--force without --version should force-update both components."""
        mock_rules_result = MagicMock(
            updated=True,
            previous_version="0.3.0",
            new_version="0.3.0",
            rule_count=200,
            message="Updated.",
        )
        mock_rec_result = MagicMock(
            updated=True,
            previous_version="0.1.0",
            new_version="0.1.0",
            rule_count=10,
            message="Updated.",
        )

        with (
            patch("reporails_cli.core.init.update_rules", return_value=mock_rules_result) as mock_rules,
            patch("reporails_cli.core.init.update_recommended", return_value=mock_rec_result) as mock_rec,
        ):
            result = runner.invoke(app, ["update", "--force"])

        assert result.exit_code == 0, result.output
        mock_rules.assert_called_once_with(version=None, force=True)
        mock_rec.assert_called_once_with(force=True)
