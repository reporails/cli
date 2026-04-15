"""End-to-end CLI tests — exercise ails commands via Typer CliRunner.

Covers the check CLI surface:
  - ails check -f json (JSON output parseable)
  - ails check --strict (exit 1 on violations)
  - ails check -f json (no prompt text in output)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

_has_onnx_model = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "reporails_cli"
    / "bundled"
    / "models"
    / "minilm-l6-v2"
    / "onnx"
    / "model.onnx"
).exists()

requires_model = pytest.mark.skipif(
    not _has_onnx_model, reason="Bundled ONNX model not available"
)


def _rules_installed() -> bool:
    """Check if rules framework is installed."""
    from reporails_cli.core.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(
    not _rules_installed(),
    reason="Rules framework not installed",
)


# ---------------------------------------------------------------------------
# ails check
# (Version command covered by smoke tests)
# ---------------------------------------------------------------------------


class TestCheckCommand:
    def test_json_output_parseable(self, level2_project: Path) -> None:
        """JSON output should be valid JSON with expected keys."""
        result = runner.invoke(
            app,
            [
                "check",
                str(level2_project),
                "-f",
                "json",
            ],
        )
        assert result.exit_code == 0, result.output
        data = json.loads(result.output)
        assert "files" in data and "stats" in data

    # text_output_has_score, compact_output, missing_path, no_instruction_files
    # covered by smoke and behavioral tests

    @requires_rules
    def test_strict_mode_exits_1_on_violations(self, level2_project: Path) -> None:
        """--strict should exit 1 when violations exist."""
        # Use level2 — more rules apply, more likely to have violations
        result = runner.invoke(
            app,
            [
                "check",
                str(level2_project),
                "--strict",
                "-f",
                "json",
            ],
        )
        # --strict exits 1 only when stats.errors > 0
        data = json.loads(result.output)
        errors = data.get("stats", {}).get("errors", 0)
        if errors > 0:
            assert result.exit_code == 1
        else:
            # No errors = exit 0 even with warnings
            assert result.exit_code == 0

    @requires_model
    def test_pre_run_prompt_skipped_in_json_format(self, level2_project: Path) -> None:
        """JSON format should produce clean JSON output with no prompt text."""
        result = runner.invoke(
            app,
            [
                "check",
                str(level2_project),
                "-f",
                "json",
            ],
        )
        assert result.exit_code == 0, result.output
        # Output should be valid JSON (no prompt text mixed in)
        data = json.loads(result.output)
        assert "files" in data and "stats" in data
