"""Unit tests for action/summary.py — GitHub Actions step summary generator."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import patch

# Load summary.py as a module since action/ is not a package
_summary_path = Path(__file__).resolve().parents[2] / "action" / "summary.py"
_spec = importlib.util.spec_from_file_location("summary", _summary_path)
assert _spec and _spec.loader
summary = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(summary)

generate_summary = summary.generate_summary
main = summary.main


# ---------------------------------------------------------------------------
# generate_summary — score table
# ---------------------------------------------------------------------------


class TestScoreTable:
    """Score/level/status header table."""

    def test_score_display(self):
        md = generate_summary({"score": 7.5, "level": "L3"})
        assert "**7.5/10**" in md

    def test_level_and_capability(self):
        md = generate_summary({"score": 9, "level": "L5", "capability": "Autonomous"})
        assert "**L5** Autonomous" in md

    def test_positive_delta(self):
        md = generate_summary({"score": 8, "level": "L4", "score_delta": 1.5})
        assert "(+1.5)" in md

    def test_negative_delta(self):
        md = generate_summary({"score": 5, "level": "L2", "score_delta": -2.0})
        assert "(-2.0)" in md

    def test_zero_delta_omitted(self):
        md = generate_summary({"score": 6, "level": "L3", "score_delta": 0})
        assert "(+" not in md and "(-" not in md

    def test_null_delta_omitted(self):
        md = generate_summary({"score": 6, "level": "L3", "score_delta": None})
        assert "(+" not in md and "(-" not in md


# ---------------------------------------------------------------------------
# generate_summary — status line
# ---------------------------------------------------------------------------


class TestStatus:
    """Status line derivation from violations."""

    def test_no_violations_pass(self):
        md = generate_summary({"score": 10, "level": "L6", "violations": []})
        assert "Pass" in md

    def test_critical_fail(self):
        md = generate_summary(
            {
                "score": 2,
                "level": "L1",
                "violations": [{"severity": "critical", "rule_id": "X", "location": "f", "message": "m"}],
            }
        )
        assert "Fail" in md

    def test_high_fail(self):
        md = generate_summary(
            {
                "score": 3,
                "level": "L2",
                "violations": [{"severity": "high", "rule_id": "X", "location": "f", "message": "m"}],
            }
        )
        assert "Fail" in md

    def test_medium_warnings(self):
        md = generate_summary(
            {
                "score": 6,
                "level": "L3",
                "violations": [{"severity": "medium", "rule_id": "X", "location": "f", "message": "m"}],
            }
        )
        assert "Warnings" in md

    def test_low_warnings(self):
        md = generate_summary(
            {
                "score": 7,
                "level": "L3",
                "violations": [{"severity": "low", "rule_id": "X", "location": "f", "message": "m"}],
            }
        )
        assert "Warnings" in md


# ---------------------------------------------------------------------------
# generate_summary — category summary
# ---------------------------------------------------------------------------


class TestCategorySummary:
    """Category summary table rendering."""

    def test_table_rendered(self):
        md = generate_summary(
            {
                "score": 7,
                "level": "L3",
                "category_summary": [{"name": "structure", "passed": 3, "failed": 1, "worst_severity": "medium"}],
            }
        )
        assert "### Categories" in md
        assert "Structure" in md
        assert "| 3 | 1 |" in md

    def test_empty_skipped(self):
        md = generate_summary({"score": 10, "level": "L6", "category_summary": []})
        assert "### Categories" not in md

    def test_severity_icon_shown(self):
        md = generate_summary(
            {
                "score": 5,
                "level": "L2",
                "category_summary": [{"name": "content", "passed": 0, "failed": 2, "worst_severity": "critical"}],
            }
        )
        # critical icon
        assert "\u274c" in md

    def test_passing_checkmark(self):
        md = generate_summary(
            {
                "score": 9,
                "level": "L5",
                "category_summary": [{"name": "content", "passed": 5, "failed": 0, "worst_severity": "-"}],
            }
        )
        assert "\u2705" in md


# ---------------------------------------------------------------------------
# generate_summary — violations table
# ---------------------------------------------------------------------------


class TestViolationsTable:
    """Violations detail table rendering."""

    def test_row_rendered(self):
        md = generate_summary(
            {
                "score": 5,
                "level": "L2",
                "violations": [
                    {
                        "severity": "high",
                        "rule_id": "CORE:S:0001",
                        "location": "CLAUDE.md",
                        "message": "Missing section",
                    }
                ],
            }
        )
        assert "### Violations" in md
        assert "`CORE:S:0001`" in md
        assert "`CLAUDE.md`" in md
        assert "Missing section" in md

    def test_long_message_truncated(self):
        long_msg = "A" * 100
        md = generate_summary(
            {
                "score": 3,
                "level": "L1",
                "violations": [{"severity": "low", "rule_id": "X", "location": "f", "message": long_msg}],
            }
        )
        assert "AAA..." in md
        # Truncated to 77 + "..."
        assert "A" * 78 not in md

    def test_empty_violations_skipped(self):
        md = generate_summary({"score": 10, "level": "L6", "violations": []})
        assert "### Violations" not in md

    def test_severity_icons(self):
        violations = [
            {"severity": sev, "rule_id": "X", "location": "f", "message": "m"}
            for sev in ("critical", "high", "medium", "low")
        ]
        md = generate_summary({"score": 1, "level": "L1", "violations": violations})
        assert "\u274c" in md  # critical
        assert "\U0001f7e0" in md  # high/orange
        assert "\u26a0\ufe0f" in md  # medium/warning
        assert "\U0001f535" in md  # low/blue


# ---------------------------------------------------------------------------
# main() — CLI entry point
# ---------------------------------------------------------------------------


class TestMain:
    """main() argument handling."""

    def test_no_args(self, capsys):
        with patch.object(sys, "argv", ["summary.py"]):
            main()
        out = capsys.readouterr().out
        assert "No results available" in out

    def test_empty_arg(self, capsys):
        with patch.object(sys, "argv", ["summary.py", "  "]):
            main()
        out = capsys.readouterr().out
        assert "No results available" in out

    def test_invalid_json(self, capsys):
        with patch.object(sys, "argv", ["summary.py", "not-json"]):
            main()
        out = capsys.readouterr().out
        assert "Failed to parse" in out

    def test_valid_json(self, capsys):
        import json

        payload = json.dumps({"score": 8.0, "level": "L4", "violations": []})
        with patch.object(sys, "argv", ["summary.py", payload]):
            main()
        out = capsys.readouterr().out
        assert "8.0/10" in out
        assert "Pass" in out
