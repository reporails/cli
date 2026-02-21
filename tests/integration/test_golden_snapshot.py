"""Golden snapshot tests — assert full pipeline output stability.

Runs `run_validation` + `format_result` against committed fixture projects
and compares structurally against expected.json golden files.

Regenerate golden files after intentional changes:
    uv run pytest tests/integration/test_golden_snapshot.py --update-golden -v
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.engine import run_validation
from reporails_cli.formatters.json import format_result


def _rules_installed() -> bool:
    from reporails_cli.core.bootstrap import get_rules_path

    return (get_rules_path() / "core").exists()


requires_rules = pytest.mark.skipif(
    not _rules_installed(),
    reason="Rules framework not installed",
)

GOLDEN_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "golden"

# Fields matched exactly — these are deterministic for static input
EXACT_FIELDS = {"score", "level", "friction", "summary", "category_summary"}

# Fields stripped entirely — non-deterministic or delta-dependent
STRIP_FIELDS = {
    "score_delta",
    "level_previous",
    "level_improved",
    "violations_delta",
}

# Per-violation fields that drift with rule text edits
VIOLATION_SKIP_FIELDS = {"message", "rule_title"}

# Per-judgment-request fields that drift with rule text edits
JUDGMENT_SKIP_FIELDS = {"content", "question", "rule_title"}

# Top-level fields with human-readable labels that may change
LABEL_SKIP_FIELDS = {"feature_summary", "capability"}


# ---------------------------------------------------------------------------
# Fixture scenarios
# ---------------------------------------------------------------------------

SCENARIOS = [
    pytest.param("l2_claude", "claude", id="l2-claude"),
    pytest.param("l2_generic", "", id="l2-generic"),
    pytest.param("l5_claude", "claude", id="l5-claude"),
]


# ---------------------------------------------------------------------------
# Structured comparison
# ---------------------------------------------------------------------------


def _strip_violation(v: dict[str, Any]) -> dict[str, Any]:
    """Keep only stable violation fields."""
    return {k: val for k, val in v.items() if k not in VIOLATION_SKIP_FIELDS}


def _strip_judgment(j: dict[str, Any]) -> dict[str, Any]:
    """Keep only stable judgment request fields."""
    return {k: val for k, val in j.items() if k not in JUDGMENT_SKIP_FIELDS}


def _stable_output(data: dict[str, Any]) -> dict[str, Any]:
    """Extract the structurally stable subset of a format_result dict."""
    stable: dict[str, Any] = {}

    # Exact-match scalar/dict fields
    for field in EXACT_FIELDS:
        if field in data:
            stable[field] = data[field]

    # Evaluation completeness
    stable["evaluation"] = data.get("evaluation")
    stable["is_partial"] = data.get("is_partial")

    # Violations: strip drifty text, sort for determinism
    violations = [_strip_violation(v) for v in data.get("violations", [])]
    stable["violations"] = sorted(
        violations, key=lambda v: (v["rule_id"], v.get("location", ""), v.get("check_id", ""))
    )

    # Judgment requests: strip drifty text, sort for determinism
    judgments = [_strip_judgment(j) for j in data.get("judgment_requests", [])]
    stable["judgment_requests"] = sorted(judgments, key=lambda j: (j["rule_id"], j.get("location", "")))

    # Optional sections — include when present in either actual or expected
    if "pending_semantic" in data and data["pending_semantic"] is not None:
        ps = data["pending_semantic"]
        stable["pending_semantic"] = {
            "rule_count": ps["rule_count"],
            "file_count": ps["file_count"],
            "rules": sorted(ps["rules"]),
        }

    if "skipped_experimental" in data and data["skipped_experimental"] is not None:
        se = data["skipped_experimental"]
        stable["skipped_experimental"] = {
            "rule_count": se["rule_count"],
            "rules": sorted(se["rules"]),
        }

    return stable


def _diff_golden(actual: dict[str, Any], expected: dict[str, Any]) -> list[str]:
    """Compare two stable dicts, returning human-readable diffs."""
    diffs: list[str] = []

    all_keys = sorted(set(actual) | set(expected))
    for key in all_keys:
        if key not in actual:
            diffs.append(f"Missing in actual: {key}")
            continue
        if key not in expected:
            diffs.append(f"Extra in actual: {key}")
            continue
        if actual[key] != expected[key]:
            a = json.dumps(actual[key], indent=2, default=str)
            e = json.dumps(expected[key], indent=2, default=str)
            diffs.append(f"Mismatch in '{key}':\n  actual:   {a}\n  expected: {e}")

    return diffs


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@requires_rules
class TestGoldenSnapshots:
    """Run full pipeline against committed fixtures, compare golden output."""

    @pytest.mark.parametrize("fixture_name,agent", SCENARIOS)
    def test_golden_output(
        self,
        fixture_name: str,
        agent: str,
        update_golden: bool,
    ) -> None:
        fixture_dir = GOLDEN_DIR / fixture_name
        expected_path = fixture_dir / "expected.json"

        # Run full pipeline
        result = run_validation(
            fixture_dir,
            agent=agent,
            use_cache=False,
            record_analytics=False,
        )
        raw_output = format_result(result, delta=None)
        actual_stable = _stable_output(raw_output)

        if update_golden:
            expected_path.write_text(json.dumps(actual_stable, indent=2, sort_keys=True) + "\n")
            pytest.skip(f"Updated golden file: {expected_path}")
            return

        if not expected_path.exists():
            pytest.fail(f"Golden file missing: {expected_path}\nRun with --update-golden to generate it.")

        expected = json.loads(expected_path.read_text())
        diffs = _diff_golden(actual_stable, expected)

        if diffs:
            pytest.fail(
                f"Golden snapshot mismatch for {fixture_name}:\n"
                + "\n".join(diffs)
                + "\n\nRun with --update-golden to accept changes."
            )
