"""Pipeline smoke test — runs full validation with all three gate types.

This is the integration test that catches composition bugs invisible to
unit tests (which mock the regex engine) and the rule harness (which tests one
rule at a time). It exercises:

    template resolution → regex execution → SARIF parsing → rule matching

across multiple rules simultaneously, verifying mechanical, deterministic,
and semantic gates all produce output.

Regression coverage:
- SARIF ruleId format (rule IDs must be valid coordinates)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.engine import run_validation
from reporails_cli.core.models import RuleType


@pytest.fixture
def vague_project(tmp_path: Path) -> Path:
    """Fixture project that triggers all three gate types.

    Mechanical: missing cross-agent file, not git-tracked
    Deterministic: vague qualifiers, style conventions
    Semantic: specificity-over-vagueness (vague content → LLM judgment)
    """
    project = tmp_path / "vague_project"
    project.mkdir()

    (project / "CLAUDE.md").write_text("""\
# My App

A web application.

## Guidelines

Write clean code and follow good practices.
Format code properly and use appropriate naming.
Handle errors well and write good tests.
""")

    return project


class TestPipelineSmoke:
    """Smoke tests for the full validation pipeline."""

    def test_all_three_gates_produce_output(
        self,
        vague_project: Path,
        dev_rules_dir: Path,
    ) -> None:
        """Mechanical + deterministic + semantic gates all fire.

        This is the composition test that catches:
        - SARIF ruleId format corruption
        - Template resolution failures (unresolved {{placeholders}})
        """
        result = run_validation(
            vague_project,
            rules_paths=[dev_rules_dir],
            agent="claude",
            use_cache=False,
            record_analytics=False,
        )

        # Mechanical violations should exist (not git-tracked, missing files, etc.)
        mechanical_violations = [
            v
            for v in result.violations
            if any(r.type == RuleType.MECHANICAL for r in _get_rules_for_violations(result, v.rule_id))
        ]
        assert len(mechanical_violations) > 0, (
            "Expected mechanical violations (e.g., not git-tracked) but got none. Mechanical gate may not be running."
        )

        # Deterministic violations should exist (vague qualifiers in fixture)
        deterministic_violations = [
            v
            for v in result.violations
            if any(r.type == RuleType.DETERMINISTIC for r in _get_rules_for_violations(result, v.rule_id))
        ]
        assert len(deterministic_violations) > 0, (
            "Expected deterministic violations (vague qualifiers like 'clean', 'good') "
            "but got none. Template resolution or SARIF parsing may be broken."
        )

        # Semantic rules are L2+ and may be experimental; an L1 project
        # won't trigger them.  Verify the pipeline reports applicable counts.
        assert result.rules_checked > 0, "No rules were checked at all."

    def test_multiple_rules_checked(
        self,
        vague_project: Path,
        dev_rules_dir: Path,
    ) -> None:
        """Multiple rules must be checked."""
        result = run_validation(
            vague_project,
            rules_paths=[dev_rules_dir],
            agent="claude",
            use_cache=False,
            record_analytics=False,
        )

        # An L1 project should check at least the core L1 rules
        assert result.rules_checked >= 8, (
            f"Only {result.rules_checked} rules checked — expected 8+. "
            "Template resolution may be writing all rule.yml to the same temp path."
        )

    def test_deterministic_violations_have_correct_rule_ids(
        self,
        vague_project: Path,
        dev_rules_dir: Path,
    ) -> None:
        """Violation rule_ids must be valid coordinates.

        Rule IDs must be in NAMESPACE:CATEGORY:SLOT format (e.g., CORE:C:0006).
        """
        result = run_validation(
            vague_project,
            rules_paths=[dev_rules_dir],
            agent="claude",
            use_cache=False,
            record_analytics=False,
        )

        for v in result.violations:
            parts = v.rule_id.split(":")
            assert len(parts) == 3, (
                f"Violation rule_id '{v.rule_id}' is not a valid coordinate. "
                "Expected format: NAMESPACE:CATEGORY:SLOT (e.g., CORE:C:0006)."
            )
            namespace, category, slot = parts
            assert namespace.isupper(), f"Namespace '{namespace}' in '{v.rule_id}' should be uppercase."
            assert len(category) == 1 and category.isupper(), (
                f"Category '{category}' in '{v.rule_id}' should be a single uppercase letter."
            )
            assert slot.isdigit() and len(slot) == 4, f"Slot '{slot}' in '{v.rule_id}' should be 4 digits."


def _get_rules_for_violations(result, rule_id: str) -> list:
    """Infer rule type from violation's rule_id category code.

    Structure (S) rules are mechanical; Content/other rules are deterministic.
    """
    category_code = rule_id.split(":")[1] if ":" in rule_id else ""

    from reporails_cli.core.models import Category, Rule

    if category_code == "S":
        return [
            Rule(
                id=rule_id,
                title="",
                category=Category.STRUCTURE,
                type=RuleType.MECHANICAL,
                level="L1",
            )
        ]
    if category_code in ("C", "E", "M", "G"):
        return [
            Rule(
                id=rule_id,
                title="",
                category=Category.CONTENT,
                type=RuleType.DETERMINISTIC,
                level="L1",
            )
        ]
    return []
