"""Unit tests for rule registry: build_rule and backed_by parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.models import Category, PatternConfidence, RuleType
from reporails_cli.core.registry import build_rule

MINIMAL_FRONTMATTER = {
    "id": "CORE:S:0001",
    "title": "Test Rule",
    "category": "structure",
    "type": "deterministic",
    "level": "L2",
    "slug": "test-rule",
    "targets": "{{instruction_files}}",
}


class TestBuildRuleBackedBy:
    """Test backed_by parsing in build_rule (now plain string list)."""

    def test_backed_by_parsed(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "backed_by": ["anthropic-docs", "community-practice"],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert len(rule.backed_by) == 2
        assert rule.backed_by[0] == "anthropic-docs"
        assert rule.backed_by[1] == "community-practice"

    def test_backed_by_empty_when_absent(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.backed_by == []

    def test_backed_by_skips_non_string_entries(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "backed_by": [
                "valid-source",
                {"source": "dict-entry"},  # not a string — skipped
                42,  # not a string — skipped
            ],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert len(rule.backed_by) == 1
        assert rule.backed_by[0] == "valid-source"


class TestBuildRuleSources:
    """Test that sources accepts string lists."""

    def test_sources_as_strings(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "sources": ["https://example.com/doc1", "https://example.com/doc2"],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.sources == ["https://example.com/doc1", "https://example.com/doc2"]

    def test_sources_default_empty(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.sources == []


class TestBuildRuleBasic:
    """Test basic build_rule construction."""

    def test_minimal_rule(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.id == "CORE:S:0001"
        assert rule.title == "Test Rule"
        assert rule.category == Category.STRUCTURE
        assert rule.type == RuleType.DETERMINISTIC
        assert rule.level == "L2"
        assert rule.slug == "test-rule"
        assert rule.targets == "{{instruction_files}}"

    def test_checks_parsed_new_format(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "checks": [
                {"id": "CORE:S:0001:check:0001", "type": "mechanical", "check": "file_exists", "severity": "critical"},
                {"id": "CORE:S:0001:check:0002", "type": "deterministic", "severity": "high"},
            ],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert len(rule.checks) == 2
        assert rule.checks[0].id == "CORE:S:0001:check:0001"
        assert rule.checks[0].type == "mechanical"
        assert rule.checks[0].check == "file_exists"
        assert rule.checks[0].severity.value == "critical"
        assert rule.checks[1].type == "deterministic"
        assert rule.checks[1].check is None

    def test_mechanical_check_with_args(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "type": "mechanical",
            "checks": [
                {
                    "id": "CORE:S:0005:check:0001",
                    "type": "mechanical",
                    "check": "line_count",
                    "args": {"max": 300},
                    "severity": "high",
                },
            ],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.checks[0].args == {"max": 300}

    def test_supersedes_parsed(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "supersedes": "CORE:S:0003",
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.supersedes == "CORE:S:0003"


class TestBuildRulePatternConfidence:
    """Test pattern_confidence parsing in build_rule."""

    @pytest.mark.parametrize("level", ["very_high", "high", "medium", "low", "very_low"])
    def test_confidence_level_parsed(self, level: str) -> None:
        fm = {**MINIMAL_FRONTMATTER, "pattern_confidence": level}
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.pattern_confidence == PatternConfidence(level)

    def test_none_when_absent(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.pattern_confidence is None

    def test_invalid_value_raises(self) -> None:
        fm = {**MINIMAL_FRONTMATTER, "pattern_confidence": "bogus"}
        with pytest.raises(ValueError):
            build_rule(fm, Path("test.md"), None)


class TestInferAgentFromRuleId:
    """Test infer_agent_from_rule_id prefix logic."""

    @pytest.mark.parametrize(
        ("rule_id", "expected"),
        [
            ("CORE:S:0001", ""),
            ("RRAILS:C:0003", ""),
            ("CLAUDE:S:0001", "claude"),
            ("CODEX:S:0001", "codex"),
            ("COPILOT:S:0001", "copilot"),
            ("no-colon", ""),
        ],
    )
    def test_infer(self, rule_id: str, expected: str) -> None:
        from reporails_cli.core.registry import infer_agent_from_rule_id

        assert infer_agent_from_rule_id(rule_id) == expected
