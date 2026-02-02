"""Unit tests for rule registry: build_rule and backed_by parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.models import BackedByEntry, Category, PatternConfidence, RuleType
from reporails_cli.core.registry import build_rule

MINIMAL_FRONTMATTER = {
    "id": "T1",
    "title": "Test Rule",
    "category": "structure",
    "type": "deterministic",
    "level": "L2",
}


class TestBuildRuleBackedBy:
    """Test backed_by parsing in build_rule."""

    def test_backed_by_parsed(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "backed_by": [
                {"source": "anthropic-docs", "claim": "file-structure"},
                {"source": "community-practice", "claim": "naming-convention"},
            ],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert len(rule.backed_by) == 2
        assert rule.backed_by[0] == BackedByEntry(source="anthropic-docs", claim="file-structure")
        assert rule.backed_by[1] == BackedByEntry(source="community-practice", claim="naming-convention")

    def test_backed_by_empty_when_absent(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.backed_by == []

    def test_backed_by_skips_malformed_entries(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "backed_by": [
                {"source": "valid", "claim": "ok"},
                {"source": "missing-claim"},  # no claim key
                "not-a-dict",
                {"claim": "missing-source"},  # no source key
            ],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert len(rule.backed_by) == 1
        assert rule.backed_by[0].source == "valid"


class TestBuildRuleSources:
    """Test that sources accepts string lists (schema v4)."""

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
        assert rule.id == "T1"
        assert rule.title == "Test Rule"
        assert rule.category == Category.STRUCTURE
        assert rule.type == RuleType.DETERMINISTIC
        assert rule.level == "L2"

    def test_checks_parsed(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "checks": [
                {"id": "T1-check1", "name": "First check", "severity": "high"},
                {"id": "T1-check2", "name": "Second check", "severity": "low"},
            ],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert len(rule.checks) == 2
        assert rule.checks[0].id == "T1-check1"
        assert rule.checks[0].severity.value == "high"


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
