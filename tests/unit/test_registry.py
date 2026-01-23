"""Unit tests for registry module."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from reporails_cli.core.models import Category, Rule, RuleType
from reporails_cli.core.registry import (
    build_rule,
    get_rules_by_category,
    get_rules_by_type,
    parse_frontmatter,
)


class TestParseFrontmatter:
    """Test parse_frontmatter function."""

    def test_parses_valid_frontmatter(self) -> None:
        """Parses valid YAML frontmatter."""
        content = dedent("""\
            ---
            id: S1
            title: Size Limits
            category: structure
            ---

            # Content here
        """)
        result = parse_frontmatter(content)
        assert result["id"] == "S1"
        assert result["title"] == "Size Limits"
        assert result["category"] == "structure"

    def test_raises_on_missing_frontmatter(self) -> None:
        """Raises ValueError when frontmatter missing."""
        content = "# No frontmatter here"
        with pytest.raises(ValueError, match="No frontmatter found"):
            parse_frontmatter(content)

    def test_raises_on_invalid_yaml(self) -> None:
        """Raises ValueError on invalid YAML."""
        content = dedent("""\
            ---
            invalid: yaml: content:
            ---
        """)
        with pytest.raises(ValueError, match="Invalid YAML"):
            parse_frontmatter(content)

    def test_handles_empty_frontmatter(self) -> None:
        """Returns empty dict for empty frontmatter."""
        content = dedent("""\
            ---
            ---
            # Content
        """)
        result = parse_frontmatter(content)
        assert result == {}


class TestBuildRule:
    """Test build_rule function."""

    def test_builds_minimal_rule(self) -> None:
        """Builds rule with required fields only."""
        frontmatter = {
            "id": "S1",
            "title": "Size Limits",
            "category": "structure",
            "type": "deterministic",
            "level": "L2+",
            "scoring": 10,
        }
        rule = build_rule(frontmatter, Path("/rules/S1.md"), None)

        assert rule.id == "S1"
        assert rule.title == "Size Limits"
        assert rule.category == Category.STRUCTURE
        assert rule.type == RuleType.DETERMINISTIC
        assert rule.level == "L2+"
        assert rule.scoring == 10
        assert rule.antipatterns == []
        assert rule.md_path == Path("/rules/S1.md")

    def test_builds_rule_with_antipatterns(self) -> None:
        """Builds rule with antipatterns."""
        frontmatter = {
            "id": "S1",
            "title": "Size Limits",
            "category": "structure",
            "type": "deterministic",
            "level": "L2+",
            "scoring": 10,
            "antipatterns": [
                {"id": "A1", "name": "Too large", "severity": "critical", "points": -25}
            ],
        }
        rule = build_rule(frontmatter, Path("/rules/S1.md"), None)

        assert len(rule.antipatterns) == 1
        assert rule.antipatterns[0].id == "A1"
        assert rule.antipatterns[0].points == -25

    def test_builds_rule_with_yml_path(self) -> None:
        """Associates yml path with rule."""
        frontmatter = {
            "id": "S1",
            "title": "Size Limits",
            "category": "structure",
            "type": "deterministic",
            "level": "L2+",
            "scoring": 10,
        }
        yml_path = Path("/rules/S1.yml")
        rule = build_rule(frontmatter, Path("/rules/S1.md"), yml_path)

        assert rule.yml_path == yml_path

    def test_raises_on_missing_required_field(self) -> None:
        """Raises KeyError when required field missing."""
        frontmatter = {
            "id": "S1",
            # Missing 'title', 'category', etc.
        }
        with pytest.raises(KeyError):
            build_rule(frontmatter, Path("/rules/S1.md"), None)


class TestGetRulesByType:
    """Test get_rules_by_type function."""

    def test_filters_by_type(self) -> None:
        """Returns only rules of specified type."""
        rules = {
            "S1": Rule(
                id="S1",
                title="Rule 1",
                category=Category.STRUCTURE,
                type=RuleType.DETERMINISTIC,
                level="L2+",
                scoring=10,
            ),
            "C1": Rule(
                id="C1",
                title="Rule 2",
                category=Category.CONTENT,
                type=RuleType.HEURISTIC,
                level="L2+",
                scoring=10,
            ),
            "C2": Rule(
                id="C2",
                title="Rule 3",
                category=Category.CONTENT,
                type=RuleType.SEMANTIC,
                level="L3+",
                scoring=15,
            ),
        }

        deterministic = get_rules_by_type(rules, RuleType.DETERMINISTIC)
        assert len(deterministic) == 1
        assert "S1" in deterministic

        heuristic = get_rules_by_type(rules, RuleType.HEURISTIC)
        assert len(heuristic) == 1
        assert "C1" in heuristic

        semantic = get_rules_by_type(rules, RuleType.SEMANTIC)
        assert len(semantic) == 1
        assert "C2" in semantic

    def test_returns_empty_dict_when_no_matches(self) -> None:
        """Returns empty dict when no rules match."""
        rules = {
            "S1": Rule(
                id="S1",
                title="Rule 1",
                category=Category.STRUCTURE,
                type=RuleType.DETERMINISTIC,
                level="L2+",
                scoring=10,
            ),
        }
        result = get_rules_by_type(rules, RuleType.SEMANTIC)
        assert result == {}


class TestGetRulesByCategory:
    """Test get_rules_by_category function."""

    def test_filters_by_category(self) -> None:
        """Returns only rules of specified category."""
        rules = {
            "S1": Rule(
                id="S1",
                title="Rule 1",
                category=Category.STRUCTURE,
                type=RuleType.DETERMINISTIC,
                level="L2+",
                scoring=10,
            ),
            "C1": Rule(
                id="C1",
                title="Rule 2",
                category=Category.CONTENT,
                type=RuleType.HEURISTIC,
                level="L2+",
                scoring=10,
            ),
        }

        structure = get_rules_by_category(rules, Category.STRUCTURE)
        assert len(structure) == 1
        assert "S1" in structure

        content = get_rules_by_category(rules, Category.CONTENT)
        assert len(content) == 1
        assert "C1" in content

    def test_returns_empty_dict_when_no_matches(self) -> None:
        """Returns empty dict when no rules match."""
        rules = {
            "S1": Rule(
                id="S1",
                title="Rule 1",
                category=Category.STRUCTURE,
                type=RuleType.DETERMINISTIC,
                level="L2+",
                scoring=10,
            ),
        }
        result = get_rules_by_category(rules, Category.GOVERNANCE)
        assert result == {}
