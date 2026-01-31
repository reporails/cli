"""Unit tests for package-level rule mappings."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import yaml

from reporails_cli.core.bootstrap import get_package_level_rules
from reporails_cli.core.levels import get_rules_for_level
from reporails_cli.core.applicability import get_applicable_rules
from reporails_cli.core.models import Category, Level, Rule, RuleType


# =============================================================================
# get_package_level_rules tests
# =============================================================================


class TestGetPackageLevelRules:
    """Test loading and merging level→rules from packages."""

    def test_loads_from_package(self, tmp_path: Path) -> None:
        """Reads levels.yml from a single package directory."""
        pkg_dir = tmp_path / ".reporails" / "packages" / "my-rules"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "levels.yml").write_text(yaml.dump({
            "levels": {
                "L2": {"rules": ["CUSTOM-1", "CUSTOM-2"]},
                "L4": {"rules": ["CUSTOM-3"]},
            }
        }))

        result = get_package_level_rules(tmp_path, ["my-rules"])

        assert result == {"L2": ["CUSTOM-1", "CUSTOM-2"], "L4": ["CUSTOM-3"]}

    def test_merges_multiple_packages(self, tmp_path: Path) -> None:
        """Unions rule IDs across multiple packages."""
        for name, levels_data in [
            ("pkg-a", {"levels": {"L2": {"rules": ["A-1"]}}}),
            ("pkg-b", {"levels": {"L2": {"rules": ["B-1"]}, "L3": {"rules": ["B-2"]}}}),
        ]:
            pkg_dir = tmp_path / ".reporails" / "packages" / name
            pkg_dir.mkdir(parents=True)
            (pkg_dir / "levels.yml").write_text(yaml.dump(levels_data))

        result = get_package_level_rules(tmp_path, ["pkg-a", "pkg-b"])

        assert set(result["L2"]) == {"A-1", "B-1"}
        assert result["L3"] == ["B-2"]

    def test_missing_levels_yml(self, tmp_path: Path) -> None:
        """Package dir without levels.yml returns empty."""
        pkg_dir = tmp_path / ".reporails" / "packages" / "no-levels"
        pkg_dir.mkdir(parents=True)

        result = get_package_level_rules(tmp_path, ["no-levels"])

        assert result == {}

    def test_malformed_yaml(self, tmp_path: Path) -> None:
        """Malformed levels.yml is silently skipped."""
        pkg_dir = tmp_path / ".reporails" / "packages" / "bad"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "levels.yml").write_text(": : : [[[invalid")

        result = get_package_level_rules(tmp_path, ["bad"])

        assert result == {}

    def test_empty_packages_list(self, tmp_path: Path) -> None:
        """Empty packages list returns empty dict."""
        result = get_package_level_rules(tmp_path, [])

        assert result == {}

    def test_nonexistent_package_dir(self, tmp_path: Path) -> None:
        """Package name that doesn't exist as a directory returns empty."""
        result = get_package_level_rules(tmp_path, ["ghost"])

        assert result == {}

    def test_levels_yml_without_levels_key(self, tmp_path: Path) -> None:
        """levels.yml without 'levels' key returns empty."""
        pkg_dir = tmp_path / ".reporails" / "packages" / "empty-config"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "levels.yml").write_text(yaml.dump({"other": "data"}))

        result = get_package_level_rules(tmp_path, ["empty-config"])

        assert result == {}


# =============================================================================
# get_rules_for_level with extras tests
# =============================================================================


class TestGetRulesForLevelWithExtras:
    """Test that extra_level_rules are merged correctly."""

    def test_extra_rules_included_at_correct_level(self) -> None:
        """Extra rules at L2 appear when querying L2."""
        extras = {"L2": ["CUSTOM-1", "CUSTOM-2"]}

        result = get_rules_for_level(Level.L2, extra_level_rules=extras)

        assert "CUSTOM-1" in result
        assert "CUSTOM-2" in result

    def test_extra_rules_inherited_at_higher_level(self) -> None:
        """Extra rules at L2 are included when querying L3 (inheritance)."""
        extras = {"L2": ["CUSTOM-1"]}

        result = get_rules_for_level(Level.L3, extra_level_rules=extras)

        assert "CUSTOM-1" in result

    def test_extra_rules_not_at_lower_level(self) -> None:
        """Extra rules at L4 are NOT included when querying L2."""
        extras = {"L4": ["CUSTOM-HIGH"]}

        result = get_rules_for_level(Level.L2, extra_level_rules=extras)

        assert "CUSTOM-HIGH" not in result

    def test_none_extras_is_noop(self) -> None:
        """None extra_level_rules doesn't change behavior."""
        base = get_rules_for_level(Level.L2)
        with_none = get_rules_for_level(Level.L2, extra_level_rules=None)

        assert base == with_none


# =============================================================================
# get_applicable_rules with extras (end-to-end) tests
# =============================================================================


def _make_rule(rule_id: str) -> Rule:
    """Helper to create a minimal Rule."""
    return Rule(
        id=rule_id,
        title=f"Rule {rule_id}",
        category=Category.STRUCTURE,
        type=RuleType.DETERMINISTIC,
        level="L2",
        checks=[],
    )


class TestGetApplicableRulesWithPackages:
    """Test end-to-end: package rule passes applicability filter."""

    def test_package_rule_included(self) -> None:
        """A package rule mapped to L2 passes the filter at L2."""
        rules = {"CUSTOM-1": _make_rule("CUSTOM-1")}
        extras = {"L2": ["CUSTOM-1"]}

        result = get_applicable_rules(rules, Level.L2, extra_level_rules=extras)

        assert "CUSTOM-1" in result

    def test_package_rule_excluded_without_extras(self) -> None:
        """Without extras, a custom rule ID not in levels.yml is filtered out."""
        rules = {"CUSTOM-1": _make_rule("CUSTOM-1")}

        result = get_applicable_rules(rules, Level.L2)

        assert "CUSTOM-1" not in result
