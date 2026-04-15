"""Applicability unit tests - feature detection and rule filtering.

Tests the filesystem feature detection pipeline and target-existence
rule applicability logic including supersession.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.models import Category, FileMatch, Rule, RuleType


def _make_rule(
    rule_id: str = "S1",
    supersedes: str | None = None,
    **kw: object,
) -> Rule:
    """Create a minimal Rule for testing."""
    defaults: dict[str, object] = {
        "id": rule_id,
        "title": "Test",
        "category": Category.STRUCTURE,
        "type": RuleType.DETERMINISTIC,
        "checks": [],
        "match": FileMatch(type="main"),
        "slug": "test",
        "see_also": [],
        "supersedes": supersedes,
        "md_path": None,
        "yml_path": None,
    }
    defaults.update(kw)
    return Rule(**defaults)  # type: ignore[arg-type]


class TestDetectFeaturesFilesystem:
    """Test detect_features_filesystem with real temp directories."""

    def test_empty_directory_no_features(self, tmp_path: Path) -> None:
        """Empty directory should detect no features."""
        from reporails_cli.core.applicability import detect_features_filesystem

        features = detect_features_filesystem(tmp_path)

        assert features.has_claude_md is False
        assert features.has_instruction_file is False
        assert features.instruction_file_count == 0
        assert features.is_abstracted is False
        assert features.has_backbone is False
        assert features.has_multiple_instruction_files is False

    def test_claude_md_only(self, tmp_path: Path) -> None:
        """CLAUDE.md at root should be detected."""
        from reporails_cli.core.applicability import detect_features_filesystem

        (tmp_path / "CLAUDE.md").write_text("# My Project\n", encoding="utf-8")

        features = detect_features_filesystem(tmp_path)

        assert features.has_claude_md is True
        assert features.has_instruction_file is True
        assert features.instruction_file_count == 1

    def test_claude_rules_dir_is_abstracted(self, tmp_path: Path) -> None:
        """Presence of .claude/rules/ with content should set is_abstracted."""
        from reporails_cli.core.applicability import detect_features_filesystem

        rules_dir = tmp_path / ".claude" / "rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "style.md").write_text("# Style\n", encoding="utf-8")
        # Also create CLAUDE.md so the project has an instruction file
        (tmp_path / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")

        features = detect_features_filesystem(tmp_path)

        assert features.is_abstracted is True


class TestGetApplicableRules:
    """Test target-existence rule filtering and supersession."""

    def test_rule_included_when_target_present(self) -> None:
        """A rule targeting 'main' is included when 'main' is present."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {"S1": _make_rule(rule_id="S1", match=FileMatch(type="main"))}

        result = get_applicable_rules(rules, {"main"})

        assert "S1" in result

    def test_rule_excluded_when_target_absent(self) -> None:
        """A rule targeting 'main' is excluded when 'main' is not present."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {"S1": _make_rule(rule_id="S1", match=FileMatch(type="main"))}

        result = get_applicable_rules(rules, {"scoped_rule"})

        assert "S1" not in result

    def test_wildcard_match_none_fires_when_any_present(self) -> None:
        """Rules with match=None fire if any type is present."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {"S1": _make_rule(rule_id="S1", match=None)}

        result = get_applicable_rules(rules, {"main"})

        assert "S1" in result

    def test_wildcard_type_none_fires_when_any_present(self) -> None:
        """Rules with match.type=None fire if any type is present."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {"S1": _make_rule(rule_id="S1", match=FileMatch(type=None))}

        result = get_applicable_rules(rules, {"scoped_rule"})

        assert "S1" in result

    def test_no_present_types_returns_empty(self) -> None:
        """No present types → no rules fire."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {"S1": _make_rule(rule_id="S1")}

        result = get_applicable_rules(rules, set())

        assert result == {}

    def test_supersession_drops_superseded_rule(self) -> None:
        """When rule A supersedes rule B and both are applicable, B is dropped."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "S1": _make_rule(rule_id="S1"),
            "S2": _make_rule(rule_id="S2", supersedes="S1"),
        }

        result = get_applicable_rules(rules, {"main"})

        assert "S2" in result
        assert "S1" not in result, "Superseded rule S1 should be dropped"

    def test_supersession_keeps_both_when_superseder_target_absent(self) -> None:
        """When superseding rule targets absent type, both remain (only applicable supersede)."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "S1": _make_rule(rule_id="S1", match=FileMatch(type="main")),
            "S2": _make_rule(rule_id="S2", match=FileMatch(type="config"), supersedes="S1"),
        }

        # Only "main" present, S2 targets "config" which is absent → S2 excluded
        result = get_applicable_rules(rules, {"main"})

        assert "S1" in result
        assert "S2" not in result

    def test_multiple_types_filter_correctly(self) -> None:
        """Rules targeting different types are filtered by presence."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "R1": _make_rule(rule_id="R1", match=FileMatch(type="main")),
            "R2": _make_rule(rule_id="R2", match=FileMatch(type="scoped_rule")),
            "R3": _make_rule(rule_id="R3", match=FileMatch(type="skill")),
        }

        result = get_applicable_rules(rules, {"main", "scoped_rule"})

        assert "R1" in result
        assert "R2" in result
        assert "R3" not in result

    def test_empty_rules_returns_empty(self) -> None:
        """Empty rules dict returns empty result."""
        from reporails_cli.core.applicability import get_applicable_rules

        result = get_applicable_rules({}, {"main"})

        assert result == {}

    def test_supersedes_nonexistent_rule_ignored(self) -> None:
        """A rule that supersedes a rule ID not in the dict should not crash."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "S1": _make_rule(rule_id="S1", supersedes="DOES_NOT_EXIST"),
        }

        result = get_applicable_rules(rules, {"main"})

        assert "S1" in result

    def test_multiple_target_types_fire_when_present(self) -> None:
        """Rules targeting different types all fire when their types are present."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "R1": _make_rule(rule_id="R1", match=FileMatch(type="main")),
            "R2": _make_rule(rule_id="R2", match=FileMatch(type="scoped_rule")),
            "R3": _make_rule(rule_id="R3", match=FileMatch(type="skill")),
        }

        result = get_applicable_rules(rules, {"main", "scoped_rule", "skill"})

        assert "R1" in result
        assert "R2" in result
        assert "R3" in result
