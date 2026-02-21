"""Applicability unit tests - feature detection and rule filtering.

Tests the filesystem feature detection pipeline and level-based rule
applicability logic including supersession.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.models import Category, Level, Rule, RuleType


def _make_rule(
    rule_id: str = "S1",
    level: str = "L2",
    supersedes: str | None = None,
    **kw: object,
) -> Rule:
    """Create a minimal Rule for testing."""
    defaults: dict[str, object] = {
        "id": rule_id,
        "title": "Test",
        "category": Category.STRUCTURE,
        "type": RuleType.DETERMINISTIC,
        "level": level,
        "checks": [],
        "question": None,
        "criteria": None,
        "choices": None,
        "examples": None,
        "pass_value": None,
        "targets": "CLAUDE.md",
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


class TestCountComponents:
    """Test _count_components with v1 and v2 backbone formats."""

    def test_v1_backbone_with_components(self) -> None:
        """v1 backbone counts entries in components dict."""
        from reporails_cli.core.applicability import _count_components

        backbone = {
            "version": 1,
            "components": {
                "api": {"path": "src/api"},
                "web": {"path": "src/web"},
                "workers": {"path": "src/workers"},
            },
        }

        assert _count_components(backbone) == 3

    def test_v2_backbone_extracts_top_level_dirs(self) -> None:
        """v2 backbone collects distinct top-level directories from path values."""
        from reporails_cli.core.applicability import _count_components

        backbone = {
            "version": 2,
            "structure": {
                "source": "src/main",
                "tests": "tests/unit",
                "docs": "docs/specs/arch.md",
            },
        }

        count = _count_components(backbone)

        # Should find: src, tests, docs
        assert count == 3

    def test_v1_backbone_empty_components(self) -> None:
        """v1 backbone with no components should return 0."""
        from reporails_cli.core.applicability import _count_components

        backbone = {"version": 1, "components": {}}

        assert _count_components(backbone) == 0

    def test_v2_backbone_skips_urls(self) -> None:
        """v2 backbone should skip URL-like values (containing ':' or '@')."""
        from reporails_cli.core.applicability import _count_components

        backbone = {
            "version": 2,
            "source": "src/main",
            "repo_url": "https://github.com/org/repo",
            "contact": "user@example.com",
        }

        count = _count_components(backbone)

        # Only src/main produces a top-level dir; URLs and emails are skipped
        assert count == 1


class TestGetApplicableRules:
    """Test level-based rule filtering and supersession."""

    def test_l2_rule_not_included_at_l1(self) -> None:
        """A rule requiring L2 should not be included when project is at L1."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {"S1": _make_rule(rule_id="S1", level="L2")}

        result = get_applicable_rules(rules, Level.L1)

        assert "S1" not in result

    def test_l2_rule_included_at_l3(self) -> None:
        """A rule requiring L2 should be included when project is at L3."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {"S1": _make_rule(rule_id="S1", level="L2")}

        result = get_applicable_rules(rules, Level.L3)

        assert "S1" in result

    def test_l2_rule_included_at_l2(self) -> None:
        """A rule requiring L2 should be included when project is exactly at L2."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {"S1": _make_rule(rule_id="S1", level="L2")}

        result = get_applicable_rules(rules, Level.L2)

        assert "S1" in result

    def test_supersession_drops_superseded_rule(self) -> None:
        """When rule A supersedes rule B and both are applicable, B is dropped."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "S1": _make_rule(rule_id="S1", level="L1"),
            "S2": _make_rule(rule_id="S2", level="L2", supersedes="S1"),
        }

        result = get_applicable_rules(rules, Level.L3)

        assert "S2" in result
        assert "S1" not in result, "Superseded rule S1 should be dropped"

    def test_supersession_keeps_both_when_superseder_not_applicable(self) -> None:
        """When superseding rule is above project level, superseded rule stays."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "S1": _make_rule(rule_id="S1", level="L1"),
            "S2": _make_rule(rule_id="S2", level="L4", supersedes="S1"),
        }

        # At L2, S2 (L4) is not applicable, so S1 should remain
        result = get_applicable_rules(rules, Level.L2)

        assert "S1" in result
        assert "S2" not in result

    def test_multiple_rules_at_different_levels(self) -> None:
        """Multiple rules with different levels are filtered correctly."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "R1": _make_rule(rule_id="R1", level="L1"),
            "R2": _make_rule(rule_id="R2", level="L3"),
            "R3": _make_rule(rule_id="R3", level="L5"),
        }

        result = get_applicable_rules(rules, Level.L3)

        assert "R1" in result
        assert "R2" in result
        assert "R3" not in result

    def test_empty_rules_returns_empty(self) -> None:
        """Empty rules dict returns empty result."""
        from reporails_cli.core.applicability import get_applicable_rules

        result = get_applicable_rules({}, Level.L3)

        assert result == {}

    def test_invalid_level_string_skipped(self) -> None:
        """A rule with an invalid level string should be silently skipped."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "R1": _make_rule(rule_id="R1", level="L2"),
            "BAD": _make_rule(rule_id="BAD", level="invalid"),
        }

        result = get_applicable_rules(rules, Level.L3)

        assert "R1" in result
        assert "BAD" not in result

    def test_supersedes_nonexistent_rule_ignored(self) -> None:
        """A rule that supersedes a rule ID not in the dict should not crash."""
        from reporails_cli.core.applicability import get_applicable_rules

        rules = {
            "S1": _make_rule(rule_id="S1", level="L1", supersedes="DOES_NOT_EXIST"),
        }

        result = get_applicable_rules(rules, Level.L3)

        assert "S1" in result
