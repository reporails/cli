"""Unit tests for rule registry: build_rule and backed_by parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters.registry import build_rule
from reporails_cli.core.platform.dto.models import Category, PatternConfidence, Rule, RuleType

MINIMAL_FRONTMATTER = {
    "id": "CORE:S:0001",
    "title": "Test Rule",
    "category": "structure",
    "type": "deterministic",
    "slug": "test-rule",
    "match": {"type": "main"},
}


class TestBuildRuleBackedBy:
    """Test backed_by parsing in build_rule (now plain string list)."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_backed_by_parsed(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "backed_by": ["anthropic-docs", "community-practice"],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert len(rule.backed_by) == 2
        assert rule.backed_by[0] == "anthropic-docs"
        assert rule.backed_by[1] == "community-practice"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_backed_by_empty_when_absent(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.backed_by == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
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

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_sources_as_strings(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "sources": ["https://example.com/doc1", "https://example.com/doc2"],
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.sources == ["https://example.com/doc1", "https://example.com/doc2"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_sources_default_empty(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.sources == []


class TestBuildRuleBasic:
    """Test basic build_rule construction."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_minimal_rule(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.id == "CORE:S:0001"
        assert rule.title == "Test Rule"
        assert rule.category == Category.STRUCTURE
        assert rule.type == RuleType.DETERMINISTIC
        assert rule.slug == "test-rule"
        assert rule.match is not None
        assert rule.match.type == "main"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
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
        # Severity derived from first check's frontmatter entry → rule level
        assert rule.severity.value == "critical"
        assert rule.checks[1].type == "deterministic"
        assert rule.checks[1].check is None

    @pytest.mark.unit
    @pytest.mark.subsys_lint
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

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_supersedes_parsed(self) -> None:
        fm = {
            **MINIMAL_FRONTMATTER,
            "supersedes": "CORE:S:0003",
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.supersedes == "CORE:S:0003"


class TestBuildRulePatternConfidence:
    """Test pattern_confidence parsing in build_rule."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("level", ["very_high", "high", "medium", "low", "very_low"])
    def test_confidence_level_parsed(self, level: str) -> None:
        fm = {**MINIMAL_FRONTMATTER, "pattern_confidence": level}
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.pattern_confidence == PatternConfidence(level)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_none_when_absent(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.pattern_confidence is None

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_invalid_value_raises(self) -> None:
        fm = {**MINIMAL_FRONTMATTER, "pattern_confidence": "bogus"}
        with pytest.raises(ValueError):
            build_rule(fm, Path("test.md"), None)


class TestBuildRuleNewFields:
    """Test inherited and depends_on parsing."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_inherited_parsed(self) -> None:
        fm = {**MINIMAL_FRONTMATTER, "inherited": "CORE:S:0038"}
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.inherited == "CORE:S:0038"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_inherited_none_when_absent(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.inherited is None

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_depends_on_parsed(self) -> None:
        fm = {**MINIMAL_FRONTMATTER, "depends_on": ["CORE:S:0001", "CORE:S:0002"]}
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.depends_on == ["CORE:S:0001", "CORE:S:0002"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_depends_on_empty_when_absent(self) -> None:
        rule = build_rule(MINIMAL_FRONTMATTER, Path("test.md"), None)
        assert rule.depends_on == []


class TestApplyInheritance:
    """Test _apply_inheritance merges checks without removing parent."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_inheritance_merges_checks(self) -> None:
        from reporails_cli.core.platform.adapters.registry import _apply_inheritance
        from reporails_cli.core.platform.dto.models import Check

        parent_check = Check(id="CORE.S.0038.has_frontmatter", type="mechanical", check="frontmatter_present")
        child_check = Check(id="CLAUDE.S.0015.has_paths_key", type="mechanical", check="frontmatter_key")

        rules: dict[str, Rule] = {
            "CORE:S:0038": Rule(
                id="CORE:S:0038",
                title="Parent",
                category=Category.STRUCTURE,
                type=RuleType.MECHANICAL,
                checks=[parent_check],
                slug="parent",
            ),
            "CLAUDE:S:0015": Rule(
                id="CLAUDE:S:0015",
                title="Child",
                category=Category.STRUCTURE,
                type=RuleType.MECHANICAL,
                checks=[child_check],
                inherited="CORE:S:0038",
                slug="child",
            ),
        }
        _apply_inheritance(rules)

        # Parent stays
        assert "CORE:S:0038" in rules
        # Child has both checks
        child = rules["CLAUDE:S:0015"]
        assert len(child.checks) == 2
        assert child.checks[0].id == "CORE.S.0038.has_frontmatter"
        assert child.checks[1].id == "CLAUDE.S.0015.has_paths_key"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_inheritance_missing_parent_is_noop(self) -> None:
        from reporails_cli.core.platform.adapters.registry import _apply_inheritance

        rules: dict[str, Rule] = {
            "CLAUDE:S:0015": Rule(
                id="CLAUDE:S:0015",
                title="Child",
                category=Category.STRUCTURE,
                type=RuleType.MECHANICAL,
                checks=[],
                inherited="CORE:S:9999",
                slug="child",
            ),
        }
        _apply_inheritance(rules)
        assert len(rules["CLAUDE:S:0015"].checks) == 0


class TestValidateDependsOn:
    """Test _validate_depends_on cycle detection."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_cycle_passes_silently(self) -> None:
        from reporails_cli.core.platform.adapters.registry import _validate_depends_on

        rules: dict[str, Rule] = {
            "A": Rule(
                id="A", title="A", category=Category.STRUCTURE, type=RuleType.MECHANICAL, depends_on=["B"], slug="a"
            ),
            "B": Rule(id="B", title="B", category=Category.STRUCTURE, type=RuleType.MECHANICAL, slug="b"),
        }
        _validate_depends_on(rules)  # Should not raise

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_cycle_logs_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        from reporails_cli.core.platform.adapters.registry import _validate_depends_on

        rules: dict[str, Rule] = {
            "A": Rule(
                id="A", title="A", category=Category.STRUCTURE, type=RuleType.MECHANICAL, depends_on=["B"], slug="a"
            ),
            "B": Rule(
                id="B", title="B", category=Category.STRUCTURE, type=RuleType.MECHANICAL, depends_on=["A"], slug="b"
            ),
        }
        with caplog.at_level("WARNING"):
            _validate_depends_on(rules)
        assert "Circular depends_on" in caplog.text


class TestInferAgentFromRuleId:
    """Test infer_agent_from_rule_id prefix logic."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        ("rule_id", "expected"),
        [
            ("CORE:S:0001", ""),
            ("RRAILS:C:0003", ""),
            ("CLAUDE:S:0004", "claude"),
            ("CODEX:S:0001", "codex"),
            ("COPILOT:S:0001", "copilot"),
            ("no-colon", ""),
        ],
    )
    def test_infer(self, rule_id: str, expected: str) -> None:
        from reporails_cli.core.platform.adapters.registry import infer_agent_from_rule_id

        assert infer_agent_from_rule_id(rule_id) == expected


class TestSizeRuleSupersession:
    """CODEX:E:0001 supersedes the generic CORE:E:0001 with a hard 32 KiB cap; generic stays a warning."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_codex_supersedes_with_hard_cap(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules = load_rules(project_root=tmp_path, scan_root=tmp_path, agent="codex")
        assert "CORE:E:0001" not in rules  # superseded for codex
        codex = rules["CODEX:E:0001"]
        assert codex.severity.value == "high"  # an actual failure
        maxes = [(c.args or {}).get("max") for c in codex.checks if c.check == "aggregate_byte_size"]
        assert maxes == [32768]  # the codex cap replaces the inherited 102400, not both

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_generic_core_size_rule_is_a_warning(self, tmp_path: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules = load_rules(project_root=tmp_path, scan_root=tmp_path, agent="claude")
        assert rules["CORE:E:0001"].severity.value == "medium"  # renders as warning, not error
