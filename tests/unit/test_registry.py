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
    def test_match_carries_loading_verb_and_link_source_type(self) -> None:
        """A rule's `match:` mapping can target `loading_verb` / `link_source_type` — both are
        declared `FileMatch` fields and compared by `MATCH_PROPERTIES`, but `_parse_match` used
        to omit them from the `FileMatch(...)` kwargs, so a rule author's `loading_verb: read`
        was silently dropped at load and could never match a file."""
        fm = {
            **MINIMAL_FRONTMATTER,
            "match": {"type": "generic", "loading_verb": ["read"], "link_source_type": ["main"]},
        }
        rule = build_rule(fm, Path("test.md"), None)
        assert rule.match is not None
        assert rule.match.loading_verb == ["read"]
        assert rule.match.link_source_type == ["main"]

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

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_dependency_unknown_to_every_source_warns(self, caplog: pytest.LogCaptureFixture) -> None:
        from reporails_cli.core.platform.adapters.registry import _validate_depends_on

        rules: dict[str, Rule] = {
            "A": Rule(
                id="A", title="A", category=Category.STRUCTURE, type=RuleType.MECHANICAL, depends_on=["GHOST"], slug="a"
            ),
        }
        with caplog.at_level("WARNING"):
            _validate_depends_on(rules, None, {"A", "B"})
        assert "GHOST" in caplog.text

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_dependency_left_out_by_agent_config_is_silent(self, caplog: pytest.LogCaptureFixture) -> None:
        from reporails_cli.core.platform.adapters.registry import _validate_depends_on

        rules: dict[str, Rule] = {
            "A": Rule(
                id="A", title="A", category=Category.STRUCTURE, type=RuleType.MECHANICAL, depends_on=["B"], slug="a"
            ),
        }
        with caplog.at_level("WARNING"):
            _validate_depends_on(rules, None, {"A", "B"})
        assert "not loaded" not in caplog.text

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_copilot_load_keeps_dependent_rule_without_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        from reporails_cli.core.platform.adapters import registry

        rules_dir = Path(__file__).resolve().parents[2] / "framework" / "rules"
        registry.clear_rule_cache()
        try:
            with caplog.at_level("WARNING"):
                rules = registry.load_rules(rules_paths=[rules_dir], agent="copilot")
        finally:
            registry.clear_rule_cache()
        assert "which is not loaded" not in caplog.text
        assert "CORE:S:0026" in rules
        assert "CORE:S:0024" not in rules


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
        assert rules["CORE:E:0001"].severity.value == "low"  # demoted tier — renders as info, not error


class TestRuleDependencies:
    """`depends_on` resolves through supersession so the findings of the superseding rule satisfy it."""

    @staticmethod
    def _write(root: Path, folder: str, rule_id: str, extra: str = "") -> None:
        rule_dir = root / folder
        rule_dir.mkdir(parents=True)
        slug = folder.replace("/", "-")
        (rule_dir / "rule.md").write_text(
            f"---\nid: {rule_id}\ntitle: T\ncategory: structure\ntype: deterministic\nslug: {slug}\n"
            f"match:\n  type: main\n{extra}---\nbody\n",
            encoding="utf-8",
        )

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_dependency_on_a_superseded_core_rule_names_the_superseding_agent_rule(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from reporails_cli.core.platform.adapters import registry

        self._write(tmp_path, "core/base", "CORE:S:0901")
        self._write(tmp_path, "core/dependent", "CORE:S:0902", "depends_on: [CORE:S:0901]\n")
        self._write(tmp_path, "claude/base", "CLAUDE:S:0901", "supersedes: CORE:S:0901\n")
        monkeypatch.setattr(registry, "get_rules_dir", lambda: tmp_path)
        registry.clear_rule_cache()
        try:
            assert registry.rule_dependencies("claude") == {"CORE:S:0902": frozenset({"CLAUDE:S:0901"})}
            assert registry.rule_dependencies("") == {"CORE:S:0902": frozenset({"CORE:S:0901"})}
        finally:
            registry.clear_rule_cache()


class TestProjectScopeModes:
    """`project_scope` marks a check that judges the project, not one file: `aggregate` or `once`."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_the_shipped_checks_declare_their_mode(self, dev_rules_dir: Path) -> None:
        from reporails_cli.core.platform.adapters.registry import load_rules

        rules = load_rules(agent="claude")
        modes = {c.id: c.project_scope for r in rules.values() for c in r.checks if c.project_scope}
        assert modes["CORE.G.0001.check"] == "once"
        assert modes["CORE.E.0001.check"] == "aggregate"
        assert set(modes.values()) == {"aggregate", "once"}

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_an_unknown_mode_is_refused(self) -> None:
        from pydantic import ValidationError

        from reporails_cli.core.platform.dto.models import Check

        with pytest.raises(ValidationError):
            Check(id="X.1", type="mechanical", check="git_tracked", project_scope="always")  # type: ignore[arg-type]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_both_modes_stand_for_the_run_as_a_whole(self, dev_rules_dir: Path) -> None:
        """The once-per-project git check reports on the first matched file, like the aggregate checks."""
        from reporails_cli.core.platform.adapters.registry import whole_run_check_ids

        whole_run = whole_run_check_ids("claude")
        assert "CORE.G.0001.check" in whole_run
        assert "CORE.E.0001.check" in whole_run
