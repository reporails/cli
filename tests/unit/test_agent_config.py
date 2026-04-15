"""Unit tests for agent config loading, excludes, and overrides."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from reporails_cli.core.agents import (
    DetectedAgent,
    _codex_global_heuristic,
    _disambiguate_codex_generic,
    auto_detect_agent,
    get_known_agents,
)
from reporails_cli.core.bootstrap import get_agent_config
from reporails_cli.core.models import (
    AgentConfig,
    Category,
    Check,
    Rule,
    RuleType,
    Severity,
)
from reporails_cli.core.registry import _apply_agent_overrides, _is_other_agent_rule, load_rules

# =============================================================================
# get_agent_config tests
# =============================================================================


class TestGetAgentConfig:
    """Test loading agent config from framework."""

    def test_loads_excludes_and_overrides(self, tmp_path: Path, make_config_file) -> None:
        config_data = {
            "agent": "claude",
            "excludes": ["S4", "S5"],
            "overrides": {
                "E2-no-ritual-section": {"severity": "medium"},
                "E5-no-grep-guidance": {"severity": "low", "disabled": True},
            },
        }
        config_path = make_config_file(yaml.dump(config_data), subdir="agents/claude")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result.agent == "claude"
        assert result.excludes == ["S4", "S5"]
        assert result.overrides["E2-no-ritual-section"] == {"severity": "medium"}
        assert result.overrides["E5-no-grep-guidance"] == {"severity": "low", "disabled": True}

    def test_missing_config_returns_defaults(self) -> None:
        with patch(
            "reporails_cli.core.bootstrap.get_agent_config_path",
            return_value=Path("/nonexistent/config.yml"),
        ):
            result = get_agent_config("claude")

        assert result == AgentConfig()
        assert result.excludes == []
        assert result.overrides == {}

    def test_malformed_yaml_returns_defaults(self, tmp_path: Path, make_config_file) -> None:
        config_path = make_config_file(": : : invalid yaml [[[", subdir=".", name="config.yml")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result == AgentConfig()

    def test_empty_file_returns_defaults(self, tmp_path: Path, make_config_file) -> None:
        config_path = make_config_file("", subdir=".", name="config.yml")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result == AgentConfig()

    def test_config_without_excludes_or_overrides(self, tmp_path: Path, make_config_file) -> None:
        config_data = {"agent": "claude", "vars": {"instruction_files": "CLAUDE.md"}}
        config_path = make_config_file(yaml.dump(config_data), subdir=".", name="config.yml")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result.agent == "claude"
        assert result.excludes == []
        assert result.overrides == {}

    def test_loads_prefix_name_core(self, tmp_path: Path, make_config_file) -> None:
        config_data = {
            "agent": "claude",
            "prefix": "CLAUDE",
            "name": "Claude Code",
            "core": False,
            "excludes": ["CODEX:*"],
        }
        config_path = make_config_file(yaml.dump(config_data), subdir="agents/claude")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result.prefix == "CLAUDE"
        assert result.name == "Claude Code"
        assert result.core is False
        assert result.excludes == ["CODEX:*"]

    def test_missing_new_fields_default(self, tmp_path: Path, make_config_file) -> None:
        """Config without prefix/name/core gets empty defaults."""
        config_data = {"agent": "claude"}
        config_path = make_config_file(yaml.dump(config_data), subdir="agents/claude")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result.prefix == ""
        assert result.name == ""
        assert result.core is False

    def test_core_agent_config(self, tmp_path: Path, make_config_file) -> None:
        """Core agent (generic) sets core=True."""
        config_data = {"agent": "generic", "prefix": "CORE", "core": True}
        config_path = make_config_file(yaml.dump(config_data), subdir="agents/generic")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("generic")

        assert result.core is True
        assert result.prefix == "CORE"


# =============================================================================
# _apply_agent_overrides tests
# =============================================================================


def _make_rule(rule_id: str, checks: list[Check], severity: Severity = Severity.MEDIUM) -> Rule:
    """Helper to create a Rule with given checks."""
    return Rule(
        id=rule_id,
        title=f"Rule {rule_id}",
        category=Category.STRUCTURE,
        type=RuleType.DETERMINISTIC,
        severity=severity,
        checks=checks,
    )


class TestApplyAgentOverrides:
    """Test agent check-level overrides."""

    def test_severity_changed(self) -> None:
        checks = [Check(id="E2-check")]
        rules = {"E2": _make_rule("E2", checks, severity=Severity.HIGH)}

        overrides = {"E2-check": {"severity": "low"}}
        result = _apply_agent_overrides(rules, overrides)

        # Severity override now lifted to rule level
        assert result["E2"].severity == Severity.LOW

    def test_check_disabled(self) -> None:
        checks = [
            Check(id="E2-check-a"),
            Check(id="E2-check-b"),
        ]
        rules = {"E2": _make_rule("E2", checks)}

        overrides = {"E2-check-a": {"disabled": True}}
        result = _apply_agent_overrides(rules, overrides)

        assert len(result["E2"].checks) == 1
        assert result["E2"].checks[0].id == "E2-check-b"

    def test_nonexistent_check_is_noop(self) -> None:
        checks = [Check(id="E2-check")]
        rules = {"E2": _make_rule("E2", checks, severity=Severity.HIGH)}

        overrides = {"BOGUS-check": {"severity": "low"}}
        result = _apply_agent_overrides(rules, overrides)

        assert result["E2"].severity == Severity.HIGH  # unchanged

    def test_all_checks_disabled_leaves_empty_list(self) -> None:
        checks = [Check(id="E2-check")]
        rules = {"E2": _make_rule("E2", checks)}

        overrides = {"E2-check": {"disabled": True}}
        result = _apply_agent_overrides(rules, overrides)

        assert result["E2"].checks == []

    def test_invalid_severity_skipped(self) -> None:
        checks = [Check(id="E2-check")]
        rules = {"E2": _make_rule("E2", checks, severity=Severity.HIGH)}

        overrides = {"E2-check": {"severity": "bogus"}}
        result = _apply_agent_overrides(rules, overrides)
        # Invalid severity is skipped — original rule severity unchanged
        assert result["E2"].severity == Severity.HIGH

    def test_multiple_rules_overridden(self) -> None:
        rules = {
            "E2": _make_rule("E2", [Check(id="E2-c1")], severity=Severity.HIGH),
            "E5": _make_rule("E5", [Check(id="E5-c1")], severity=Severity.MEDIUM),
        }

        overrides = {
            "E2-c1": {"severity": "low"},
            "E5-c1": {"disabled": True},
        }
        result = _apply_agent_overrides(rules, overrides)

        assert result["E2"].severity == Severity.LOW
        assert result["E5"].checks == []


# =============================================================================
# load_rules agent integration tests
# =============================================================================


class TestLoadRulesExcludes:
    """Test that agent excludes remove rules from the loaded set."""

    def test_excludes_removes_rules(self, tmp_path: Path) -> None:
        """Excluded rule IDs are filtered out."""
        # Create a minimal rules dir with two rules (new format: rule.md in slug dirs)
        for slug, coord in (("rule-a", "CORE:S:0001"), ("rule-b", "CORE:S:0002")):
            rule_dir = tmp_path / "core" / "structure" / slug
            rule_dir.mkdir(parents=True)
            (rule_dir / "rule.md").write_text(
                f'---\nid: "{coord}"\ntitle: Rule {coord}\ncategory: structure\n'
                f"type: deterministic\nlevel: L2\nslug: {slug}\n"
                f"targets: '{{{{instruction_files}}}}'\nbacked_by:\n  - anthropic-docs\n---\n"
            )

        agent_config = AgentConfig(agent="test", excludes=["CORE:S:0001"])
        with patch("reporails_cli.core.registry.get_agent_config", return_value=agent_config):
            rules = load_rules([tmp_path], agent="test")

        assert "CORE:S:0001" not in rules
        assert "CORE:S:0002" in rules

    def test_excludes_nonexistent_rule_is_noop(self, tmp_path: Path) -> None:
        """Excluding a rule ID that doesn't exist is harmless."""
        rule_dir = tmp_path / "core" / "structure" / "rule-a"
        rule_dir.mkdir(parents=True)
        (rule_dir / "rule.md").write_text(
            '---\nid: "CORE:S:0001"\ntitle: Rule CORE:S:0001\ncategory: structure\n'
            "type: deterministic\nlevel: L2\nslug: rule-a\n"
            "targets: '{{instruction_files}}'\nbacked_by:\n  - anthropic-docs\n---\n"
        )

        agent_config = AgentConfig(agent="test", excludes=["NONEXISTENT"])
        with patch("reporails_cli.core.registry.get_agent_config", return_value=agent_config):
            rules = load_rules([tmp_path], agent="test")

        assert "CORE:S:0001" in rules

    def test_no_agent_skips_processing(self, tmp_path: Path) -> None:
        """Empty agent string skips agent config loading entirely."""
        rule_dir = tmp_path / "core" / "structure" / "rule-a"
        rule_dir.mkdir(parents=True)
        (rule_dir / "rule.md").write_text(
            '---\nid: "CORE:S:0001"\ntitle: Rule CORE:S:0001\ncategory: structure\n'
            "type: deterministic\nlevel: L2\nslug: rule-a\n"
            "targets: '{{instruction_files}}'\nbacked_by:\n  - anthropic-docs\n---\n"
        )

        rules = load_rules([tmp_path], agent="")

        assert "CORE:S:0001" in rules

    def test_glob_excludes_match_namespaced_rules(self, tmp_path: Path) -> None:
        """Glob pattern CLAUDE:* excludes all CLAUDE-namespaced rules."""
        rule_fm = (
            '---\nid: "{}"\ntitle: Rule {}\ncategory: structure\n'
            "type: deterministic\nlevel: L2\nslug: {}\n"
            "targets: '{{{{instruction_files}}}}'\nbacked_by:\n  - anthropic-docs\n---\n"
        )
        for slug, coord in (
            ("core-rule", "CORE:S:0001"),
            ("claude-rule-a", "CLAUDE:S:0001"),
            ("claude-rule-b", "CLAUDE:C:0002"),
            ("codex-rule", "CODEX:S:0001"),
        ):
            rule_dir = tmp_path / "core" / "structure" / slug
            rule_dir.mkdir(parents=True)
            (rule_dir / "rule.md").write_text(rule_fm.format(coord, coord, slug))

        agent_config = AgentConfig(
            agent="copilot",
            prefix="COPILOT",
            excludes=["CLAUDE:*", "CODEX:*"],
        )
        with patch("reporails_cli.core.registry.get_agent_config", return_value=agent_config):
            rules = load_rules([tmp_path], agent="copilot")

        assert "CORE:S:0001" in rules
        assert "CLAUDE:S:0001" not in rules
        assert "CLAUDE:C:0002" not in rules
        assert "CODEX:S:0001" not in rules

    def test_exact_and_glob_excludes_coexist(self, tmp_path: Path) -> None:
        """Exact IDs and glob patterns work together in excludes."""
        rule_fm = (
            '---\nid: "{}"\ntitle: Rule {}\ncategory: structure\n'
            "type: deterministic\nlevel: L2\nslug: {}\n"
            "targets: '{{{{instruction_files}}}}'\nbacked_by:\n  - anthropic-docs\n---\n"
        )
        for slug, coord in (
            ("core-a", "CORE:S:0001"),
            ("core-b", "CORE:S:0002"),
            ("claude-a", "CLAUDE:S:0001"),
        ):
            rule_dir = tmp_path / "core" / "structure" / slug
            rule_dir.mkdir(parents=True)
            (rule_dir / "rule.md").write_text(rule_fm.format(coord, coord, slug))

        agent_config = AgentConfig(
            agent="test",
            excludes=["CORE:S:0001", "CLAUDE:*"],
        )
        with patch("reporails_cli.core.registry.get_agent_config", return_value=agent_config):
            rules = load_rules([tmp_path], agent="test")

        assert "CORE:S:0001" not in rules  # exact exclude
        assert "CORE:S:0002" in rules  # not excluded
        assert "CLAUDE:S:0001" not in rules  # glob exclude


# =============================================================================
# Prefix-based namespace filtering tests
# =============================================================================


class TestPrefixNamespaceFiltering:
    """Test that agent_config.prefix is used for namespace filtering."""

    @pytest.mark.parametrize(
        ("rule_id", "agent_prefix", "expected"),
        [
            pytest.param("CORE:S:0001", "CLAUDE", False, id="core_always_kept"),
            pytest.param("RRAILS:C:0001", "CLAUDE", False, id="rrails_always_kept"),
            pytest.param("CLAUDE:S:0001", "CLAUDE", False, id="own_namespace_kept"),
            pytest.param("CODEX:S:0001", "CLAUDE", True, id="other_namespace_filtered"),
            pytest.param("RRAILS_CLAUDE:S:0001", "CLAUDE", False, id="rrails_agent_kept"),
            pytest.param("RRAILS_CODEX:S:0001", "CLAUDE", True, id="rrails_other_filtered"),
        ],
    )
    def test_is_other_agent_rule(self, rule_id: str, agent_prefix: str, expected: bool) -> None:
        assert _is_other_agent_rule(rule_id, agent_prefix) == expected

    def test_prefix_from_config_used(self, tmp_path: Path) -> None:
        """When agent_config.prefix is set, it's used instead of agent.upper()."""
        rule_fm = (
            '---\nid: "{}"\ntitle: Rule {}\ncategory: structure\n'
            "type: deterministic\nlevel: L2\nslug: {}\n"
            "targets: '{{{{instruction_files}}}}'\nbacked_by:\n  - anthropic-docs\n---\n"
        )
        for slug, coord in (
            ("core-rule", "CORE:S:0001"),
            ("myagent-rule", "MYPREFIX:S:0001"),
            ("other-rule", "OTHER:S:0001"),
        ):
            rule_dir = tmp_path / "core" / "structure" / slug
            rule_dir.mkdir(parents=True)
            (rule_dir / "rule.md").write_text(rule_fm.format(coord, coord, slug))

        # Agent name is "myagent" but prefix is "MYPREFIX" — prefix should win
        agent_config = AgentConfig(agent="myagent", prefix="MYPREFIX")
        with patch("reporails_cli.core.registry.get_agent_config", return_value=agent_config):
            rules = load_rules([tmp_path], agent="myagent")

        assert "CORE:S:0001" in rules
        assert "MYPREFIX:S:0001" in rules
        assert "OTHER:S:0001" not in rules

    def test_fallback_to_agent_upper_without_prefix(self, tmp_path: Path) -> None:
        """Without prefix in config, falls back to agent.upper()."""
        rule_fm = (
            '---\nid: "{}"\ntitle: Rule {}\ncategory: structure\n'
            "type: deterministic\nlevel: L2\nslug: {}\n"
            "targets: '{{{{instruction_files}}}}'\nbacked_by:\n  - anthropic-docs\n---\n"
        )
        for slug, coord in (
            ("core-rule", "CORE:S:0001"),
            ("claude-rule", "CLAUDE:S:0001"),
            ("other-rule", "OTHER:S:0001"),
        ):
            rule_dir = tmp_path / "core" / "structure" / slug
            rule_dir.mkdir(parents=True)
            (rule_dir / "rule.md").write_text(rule_fm.format(coord, coord, slug))

        # No prefix — agent.upper() = "CLAUDE" used for filtering
        agent_config = AgentConfig(agent="claude")
        with patch("reporails_cli.core.registry.get_agent_config", return_value=agent_config):
            rules = load_rules([tmp_path], agent="claude")

        assert "CORE:S:0001" in rules
        assert "CLAUDE:S:0001" in rules
        assert "OTHER:S:0001" not in rules


# =============================================================================
# Glob exclude unit tests (fnmatch behavior)
# =============================================================================


class TestGlobExcludePatterns:
    """Verify fnmatch patterns match rule IDs correctly."""

    @pytest.mark.parametrize(
        ("rule_id", "pattern", "should_match"),
        [
            pytest.param("CLAUDE:S:0001", "CLAUDE:*", True, id="glob_namespace"),
            pytest.param("CLAUDE:C:0002", "CLAUDE:*", True, id="glob_namespace_other_cat"),
            pytest.param("CORE:S:0001", "CLAUDE:*", False, id="glob_no_match_core"),
            pytest.param("CODEX:S:0001", "CODEX:*", True, id="glob_codex"),
            pytest.param("CORE:S:0001", "CORE:S:0001", True, id="exact_match"),
            pytest.param("CORE:S:0002", "CORE:S:0001", False, id="exact_no_match"),
            pytest.param("RRAILS_CLAUDE:S:0001", "RRAILS_CLAUDE:*", True, id="glob_rrails_agent"),
        ],
    )
    def test_fnmatch_patterns(self, rule_id: str, pattern: str, should_match: bool) -> None:
        assert fnmatch(rule_id, pattern) == should_match


# =============================================================================
# auto_detect_agent tests
# =============================================================================


def _detected(agent_id: str, files: list[str] | None = None) -> DetectedAgent:
    """Create a DetectedAgent stub for a known agent."""
    return DetectedAgent(
        agent_type=get_known_agents()[agent_id],
        instruction_files=[Path(f) for f in files] if files else [],
    )


class TestAutoDetectAgent:
    """Test auto_detect_agent picks agent only when unambiguous."""

    @pytest.mark.parametrize(
        ("agents", "expected"),
        [
            pytest.param([_detected("claude", ["CLAUDE.md"])], "claude", id="single_non_generic"),
            pytest.param(
                [_detected("claude", ["CLAUDE.md"]), _detected("generic", ["AGENTS.md"])],
                "claude",
                id="non_generic_plus_generic",
            ),
            pytest.param(
                [_detected("claude", ["CLAUDE.md"]), _detected("copilot", [".github/copilot-instructions.md"])],
                "",
                id="two_distinctive_ambiguous",
            ),
            pytest.param([_detected("generic", ["AGENTS.md"])], "", id="generic_only"),
            pytest.param([], "", id="empty_list"),
            pytest.param(
                [
                    _detected("claude", ["CLAUDE.md"]),
                    _detected("codex", ["AGENTS.md"]),
                    _detected("generic", ["AGENTS.md"]),
                ],
                "claude",
                id="codex_overlaps_generic_ignored",
            ),
            pytest.param(
                [_detected("codex", ["AGENTS.md"]), _detected("generic", ["AGENTS.md"])],
                "",
                id="codex_only_not_distinctive",
            ),
        ],
    )
    def test_auto_detect(self, agents: list[DetectedAgent], expected: str) -> None:
        assert auto_detect_agent(agents) == expected


# =============================================================================
# Codex/generic disambiguation tests
# =============================================================================


def _make_detected(agent_id: str, instruction_files: list[str], config_files: list[str] | None = None) -> DetectedAgent:
    """Create a DetectedAgent with instruction and config files."""
    return DetectedAgent(
        agent_type=get_known_agents()[agent_id],
        instruction_files=[Path(f) for f in instruction_files],
        config_files=[Path(f) for f in (config_files or [])],
    )


class TestCodexGenericDisambiguation:
    """Three-tier codex/generic disambiguation on AGENTS.md projects."""

    def test_tier1_override_file_picks_codex(self, tmp_path: Path) -> None:
        """AGENTS.override.md present → codex (definitive)."""
        detected = [
            _make_detected("codex", ["AGENTS.md", "AGENTS.override.md"]),
            _make_detected("generic", ["AGENTS.md"]),
        ]
        result = _disambiguate_codex_generic(detected, tmp_path)
        ids = {a.agent_type.id for a in result}
        assert "codex" in ids
        assert "generic" not in ids

    def test_tier2_config_toml_picks_codex(self, tmp_path: Path) -> None:
        """.codex/config.toml present → codex (definitive)."""
        detected = [
            _make_detected("codex", ["AGENTS.md"], [".codex/config.toml"]),
            _make_detected("generic", ["AGENTS.md"]),
        ]
        result = _disambiguate_codex_generic(detected, tmp_path)
        ids = {a.agent_type.id for a in result}
        assert "codex" in ids
        assert "generic" not in ids

    def test_tier3_global_config_plus_gitignore(self, tmp_path: Path) -> None:
        """~/.codex/config.toml + .codex in .gitignore → codex (assumed)."""
        (tmp_path / ".gitignore").write_text(".codex/\n")
        detected = [
            _make_detected("codex", ["AGENTS.md"]),
            _make_detected("generic", ["AGENTS.md"]),
        ]
        with patch("reporails_cli.core.agents.Path.home", return_value=tmp_path / "fakehome"):
            # No global config → should NOT pick codex
            result = _disambiguate_codex_generic(detected, tmp_path)
            assert {a.agent_type.id for a in result} == {"generic"}

            # Create global config → should pick codex
            (tmp_path / "fakehome" / ".codex").mkdir(parents=True)
            (tmp_path / "fakehome" / ".codex" / "config.toml").write_text("")
            result = _disambiguate_codex_generic(detected, tmp_path)
            assert {a.agent_type.id for a in result} == {"codex"}

    def test_tier3_override_in_gitignore(self, tmp_path: Path) -> None:
        """~/.codex/config.toml + AGENTS.override in .gitignore → codex."""
        (tmp_path / ".gitignore").write_text("AGENTS.override.md\n")
        detected = [
            _make_detected("codex", ["AGENTS.md"]),
            _make_detected("generic", ["AGENTS.md"]),
        ]
        with patch("reporails_cli.core.agents.Path.home", return_value=tmp_path / "fakehome"):
            (tmp_path / "fakehome" / ".codex").mkdir(parents=True)
            (tmp_path / "fakehome" / ".codex" / "config.toml").write_text("")
            result = _disambiguate_codex_generic(detected, tmp_path)
            assert {a.agent_type.id for a in result} == {"codex"}

    def test_no_signals_picks_generic(self, tmp_path: Path) -> None:
        """No codex markers → generic wins, codex dropped."""
        detected = [
            _make_detected("codex", ["AGENTS.md"]),
            _make_detected("generic", ["AGENTS.md"]),
        ]
        result = _disambiguate_codex_generic(detected, tmp_path)
        ids = {a.agent_type.id for a in result}
        assert "generic" in ids
        assert "codex" not in ids

    def test_no_generic_returns_unchanged(self, tmp_path: Path) -> None:
        """Without generic in the list, disambiguation is a no-op."""
        detected = [_make_detected("codex", ["AGENTS.md"])]
        result = _disambiguate_codex_generic(detected, tmp_path)
        assert len(result) == 1
        assert result[0].agent_type.id == "codex"

    def test_no_codex_returns_unchanged(self, tmp_path: Path) -> None:
        """Without codex in the list, disambiguation is a no-op."""
        detected = [_make_detected("generic", ["AGENTS.md"])]
        result = _disambiguate_codex_generic(detected, tmp_path)
        assert len(result) == 1
        assert result[0].agent_type.id == "generic"

    def test_other_agents_preserved(self, tmp_path: Path) -> None:
        """Claude and copilot are untouched by disambiguation."""
        detected = [
            _make_detected("claude", ["CLAUDE.md"]),
            _make_detected("codex", ["AGENTS.md"]),
            _make_detected("generic", ["AGENTS.md"]),
            _make_detected("copilot", [".github/copilot-instructions.md"]),
        ]
        result = _disambiguate_codex_generic(detected, tmp_path)
        ids = {a.agent_type.id for a in result}
        assert "claude" in ids
        assert "copilot" in ids
        assert "generic" in ids
        assert "codex" not in ids

    def test_tier3_gitignore_without_global_config(self, tmp_path: Path) -> None:
        """Gitignore mentions .codex but no global config → generic wins."""
        (tmp_path / ".gitignore").write_text(".codex/\n")
        with patch("reporails_cli.core.agents.Path.home", return_value=tmp_path / "emptyhome"):
            (tmp_path / "emptyhome").mkdir()
            assert not _codex_global_heuristic(tmp_path)
