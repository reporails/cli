"""Unit tests for agent config loading, excludes, and overrides."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from reporails_cli.core.bootstrap import get_agent_config
from reporails_cli.core.models import AgentConfig, Category, Check, Rule, RuleType, Severity
from reporails_cli.core.registry import _apply_agent_overrides, load_rules


# =============================================================================
# get_agent_config tests
# =============================================================================


class TestGetAgentConfig:
    """Test loading agent config from framework."""

    def test_loads_excludes_and_overrides(self, tmp_path: Path) -> None:
        config_data = {
            "agent": "claude",
            "excludes": ["S4", "S5"],
            "overrides": {
                "E2-no-ritual-section": {"severity": "medium"},
                "E5-no-grep-guidance": {"severity": "low", "disabled": True},
            },
        }
        config_path = tmp_path / "agents" / "claude" / "config.yml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(yaml.dump(config_data))

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

    def test_malformed_yaml_returns_defaults(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yml"
        config_path.write_text(": : : invalid yaml [[[")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result == AgentConfig()

    def test_empty_file_returns_defaults(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.yml"
        config_path.write_text("")

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result == AgentConfig()

    def test_config_without_excludes_or_overrides(self, tmp_path: Path) -> None:
        config_data = {"agent": "claude", "vars": {"instruction_files": "CLAUDE.md"}}
        config_path = tmp_path / "config.yml"
        config_path.write_text(yaml.dump(config_data))

        with patch("reporails_cli.core.bootstrap.get_agent_config_path", return_value=config_path):
            result = get_agent_config("claude")

        assert result.agent == "claude"
        assert result.excludes == []
        assert result.overrides == {}


# =============================================================================
# _apply_agent_overrides tests
# =============================================================================


def _make_rule(rule_id: str, checks: list[Check]) -> Rule:
    """Helper to create a Rule with given checks."""
    return Rule(
        id=rule_id,
        title=f"Rule {rule_id}",
        category=Category.STRUCTURE,
        type=RuleType.DETERMINISTIC,
        level="L2",
        checks=checks,
    )


class TestApplyAgentOverrides:
    """Test agent check-level overrides."""

    def test_severity_changed(self) -> None:
        checks = [Check(id="E2-check", name="Check", severity=Severity.HIGH)]
        rules = {"E2": _make_rule("E2", checks)}

        overrides = {"E2-check": {"severity": "low"}}
        result = _apply_agent_overrides(rules, overrides)

        assert result["E2"].checks[0].severity == Severity.LOW

    def test_check_disabled(self) -> None:
        checks = [
            Check(id="E2-check-a", name="Check A", severity=Severity.HIGH),
            Check(id="E2-check-b", name="Check B", severity=Severity.MEDIUM),
        ]
        rules = {"E2": _make_rule("E2", checks)}

        overrides = {"E2-check-a": {"disabled": True}}
        result = _apply_agent_overrides(rules, overrides)

        assert len(result["E2"].checks) == 1
        assert result["E2"].checks[0].id == "E2-check-b"

    def test_nonexistent_check_is_noop(self) -> None:
        checks = [Check(id="E2-check", name="Check", severity=Severity.HIGH)]
        rules = {"E2": _make_rule("E2", checks)}

        overrides = {"BOGUS-check": {"severity": "low"}}
        result = _apply_agent_overrides(rules, overrides)

        assert result["E2"].checks[0].severity == Severity.HIGH

    def test_all_checks_disabled_leaves_empty_list(self) -> None:
        checks = [Check(id="E2-check", name="Check", severity=Severity.HIGH)]
        rules = {"E2": _make_rule("E2", checks)}

        overrides = {"E2-check": {"disabled": True}}
        result = _apply_agent_overrides(rules, overrides)

        assert result["E2"].checks == []

    def test_invalid_severity_raises(self) -> None:
        checks = [Check(id="E2-check", name="Check", severity=Severity.HIGH)]
        rules = {"E2": _make_rule("E2", checks)}

        overrides = {"E2-check": {"severity": "bogus"}}
        with pytest.raises(ValueError):
            _apply_agent_overrides(rules, overrides)

    def test_multiple_rules_overridden(self) -> None:
        rules = {
            "E2": _make_rule("E2", [Check(id="E2-c1", name="C1", severity=Severity.HIGH)]),
            "E5": _make_rule("E5", [Check(id="E5-c1", name="C1", severity=Severity.MEDIUM)]),
        }

        overrides = {
            "E2-c1": {"severity": "low"},
            "E5-c1": {"disabled": True},
        }
        result = _apply_agent_overrides(rules, overrides)

        assert result["E2"].checks[0].severity == Severity.LOW
        assert result["E5"].checks == []


# =============================================================================
# load_rules agent integration tests
# =============================================================================


class TestLoadRulesExcludes:
    """Test that agent excludes remove rules from the loaded set."""

    def test_excludes_removes_rules(self, tmp_path: Path) -> None:
        """Excluded rule IDs are filtered out."""
        # Create a minimal rules dir with two rules
        core_dir = tmp_path / "core" / "structure"
        core_dir.mkdir(parents=True)
        for rule_id in ("S1", "S2"):
            (core_dir / f"{rule_id}.md").write_text(
                f"---\nid: {rule_id}\ntitle: Rule {rule_id}\ncategory: structure\n"
                f"type: deterministic\nlevel: L2\nbacked_by:\n"
                f"  - source: anthropic-docs\n    claim: test\n---\n"
            )

        agent_config = AgentConfig(agent="test", excludes=["S1"])
        with (
            patch("reporails_cli.core.registry.get_agent_config", return_value=agent_config),
            patch("reporails_cli.core.registry._load_source_weights", return_value={"anthropic-docs": 1.0}),
        ):
            rules = load_rules(tmp_path, include_experimental=False, agent="test")

        assert "S1" not in rules
        assert "S2" in rules

    def test_excludes_nonexistent_rule_is_noop(self, tmp_path: Path) -> None:
        """Excluding a rule ID that doesn't exist is harmless."""
        core_dir = tmp_path / "core" / "structure"
        core_dir.mkdir(parents=True)
        (core_dir / "S1.md").write_text(
            "---\nid: S1\ntitle: Rule S1\ncategory: structure\n"
            "type: deterministic\nlevel: L2\nbacked_by:\n"
            "  - source: anthropic-docs\n    claim: test\n---\n"
        )

        agent_config = AgentConfig(agent="test", excludes=["NONEXISTENT"])
        with (
            patch("reporails_cli.core.registry.get_agent_config", return_value=agent_config),
            patch("reporails_cli.core.registry._load_source_weights", return_value={"anthropic-docs": 1.0}),
        ):
            rules = load_rules(tmp_path, include_experimental=False, agent="test")

        assert "S1" in rules

    def test_no_agent_skips_processing(self, tmp_path: Path) -> None:
        """Empty agent string skips agent config loading entirely."""
        core_dir = tmp_path / "core" / "structure"
        core_dir.mkdir(parents=True)
        (core_dir / "S1.md").write_text(
            "---\nid: S1\ntitle: Rule S1\ncategory: structure\n"
            "type: deterministic\nlevel: L2\nbacked_by:\n"
            "  - source: anthropic-docs\n    claim: test\n---\n"
        )

        with patch("reporails_cli.core.registry._load_source_weights", return_value={"anthropic-docs": 1.0}):
            rules = load_rules(tmp_path, include_experimental=False, agent="")

        assert "S1" in rules
