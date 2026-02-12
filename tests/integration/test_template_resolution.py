"""Template resolution tests - CRITICAL for correctness.

Every template variable must resolve before reaching the regex engine.
Unresolved templates cause silent failures that are hard to debug.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import create_temp_rule_file


class TestTemplateResolution:
    """Every template variable must resolve before reaching the regex engine."""

    def test_instruction_files_resolves_to_glob(self, agent_config: dict[str, str]) -> None:
        """{{instruction_files}} must resolve to an actual glob pattern."""
        assert "instruction_files" in agent_config, (
            "Agent config missing 'instruction_files' key - templates using this will fail silently"
        )
        value = agent_config["instruction_files"]
        assert value, "instruction_files is empty"
        # instruction_files can be a string or list of globs
        if isinstance(value, list):
            for item in value:
                assert "{{" not in item, f"instruction_files contains unresolved template: {item}"
                assert "*" in item or "/" in item, f"instruction_files item doesn't look like a path pattern: {item}"
        else:
            assert "{{" not in value, f"instruction_files contains unresolved template: {value}"
            assert "*" in value or "/" in value, f"instruction_files doesn't look like a path pattern: {value}"

    def test_rules_dir_resolves(self, agent_config: dict[str, str]) -> None:
        """{{rules_dir}} must resolve to a directory path."""
        assert "rules_dir" in agent_config, "Agent config missing 'rules_dir' key"
        value = agent_config["rules_dir"]
        assert value, "rules_dir is empty"
        assert "{{" not in value, f"rules_dir contains unresolved template: {value}"

    def test_resolve_yml_templates_replaces_placeholders(
        self,
        tmp_path: Path,
        rule_with_template_yaml: str,
        agent_config: dict[str, str],
    ) -> None:
        """Template placeholders must be replaced with actual values."""
        from reporails_cli.core.templates import resolve_templates

        rule_path = create_temp_rule_file(tmp_path, rule_with_template_yaml)
        resolved = resolve_templates(rule_path, agent_config)

        assert "{{instruction_files}}" not in resolved, (
            f"Template {{{{instruction_files}}}} was not resolved!\nResolved content:\n{resolved}"
        )
        # Check that resolved values appear in output (as list items or regex)
        value = agent_config["instruction_files"]
        if isinstance(value, list):
            # At least one item should appear (as list item or in regex pattern)
            found = any(item in resolved or item.replace("**/", "") in resolved for item in value)
            assert found, f"Expected resolved values from {value} not found in output:\n{resolved}"
        else:
            assert value in resolved, f"Expected resolved value '{value}' not found in output:\n{resolved}"

    def test_has_templates_detects_placeholders(
        self,
        tmp_path: Path,
        rule_with_template_yaml: str,
        valid_rule_yaml: str,
    ) -> None:
        """has_templates() must correctly identify files with placeholders."""
        from reporails_cli.core.templates import has_templates

        with_template = create_temp_rule_file(tmp_path, rule_with_template_yaml, "with.yml")
        without_template = create_temp_rule_file(tmp_path, valid_rule_yaml, "without.yml")

        assert has_templates(with_template), f"Failed to detect template in:\n{rule_with_template_yaml}"
        assert not has_templates(without_template), f"False positive - detected template in:\n{valid_rule_yaml}"

    def test_empty_context_skips_resolution(
        self,
        tmp_path: Path,
        rule_with_template_yaml: str,
    ) -> None:
        """Empty template context should not attempt resolution.

        regression: Empty dict {} is falsy in Python, causing template
        resolution to be skipped entirely.
        """
        from reporails_cli.core.templates import resolve_templates

        rule_path = create_temp_rule_file(tmp_path, rule_with_template_yaml)

        # With empty context, templates remain unresolved
        resolved = resolve_templates(rule_path, {})
        assert "{{instruction_files}}" in resolved, "Empty context should leave templates unresolved"

    def test_run_regex_resolves_templates_before_execution(
        self,
        tmp_path: Path,
        temp_project: Path,
        rule_with_template_yaml: str,
        agent_config: dict[str, str],
    ) -> None:
        """run_validation must resolve templates before matching.

        This is the critical integration test - templates must be resolved
        before regex patterns are compiled and executed.
        """
        from reporails_cli.core.regex import run_validation

        rule_path = create_temp_rule_file(tmp_path, rule_with_template_yaml)

        # Run with template context - should resolve
        result = run_validation(
            [rule_path],
            temp_project,
            template_context=agent_config,
        )

        # Should get valid SARIF (not empty due to template error)
        assert "runs" in result, f"Expected SARIF output, got: {result}"

    # --- NEGATIVE TESTS ---

    def test_unresolved_template_produces_no_matches(
        self,
        tmp_path: Path,
        temp_project: Path,
        rule_with_template_yaml: str,
    ) -> None:
        """Unresolved {{...}} templates should not match any files."""
        from reporails_cli.core.regex import run_validation

        rule_path = create_temp_rule_file(tmp_path, rule_with_template_yaml)

        # Run with empty context (simulates missing agent config)
        result = run_validation(
            [rule_path],
            temp_project,
            template_context={},  # Empty - no resolution
        )

        # Should return valid structure with no results (unresolved templates match nothing)
        runs = result.get("runs", [])
        if runs:
            results = runs[0].get("results", [])
            assert not results, f"Unresolved template should produce no results, but got: {results}"

    def test_unresolvable_template_leaves_placeholder(
        self,
        tmp_path: Path,
        rule_with_unresolvable_template_yaml: str,
        agent_config: dict[str, str],
    ) -> None:
        """Templates without matching context keys remain unresolved."""
        from reporails_cli.core.templates import resolve_templates

        rule_path = create_temp_rule_file(tmp_path, rule_with_unresolvable_template_yaml)

        resolved = resolve_templates(rule_path, agent_config)

        # {{nonexistent_variable}} should remain because it's not in context
        assert "{{nonexistent_variable}}" in resolved, "Unresolvable template was incorrectly modified"

    def test_multiple_templates_all_resolve(
        self,
        tmp_path: Path,
        agent_config: dict[str, str],
    ) -> None:
        """All template placeholders in a file must resolve."""
        multi_template_yaml = """\
rules:
  - id: test-multi
    message: "Test"
    severity: WARNING
    languages: [generic]
    pattern-regex: "test"
    paths:
      include:
        - "{{instruction_files}}"
        - "{{rules_dir}}/**/*.md"
"""
        from reporails_cli.core.templates import resolve_templates

        rule_path = create_temp_rule_file(tmp_path, multi_template_yaml)
        resolved = resolve_templates(rule_path, agent_config)

        assert "{{instruction_files}}" not in resolved
        assert "{{rules_dir}}" not in resolved
        # Check instruction_files resolved (may be list)
        value = agent_config["instruction_files"]
        if isinstance(value, list):
            found = any(item in resolved for item in value)
            assert found, f"Expected one of {value} in resolved output"
        else:
            assert value in resolved
        assert agent_config["rules_dir"] in resolved


class TestTemplateContextLoading:
    """Test that template context is correctly loaded from agent config."""

    def test_get_agent_vars_returns_dict(self) -> None:
        """get_agent_vars must return a dict (even if empty)."""
        from reporails_cli.core.bootstrap import get_agent_vars

        result = get_agent_vars("claude")
        assert isinstance(result, dict), f"Expected dict, got {type(result)}"

    def test_get_agent_vars_claude_has_instruction_files(self) -> None:
        """Claude agent config must include instruction_files."""
        from reporails_cli.core.bootstrap import get_agent_vars

        result = get_agent_vars("claude")
        if not result:
            pytest.skip("Framework not installed (no agent config available)")
        assert "instruction_files" in result, (
            "Claude agent config missing 'instruction_files' - this will cause template resolution to fail silently"
        )

    def test_get_agent_vars_unknown_agent_returns_empty(self) -> None:
        """Unknown agent should return empty dict, not error."""
        from reporails_cli.core.bootstrap import get_agent_vars

        result = get_agent_vars("nonexistent_agent_xyz")
        assert result == {}, f"Expected empty dict for unknown agent, got: {result}"

    def test_empty_string_agent_returns_empty(self) -> None:
        """Empty string agent should return empty dict."""
        from reporails_cli.core.bootstrap import get_agent_vars

        result = get_agent_vars("")
        assert result == {}, f"Expected empty dict for empty agent, got: {result}"


class TestEngineTemplateIntegration:
    """Test that engine.py correctly passes template context to regex engine."""

    def test_engine_passes_template_context(
        self,
        level2_project: Path,
        dev_rules_dir: Path,
    ) -> None:
        """run_validation must pass template_context to the regex engine.

        regression: If agent="" then template_context={} which is falsy,
        causing templates to not be resolved.
        """
        from reporails_cli.core.engine import run_validation_sync

        # Run validation with explicit agent
        result = run_validation_sync(
            level2_project,
            agent="claude",
            rules_paths=[dev_rules_dir],
        )

        # Should complete without error
        assert result.score >= 0, "Validation should complete successfully"
        # Score should be reasonable (not 0 due to all rules failing)
        assert result.rules_checked > 0, "No rules were checked - possibly all failed due to template issues"
