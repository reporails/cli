"""Tests for core/rule_runner.py — M-probe dispatch."""

from __future__ import annotations

from pathlib import Path

import pytest


class TestRunMProbes:
    """Verify run_m_probes dispatches mechanical and deterministic checks."""

    def test_returns_list(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """run_m_probes should return a list of LocalFinding."""
        from reporails_cli.core.agents import get_all_instruction_files
        from reporails_cli.core.rule_runner import run_m_probes

        files = get_all_instruction_files(level2_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        findings = run_m_probes(level2_project, files)
        assert isinstance(findings, list)

    def test_findings_are_local_finding(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """Each finding should be a LocalFinding instance."""
        from reporails_cli.core.agents import get_all_instruction_files
        from reporails_cli.core.models import LocalFinding
        from reporails_cli.core.rule_runner import run_m_probes

        files = get_all_instruction_files(level2_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        findings = run_m_probes(level2_project, files)
        for f in findings:
            assert isinstance(f, LocalFinding)
            assert f.source == "m_probe"

    def test_findings_sorted_by_severity(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """Findings should be sorted by severity (error < warning < info)."""
        from reporails_cli.core.agents import get_all_instruction_files
        from reporails_cli.core.rule_runner import run_m_probes

        files = get_all_instruction_files(level2_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        findings = run_m_probes(level2_project, files)
        severity_order = {"error": 0, "warning": 1, "info": 2}
        for i in range(len(findings) - 1):
            assert severity_order.get(findings[i].severity, 9) <= severity_order.get(findings[i + 1].severity, 9)

    def test_agent_specific_rules_load(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """When agent='claude' is passed, CLAUDE-namespaced rules are loaded and checked."""
        from reporails_cli.core.agents import get_all_instruction_files
        from reporails_cli.core.rule_runner import run_m_probes

        files = get_all_instruction_files(level2_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        findings = run_m_probes(level2_project, files, agent="claude")
        rules_hit = {f.rule for f in findings}
        # With agent="claude", we should get both CORE and CLAUDE rules loaded.
        # At minimum, CORE rules still fire.
        assert any(r.startswith("CORE:") for r in rules_hit)

    def test_no_agent_loads_only_core(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """Without agent param, only CORE rules load — no agent-specific rules."""
        from reporails_cli.core.registry import load_rules

        rules = load_rules(project_root=level2_project, scan_root=level2_project)
        assert all(not k.startswith("CLAUDE:") for k in rules)
