"""Tests for core/rule_runner.py — M-probe dispatch."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.exclusions import load_run_exclusions
from reporails_cli.core.platform.config.run_context import RunContext


class TestRunMProbes:
    """Verify run_m_probes dispatches mechanical and deterministic checks."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_returns_list(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """run_m_probes should return a list of LocalFinding."""
        from reporails_cli.core.discovery.agents import get_all_instruction_files
        from reporails_cli.core.lint.rule_runner import run_m_probes

        files = get_all_instruction_files(RunContext(), level2_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        findings = run_m_probes(
            RunContext(), level2_project, files, exclusions=load_run_exclusions(RunContext(), level2_project)
        )
        assert isinstance(findings, list)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_findings_are_local_finding(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """Each finding should be a LocalFinding instance."""
        from reporails_cli.core.discovery.agents import get_all_instruction_files
        from reporails_cli.core.lint.rule_runner import run_m_probes
        from reporails_cli.core.platform.dto.models import LocalFinding

        files = get_all_instruction_files(RunContext(), level2_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        findings = run_m_probes(
            RunContext(), level2_project, files, exclusions=load_run_exclusions(RunContext(), level2_project)
        )
        for f in findings:
            assert isinstance(f, LocalFinding)
            assert f.source == "m_probe"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_findings_sorted_by_severity(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """Findings should be sorted by severity (error < warning < info)."""
        from reporails_cli.core.discovery.agents import get_all_instruction_files
        from reporails_cli.core.lint.rule_runner import run_m_probes

        files = get_all_instruction_files(RunContext(), level2_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        findings = run_m_probes(
            RunContext(), level2_project, files, exclusions=load_run_exclusions(RunContext(), level2_project)
        )
        severity_order = {"error": 0, "warning": 1, "info": 2}
        for i in range(len(findings) - 1):
            assert severity_order.get(findings[i].severity, 9) <= severity_order.get(findings[i + 1].severity, 9)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_agent_specific_rules_load(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """When agent='claude' is passed, CLAUDE-namespaced rules are loaded and checked."""
        from reporails_cli.core.discovery.agents import get_all_instruction_files
        from reporails_cli.core.lint.rule_runner import run_m_probes

        files = get_all_instruction_files(RunContext(), level2_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        findings = run_m_probes(
            RunContext(),
            level2_project,
            files,
            agent="claude",
            exclusions=load_run_exclusions(RunContext(), level2_project),
        )
        rules_hit = {f.rule for f in findings}
        # With agent="claude", we should get both CORE and CLAUDE rules loaded.
        # At minimum, CORE rules still fire.
        assert any(r.startswith("CORE:") for r in rules_hit)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_no_agent_loads_only_core(self, dev_rules_dir: Path, level2_project: Path) -> None:
        """Without agent param, only CORE rules load — no agent-specific rules."""
        from reporails_cli.core.platform.rules.registry import load_rules

        rules = load_rules(
            project=RunContext().configured_root(level2_project), scan=RunContext().configured_root(level2_project)
        )
        assert all(not k.startswith("CLAUDE:") for k in rules)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_scoped_skips_project_shape_rule(self, dev_rules_dir: Path, level1_project: Path) -> None:
        """A single-file scoped run must not fire CORE:S:0010 (project needs ≥2 files)."""
        from reporails_cli.core.discovery.agents import get_all_instruction_files
        from reporails_cli.core.lint.rule_runner import run_m_probes

        files = get_all_instruction_files(RunContext(), level1_project)
        if not files:
            pytest.skip("No instruction files in fixture")
        unscoped = {
            f.rule
            for f in run_m_probes(
                RunContext(),
                level1_project,
                files,
                scoped=False,
                exclusions=load_run_exclusions(RunContext(), level1_project),
            )
        }
        scoped = {
            f.rule
            for f in run_m_probes(
                RunContext(),
                level1_project,
                files,
                scoped=True,
                exclusions=load_run_exclusions(RunContext(), level1_project),
            )
        }
        assert "CORE:S:0010" in unscoped  # whole-project enforcement still fires
        assert "CORE:S:0010" not in scoped  # narrowed subset must not misfire


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_the_regex_scan_gets_the_config_exclusions_never_the_flag_exclusions(
    dev_rules_dir: Path, level2_project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A folder named only by `--exclude-dirs` stays in the regex scan; one the config names stays out."""
    from reporails_cli.core.discovery.agents import get_all_instruction_files
    from reporails_cli.core.discovery.exclusions import parse_run_exclusions
    from reporails_cli.core.lint import rule_runner
    from reporails_cli.core.platform.dto.discovery import RunExclusions

    (level2_project / ".ails").mkdir(exist_ok=True)
    (level2_project / ".ails" / "config.yml").write_text("exclude_dirs:\n  - from-config\n", encoding="utf-8")
    files = get_all_instruction_files(RunContext(), level2_project)
    if not files:
        pytest.skip("No instruction files in fixture")
    seen: list[RunExclusions] = []

    def _record(_yml: list[Path], _target: Path, exclusions: RunExclusions, **_kw: object) -> list[object]:
        seen.append(exclusions)
        return []

    monkeypatch.setattr(rule_runner, "run_checks", _record)
    flags = parse_run_exclusions(level2_project, ["from-flag"], ())
    rule_runner.run_m_probes(RunContext(), level2_project, files, exclusions=flags)
    assert seen
    assert all([d.text for d in e.dirs] == ["from-config"] for e in seen)
