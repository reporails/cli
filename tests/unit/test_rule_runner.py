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
def test_the_regex_scan_sees_every_file_the_run_hands_it_whatever_the_exclusions_say(
    dev_rules_dir: Path, tmp_path: Path
) -> None:
    """The regex scan has one source, the file list of the run: a file in a folder the config names, and one in a
    folder only the `--exclude-dirs` flag names, are both scanned when the run hands them over."""
    from reporails_cli.core.discovery.exclusions import parse_run_exclusions
    from reporails_cli.core.lint.rule_runner import run_m_probes

    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.yml").write_text("exclude_dirs:\n  - from-config\n", encoding="utf-8")
    named = []
    for folder in ("from-config", "from-flag", "plain"):
        (tmp_path / folder).mkdir()
        named.append(tmp_path / folder / "CLAUDE.md")
        named[-1].write_text("# Notes\n\nTODO: fix this later.\n", encoding="utf-8")
    flags = parse_run_exclusions(tmp_path, ["from-flag"], ())

    findings = run_m_probes(RunContext(), tmp_path, named, agent="claude", exclusions=flags)

    ephemeral = {Path(f.file).parent.name for f in findings if f.rule == "CORE:C:0029"}
    assert ephemeral == {"from-config", "from-flag", "plain"}


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("config_folder", "scanned"),
    [(".", False), ("b", True)],
    ids=["root-config-excludes-a", "config-in-the-files-folder-is-not-read"],
)
def test_a_file_target_reads_the_project_roots_exclusions_for_the_files_its_links_reach(
    dev_rules_dir: Path, tmp_path: Path, config_folder: str, scanned: bool
) -> None:
    """`b/CLAUDE.md` links `a/x.md`. The project root's `exclude_dirs: [a]` keeps the linked file out of the
    deterministic scan; the same setting in `b/.ails/config.yml`, the named file's own folder, does not."""
    from reporails_cli.core.discovery.exclusions import load_run_exclusions
    from reporails_cli.core.lint.rule_runner import run_m_probes
    from reporails_cli.core.pipeline.check_one import resolve_scan_target

    (tmp_path / ".ails").mkdir()
    (tmp_path / ".ails" / "config.yml").write_text("generic_scanning: true\n", encoding="utf-8")
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "x.md").write_text("# X\n\nTODO: fix this later.\n", encoding="utf-8")
    (tmp_path / "b" / ".ails").mkdir(parents=True)
    named = tmp_path / "b" / "CLAUDE.md"
    named.write_text("# B\n\nSee [x](../a/x.md) for more.\n", encoding="utf-8")
    holder = tmp_path / config_folder / ".ails" / "config.yml"
    holder.write_text("generic_scanning: true\nexclude_dirs:\n  - a\n", encoding="utf-8")

    run = RunContext()
    scan_root, _ = resolve_scan_target(named, tmp_path)
    findings = run_m_probes(
        run, scan_root, [named], agent="claude", scoped=True, exclusions=load_run_exclusions(run, scan_root)
    )

    reached = {Path(f.file).parent.name for f in findings if f.rule == "CORE:C:0029"}
    assert reached == ({"a"} if scanned else set())
