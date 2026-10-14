"""Mechanical checks resolve their targets under the run's exclusion set."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.lint.mechanical.checks_absent import file_absent
from reporails_cli.core.lint.rule_runner import run_m_probes
from reporails_cli.core.pipeline.mapping import discover_scope

pytestmark = [pytest.mark.unit, pytest.mark.subsys_lint]


def _project(tmp_path: Path, config: str = "") -> tuple[Path, Path]:
    project = tmp_path / "proj"
    (project / ".ails").mkdir(parents=True)
    if config:
        (project / ".ails" / "config.yml").write_text(config, encoding="utf-8")
    (project / "CLAUDE.md").write_text("# proj\n\nAlways run the tests.\n", encoding="utf-8")
    skill = project / ".claude" / "skills" / "foo" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("---\nname: foo\ndescription: Does foo.\n---\n\nRun foo.\n", encoding="utf-8")
    return project, skill


def test_named_skill_in_left_out_folder_is_not_reported_missing(tmp_path: Path) -> None:
    project, skill = _project(tmp_path, "exclude_dirs: [skills]\n")
    clear_agent_cache()
    scope = discover_scope(project, "claude", None, None, scan_files=False, named=frozenset({skill}))
    findings = run_m_probes(project, [skill], agent="claude", scoped=True, exclusions=scope.exclusions)
    assert not [f for f in findings if "No matching files found" in f.message]


def test_flag_folder_and_config_folder_give_the_same_findings(tmp_path: Path) -> None:
    by_config, _ = _project(tmp_path / "a", "exclude_dirs: [skills]\n")
    by_flag, _ = _project(tmp_path / "b")
    results = []
    for project, flags in ((by_config, None), (by_flag, ["skills"])):
        clear_agent_cache()
        scope = discover_scope(project, "claude", flags, None)
        findings = run_m_probes(project, list(scope.files), agent="claude", exclusions=scope.exclusions)
        results.append({(f.rule, f.file, f.line, f.message) for f in findings})
    assert results[0] == results[1]


def test_rule_paths_glob_matches_files_inside_a_left_out_folder(tmp_path: Path) -> None:
    project, _ = _project(tmp_path, "exclude_dirs: [packages]\n")
    (project / "packages" / "api").mkdir(parents=True)
    (project / "packages" / "api" / "x.py").write_text("x = 1\n", encoding="utf-8")
    rule = project / ".claude" / "rules" / "api.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("---\npaths:\n  - packages/api/**\n---\n\nKeep the api small.\n", encoding="utf-8")
    clear_agent_cache()
    scope = discover_scope(project, "claude", None, None)
    findings = run_m_probes(project, list(scope.files), agent="claude", exclusions=scope.exclusions)
    assert not [f for f in findings if "matches no file" in f.message]


def test_file_absent_ignores_a_forbidden_file_in_a_left_out_folder(tmp_path: Path) -> None:
    (tmp_path / "vendored").mkdir()
    (tmp_path / "vendored" / "BAD.md").write_text("x\n", encoding="utf-8")
    left_out = RunExclusions(root=tmp_path, dirs=frozenset({"vendored"}), walk_dirs=frozenset({"vendored"}))
    args = {"pattern": "**/BAD.md", "_exclusions": left_out}
    assert file_absent(tmp_path, args, []).passed
    kept = RunExclusions.none(tmp_path)
    assert not file_absent(tmp_path, {"pattern": "**/BAD.md", "_exclusions": kept}, []).passed
