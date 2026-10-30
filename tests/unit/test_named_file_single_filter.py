"""Discovery filters each agent's files once with the run's exclusions: a named file stays, a left-out path
(also through a symlink) goes, and the Excluded record is the exclusion set's own."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.pipeline import check_one
from reporails_cli.core.pipeline.mapping import agent_file_pairs, discover_scope
from reporails_cli.interfaces.cli import check_flow
from reporails_cli.interfaces.cli.check_flow import CheckInputs, CheckState

RULE = "---\npaths:\n  - 'src/**'\n---\n\n# A\n\nUse type hints on every function.\n"
SKILL = "---\nname: foo\ndescription: Does foo.\n---\n\nRun foo.\n"


@pytest.fixture(autouse=True)
def _fresh(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    clear_agent_cache()


def _project(tmp_path: Path, config: str | None = None) -> Path:
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# Project\n\nRun the tests with pytest.\n", encoding="utf-8")
    rule = root / ".claude" / "rules" / "a.md"
    rule.parent.mkdir(parents=True)
    rule.write_text(RULE, encoding="utf-8")
    (root / ".claude" / "settings.json").write_text('{"permissions": {"allow": []}}\n', encoding="utf-8")
    if config is not None:
        (root / ".ails").mkdir()
        (root / ".ails" / "config.yml").write_text(config, encoding="utf-8")
    return root


def _state(
    project: Path, targets: list[str], dirs: list[str] | None = None, files: list[str] | None = None
) -> CheckState:
    state = CheckState(
        inputs=CheckInputs(
            targets=targets,
            format_opt="json",
            agent="",
            exclude_dirs=dirs,
            exclude_files=files,
            ascii_mode=True,
            strict=False,
            verbose=False,
            heal=False,
            dry_run=False,
            cwd=False,
            project_root=project,
        )
    )
    check_flow._flow_targets(state)
    assert check_flow._flow_scope(state)
    return state


def _rule_files(filtered: list) -> set[Path]:
    return {safe_resolve(f) for a in filtered if a.agent_type.id == "claude" for f in a.rule_files}


def _owner_of(filtered: list, project: Path, rule: Path) -> str:
    pairs = agent_file_pairs([rule], filtered, project, explicit=False, effective_agent="claude")
    return next(owner for owner, files in pairs if rule in files)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_single_file_in_a_flag_left_out_folder_keeps_its_agent_and_list(tmp_path: Path) -> None:
    project = _project(tmp_path)
    rule = project / ".claude" / "rules" / "a.md"
    plain = _state(project, [str(rule)])
    left_out = _state(project, [str(rule)], dirs=["rules"])
    assert safe_resolve(rule) in _rule_files(left_out.scope.filtered)
    assert _rule_files(left_out.scope.filtered) == _rule_files(plain.scope.filtered)
    assert _owner_of(left_out.scope.filtered, project, safe_resolve(rule)) == "claude"
    assert left_out.scope.instruction_files == plain.scope.instruction_files
    assert left_out.render.excluded == ((), ())


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_single_file_in_a_config_left_out_folder_lands_in_rule_files(tmp_path: Path) -> None:
    project = _project(tmp_path, "exclude_dirs: [rules]\n")
    rule = project / ".claude" / "rules" / "a.md"
    state = _state(project, [str(rule)])
    assert safe_resolve(rule) in _rule_files(state.scope.filtered)
    assert _owner_of(state.scope.filtered, project, safe_resolve(rule)) == "claude"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mcp_single_file_in_a_left_out_folder_lands_in_rule_files(tmp_path: Path) -> None:
    project = _project(tmp_path, "exclude_dirs: [rules]\n")
    rule = project / ".claude" / "rules" / "a.md"
    result = check_one.discover_files(project, single_file=rule)
    assert isinstance(result, check_one.Discovered)
    filter_agents, files = result.filter_agents, result.instruction_files
    assert safe_resolve(rule) in _rule_files(filter_agents)
    assert files == [safe_resolve(rule)]
    assert _owner_of(filter_agents, project, safe_resolve(rule)) == "claude"


def _symlinked(tmp_path: Path) -> tuple[Path, Path]:
    project = _project(tmp_path)
    real = project / ".agents" / "skills" / "foo"
    real.mkdir(parents=True)
    (real / "SKILL.md").write_text(SKILL, encoding="utf-8")
    (project / ".claude" / "skills").symlink_to(Path("..") / ".agents" / "skills")
    return project, project / ".claude" / "skills" / "foo" / "SKILL.md"


def _listed(found) -> set[Path]:
    return {safe_resolve(f) for f in found.files} | {
        safe_resolve(f) for a in found.filtered for f in (*a.instruction_files, *a.rule_files, *a.config_files)
    }


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_symlinked_folder_left_out_by_its_real_name_is_not_discovered(tmp_path: Path) -> None:
    project, skill = _symlinked(tmp_path)
    assert safe_resolve(skill) in _listed(discover_scope(project, "", None, None))
    found = discover_scope(project, "", [".agents"], None)
    assert safe_resolve(skill) not in _listed(found)
    kept = discover_scope(project, "", [".agents"], None, named=frozenset({skill}))
    assert safe_resolve(skill) in _listed(kept)


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("flag_dirs", "flag_files", "config"),
    [
        (["rules"], None, None),
        (None, None, "exclude_dirs: [rules]\n"),
        (None, [".claude/rules/*.md"], None),
        (None, None, "exclude_files:\n  - '.claude/rules/*.md'\n"),
        ([".agents"], None, None),
    ],
)
def test_nothing_discovered_is_left_out(
    tmp_path: Path, flag_dirs: list[str] | None, flag_files: list[str] | None, config: str | None
) -> None:
    project, _skill = _symlinked(tmp_path)
    if config:
        (project / ".ails").mkdir()
        (project / ".ails" / "config.yml").write_text(config, encoding="utf-8")
    found = discover_scope(project, "", flag_dirs, flag_files)
    assert found.exclusions is not None
    assert found.files
    assert not any(found.exclusions.leaves_out(f) for f in found.files)
    assert not any(found.exclusions.leaves_out(f) for f in _listed(found))


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_config_surface_in_a_left_out_folder_is_not_checked(tmp_path: Path) -> None:
    project = _project(tmp_path)
    settings = project / ".claude" / "settings.json"
    assert safe_resolve(settings) in _listed(discover_scope(project, "", None, None))
    found = discover_scope(project, "", [".claude"], None)
    assert safe_resolve(settings) not in _listed(found)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_record_of_a_run_naming_a_file_is_the_exclusion_sets_own(tmp_path: Path) -> None:
    project = _project(tmp_path)
    rule = project / ".claude" / "rules" / "a.md"
    state = _state(project, [str(project / "CLAUDE.md"), str(rule)], dirs=["rules", "vendor"])
    assert state.scope.exclusions is not None
    assert state.render.excluded == state.scope.exclusions.record(narrowed=True)
    assert state.render.excluded == (("vendor",), ())
    single = _state(project, [str(rule)], dirs=["rules"])
    assert single.render.excluded == ((), ())
