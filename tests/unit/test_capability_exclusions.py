"""A capability spec under the run's exclusions: listing every instance leaves out excluded folders and
files, while a file or capability the user names is checked whatever is excluded."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.classify.capability_paths import list_capability_targets
from reporails_cli.core.classify.focus_expansion import expand_focus, resolve_capability_spec
from reporails_cli.core.discovery.exclusions import load_run_exclusions
from reporails_cli.interfaces.cli import check_flow
from reporails_cli.interfaces.cli.check_flow import CheckInputs, CheckState

BACKLOG_GLOB = ".claude/skills/backlog/SKILL.md"


def _config(project: Path, text: str) -> None:
    (project / ".ails").mkdir(exist_ok=True)
    (project / ".ails" / "config.yml").write_text(text, encoding="utf-8")


@pytest.fixture
def project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# Project\n\nRun the tests with pytest.\n", encoding="utf-8")
    for name in ("backlog", "other"):
        skill = root / ".claude" / "skills" / name
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(f"---\nname: {name}\ndescription: Does {name}.\n---\n\n# {name}\n", "utf-8")
    return root


def _scope(
    project: Path,
    targets: list[str],
    exclude_dirs: list[str] | None = None,
    exclude_files: list[str] | None = None,
) -> CheckState | None:
    """Run the flow's target and scope phases; the state, or None when the run ended empty."""
    state = CheckState(
        inputs=CheckInputs(
            targets=targets,
            format_opt="json",
            agent="claude",
            exclude_dirs=exclude_dirs,
            exclude_files=exclude_files,
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
    return state if check_flow._flow_scope(state) else None


def _names(state: CheckState) -> set[str]:
    return {f.parent.name if f.name == "SKILL.md" else f.name for f in state.scope.instruction_files}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_listing_leaves_out_a_flag_file_glob(project: Path) -> None:
    exclusions = load_run_exclusions(project, None, [BACKLOG_GLOB])
    listed = list_capability_targets("claude", "skills", project, exclusions)
    assert [p.parent.name for p in listed] == ["other"]
    spec, _ = resolve_capability_spec("skills", "", "claude", project, exclusions)
    assert {p.parent.name for p in spec} == {"other"}


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_listing_with_no_run_args_honors_config_exclude_files(project: Path) -> None:
    _config(project, f"exclude_files:\n  - {BACKLOG_GLOB}\n")
    assert [p.parent.name for p in list_capability_targets("claude", "skills", project)] == ["other"]
    assert [p.parent.name for p in list_capability_targets("claude", "skills", project, None)] == ["other"]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_listing_leaves_out_a_flag_folder_and_a_config_folder(project: Path) -> None:
    assert [
        p.parent.name
        for p in list_capability_targets("claude", "skills", project, load_run_exclusions(project, ["backlog"]))
    ] == ["other"]
    _config(project, "exclude_dirs:\n  - backlog\n")
    assert [p.parent.name for p in list_capability_targets("claude", "skills", project)] == ["other"]


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_listing_with_a_file_glob_checks_the_rest_and_records_the_glob(project: Path) -> None:
    state = _scope(project, ["skills"], exclude_files=[BACKLOG_GLOB])
    assert state is not None
    assert _names(state) == {"other"}
    assert state.render.excluded == ((), (BACKLOG_GLOB,))


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_listing_with_a_flag_folder_records_the_folder(project: Path) -> None:
    state = _scope(project, ["skills"], exclude_dirs=["backlog"])
    assert state is not None
    assert _names(state) == {"other"}
    assert state.render.excluded == (("backlog",), ())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_listing_with_a_config_folder_records_the_folder(project: Path) -> None:
    _config(project, "exclude_dirs:\n  - backlog\n")
    state = _scope(project, ["skills"])
    assert state is not None
    assert _names(state) == {"other"}
    assert state.render.excluded == (("backlog",), ())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_listing_with_a_config_file_glob_leaves_it_out(project: Path) -> None:
    _config(project, f"exclude_files:\n  - {BACKLOG_GLOB}\n")
    state = _scope(project, ["skills"])
    assert state is not None
    assert _names(state) == {"other"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("config", "flags"),
    [
        (None, {"exclude_dirs": ["backlog"]}),
        ("exclude_dirs:\n  - backlog\n", {}),
        (None, {"exclude_files": [BACKLOG_GLOB]}),
        (f"exclude_files:\n  - {BACKLOG_GLOB}\n", {}),
    ],
)
def test_naming_an_excluded_instance_checks_it_and_drops_its_pattern_from_the_record(
    project: Path, config: str | None, flags: dict[str, list[str]]
) -> None:
    if config:
        _config(project, config)
    state = _scope(project, ["skills:backlog"], **flags)
    assert state is not None
    assert _names(state) == {"backlog"}
    assert state.render.excluded == ((), ())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_naming_an_instance_that_is_not_excluded_checks_it_and_records_the_rest(project: Path) -> None:
    state = _scope(project, ["skills:backlog"], exclude_dirs=["vendor"])
    assert state is not None
    assert _names(state) == {"backlog"}
    assert state.render.excluded == (("vendor",), ())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_explicit_path_to_an_excluded_file_still_checks_it(project: Path) -> None:
    state = _scope(project, [str(project / BACKLOG_GLOB)], exclude_dirs=["backlog"], exclude_files=[BACKLOG_GLOB])
    assert state is not None
    assert _names(state) == {"backlog"}
    assert state.render.excluded == ((), ())


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_listing_whose_every_file_is_excluded_is_an_empty_run(project: Path) -> None:
    assert _scope(project, ["skills"], exclude_files=[".claude/skills/**/SKILL.md"]) is None
    assert _scope(project, ["skills"], exclude_dirs=["skills"]) is None


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_preloaded_skill_the_exclusions_leave_out_is_dropped_without_a_missing_warning(project: Path) -> None:
    agent = project / ".claude" / "agents" / "writer.md"
    agent.parent.mkdir(parents=True)
    agent.write_text("---\nname: writer\ndescription: Writes.\nskills:\n  - backlog\n  - other\n---\n\n# w\n", "utf-8")
    exclusions = load_run_exclusions(project, ["backlog"])
    paths, unresolved = resolve_capability_spec("agents", "writer", "claude", project, exclusions)
    assert {p.parent.name if p.name == "SKILL.md" else p.name for p in paths} == {"writer.md", "other"}
    assert unresolved == []
    state = _scope(project, ["agents:writer"], exclude_dirs=["backlog"])
    assert state is not None
    assert _names(state) == {"writer.md", "other"}
    assert state.render.excluded == (("backlog",), ())
    agent.write_text("---\nname: writer\ndescription: Writes.\nskills:\n  - ghost\n---\n\n# w\n", "utf-8")
    _, unresolved = expand_focus({agent}, "claude", project, exclusions)
    assert [u.skill_name for u in unresolved] == ["ghost"]


@pytest.mark.unit
@pytest.mark.subsys_server
def test_mcp_validate_targets_follow_the_same_rules(project: Path) -> None:
    from reporails_cli.interfaces.mcp import validate_targets

    _config(project, f"exclude_dirs:\n  - backlog\nexclude_files:\n  - {BACKLOG_GLOB}\n")
    root = project.resolve()
    named = validate_targets.resolve_validate_targets(("skills:backlog",), root)
    assert not isinstance(named, dict)
    assert {p.parent.name for p in named[0]} == {"backlog"}
    listed = validate_targets.resolve_validate_targets(("skills",), root)
    assert not isinstance(listed, dict)
    assert {p.parent.name for p in listed[0]} == {"other"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_auto_detect_gives_a_named_config_excluded_skill_to_its_native_owner(project: Path) -> None:
    from reporails_cli.core.discovery.agents import partition_by_native_owner

    _config(project, "exclude_dirs:\n  - backlog\n")
    state = CheckState(
        inputs=CheckInputs(
            targets=["skills:backlog"],
            format_opt="json",
            agent="",
            exclude_dirs=None,
            exclude_files=None,
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
    assert _names(state) == {"backlog"}
    owners = partition_by_native_owner(state.scope.filtered, project)
    skill = next(f for f in state.scope.instruction_files if f.name == "SKILL.md")
    assert owners[skill.as_posix()] == "claude"


@pytest.mark.unit
@pytest.mark.subsys_server
def test_mcp_and_cli_name_the_same_files_under_the_same_tokens(project: Path) -> None:
    from reporails_cli.interfaces.mcp import validate_targets

    _config(project, "exclude_dirs:\n  - backlog\n")
    root = project.resolve()
    for token, expected in (("skills:backlog", {"backlog"}), ("skills", {"other"})):
        state = _scope(project, [token])
        assert state is not None
        mcp = validate_targets.resolve_validate_targets((token,), root)
        assert not isinstance(mcp, dict)
        assert {p.parent.name for p in mcp[0]} == expected == _names(state)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_rules_capabilities_count_matches_what_check_skills_checks(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reporails_cli.interfaces.cli.main import app

    _config(project, f"exclude_files:\n  - {BACKLOG_GLOB}\n")
    monkeypatch.chdir(project)
    listed = list_capability_targets("claude", "skills", project)
    state = _scope(project, ["skills"])
    assert state is not None
    assert len(listed) == len([f for f in state.scope.instruction_files if f.name == "SKILL.md"]) == 1
    result = CliRunner().invoke(app, ["rules", "capabilities", "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0
    found = {r["name"]: r["found"] for r in json.loads(result.output)["resolution"]}
    assert found["skills"] == len(listed)


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_referenced_listing_honors_a_flag_folder(project: Path) -> None:
    (project / "ext").mkdir()
    (project / "ext" / "x.md").write_text("# X\n", "utf-8")
    (project / "CLAUDE.md").write_text("# Project\n\nSee [x](ext/x.md).\n", "utf-8")
    _config(project, "generic_scanning: true\n")
    kept = list_capability_targets("claude", "referenced", project, load_run_exclusions(project, ["ext"]))
    assert all("ext" not in p.parts for p in kept)
    assert [p.name for p in list_capability_targets("claude", "referenced", project, load_run_exclusions(project))] == [
        "x.md"
    ]


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_referenced_target_checks_the_file_no_agent_lists(project: Path) -> None:
    (project / "ext").mkdir()
    (project / "ext" / "x.md").write_text("# X\n", "utf-8")
    (project / "CLAUDE.md").write_text("# Project\n\nSee [x](ext/x.md).\n", "utf-8")
    _config(project, "generic_scanning: true\n")
    state = _scope(project, ["referenced"])
    assert state is not None
    assert _names(state) == {"x.md"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_naming_a_file_in_an_excluded_folder_beside_the_main_file_checks_both(project: Path) -> None:
    (project / "ext").mkdir()
    (project / "ext" / "x.md").write_text("# X\n\nNotes.\n", "utf-8")
    state = _scope(project, [str(project / "CLAUDE.md"), str(project / "ext" / "x.md")], exclude_dirs=["ext"])
    assert state is not None
    assert _names(state) == {"CLAUDE.md", "x.md"}
    assert state.render.excluded == ((), ())
