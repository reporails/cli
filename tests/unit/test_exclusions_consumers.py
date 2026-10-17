"""The run's exclusion set reaches heal, the glob check, the section suggestions and the atom-cap route."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from reporails_cli.core.discovery.exclusions import load_run_exclusions
from reporails_cli.core.lint.mechanical.checks_advanced import frontmatter_valid_glob
from reporails_cli.core.pipeline.mapping import map_instruction_files
from reporails_cli.core.platform.adapters.payload import project_payload
from reporails_cli.core.platform.dto.models import ClassifiedFile
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.policy import preflight


class _Console:
    def print(self, *_a: Any, **_k: Any) -> None:
        pass


def _config(project: Path, body: str) -> None:
    (project / ".ails").mkdir(exist_ok=True)
    (project / ".ails" / "config.yml").write_text(body, encoding="utf-8")


def _gs_project(tmp_path: Path, big_lines: int = 0) -> Path:
    project = tmp_path / "proj"
    (project / "ext").mkdir(parents=True)
    _config(project, "generic_scanning: true\nexclude_dirs: [ext]\n")
    (project / "CLAUDE.md").write_text(
        "# Proj\n\nAlways run the tests before pushing.\n\n@ext/big.md\n", encoding="utf-8"
    )
    body = "".join(f"Always keep rule number {i} in mind when editing module {i}.\n\n" for i in range(big_lines or 3))
    (project / "ext" / "big.md").write_text(body, encoding="utf-8")
    return project


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_a_glob_excluded_rule_file_gets_no_glob_finding(tmp_path: Path) -> None:
    rules = tmp_path / ".claude" / "rules"
    rules.mkdir(parents=True)
    kept = rules / "kept.md"
    left_out = rules / "left.md"
    for f in (kept, left_out):
        f.write_text('---\npaths:\n  - "nothing/**/*.zzz"\n---\n\nBody.\n', encoding="utf-8")
    args = {"path": ".claude/rules", "require_matches": True}
    both = frontmatter_valid_glob(tmp_path, args, [])
    assert not both.passed
    assert {loc.split(":")[0] for loc, _ in both.occurrences} == {
        ".claude/rules/kept.md",
        ".claude/rules/left.md",
    }
    checked = [ClassifiedFile(path=kept, file_type="rules", properties={})]
    only = frontmatter_valid_glob(tmp_path, args, checked)
    assert {loc.split(":")[0] for loc, _ in only.occurrences} == {".claude/rules/kept.md"}


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_section_suggestions_classify_only_the_checked_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.interfaces.cli import heal as heal_cli
    from reporails_cli.interfaces.cli.heal import _collect_section_suggestions

    project = _gs_project(tmp_path)
    exclusions = load_run_exclusions(project)
    seen: list[list[ClassifiedFile]] = []
    monkeypatch.setattr(
        heal_cli, "suggest_missing_sections", lambda _v, _t, classified, _r: seen.append(classified) or []
    )
    _collect_section_suggestions(
        project,
        [project / "CLAUDE.md"],
        RulesetMap(schema_version="1", embedding_model="m", generated_at="t", files=(), atoms=()),
        "claude",
        show_progress=False,
        console=_Console(),
        exclusions=exclusions,
    )
    assert seen
    assert {cf.path.name for cf in seen[0]} == {"CLAUDE.md"}


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_the_heal_pass_receives_the_run_exclusions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from reporails_cli.interfaces.cli import check_flow

    exclusions = load_run_exclusions(tmp_path)
    seen: list[Any] = []
    monkeypatch.setattr(check_flow, "_run_heal_pass", lambda *a, **k: seen.append(a[1].exclusions))
    path = tmp_path / "CLAUDE.md"
    path.write_text("# Demo\n", encoding="utf-8")
    state = SimpleNamespace(
        inputs=SimpleNamespace(heal=True, dry_run=True),
        pipeline=SimpleNamespace(lint_result=None, funnel_error=None, ruleset_map=None, stage_timer=None),
        render=SimpleNamespace(
            heal_authed=True,
            capability_paths=set(),
            result=SimpleNamespace(reply=SimpleNamespace(notices=(), workflow=None)),
        ),
        scope=SimpleNamespace(instruction_files=[path], effective_agent="claude", exclusions=exclusions),
        targets=SimpleNamespace(single_path=None, target=tmp_path, output_format="text"),
    )
    check_flow._flow_heal(state)
    assert seen == [exclusions]


@pytest.mark.unit
@pytest.mark.requires_model
@pytest.mark.subsys_heal
def test_heal_apply_writes_only_files_the_run_mapped(tmp_path: Path) -> None:
    project = _gs_project(tmp_path)
    m = map_instruction_files(project, [project / "CLAUDE.md"], spawn_daemon=False)
    files = {Path(a.file_path).name for a in m.atoms}
    assert files == {"CLAUDE.md"}


def _route_fixture(tmp_path: Path) -> tuple[Path, int, int]:
    """A project whose `CLAUDE.md` imports `@ext/big.md`; the atoms with and without `ext/` as its own file."""
    project = _gs_project(tmp_path, big_lines=40)
    with_ext = map_instruction_files(project, [project / "CLAUDE.md", project / "ext" / "big.md"], spawn_daemon=False)
    alone = map_instruction_files(project, [project / "CLAUDE.md"], spawn_daemon=False)
    return project, len(project_payload(with_ext, project)["atoms"]), len(project_payload(alone, project)["atoms"])


@pytest.mark.unit
@pytest.mark.requires_model
@pytest.mark.subsys_funnel
def test_route_names_the_folder_whose_exclusion_brings_the_next_run_under_the_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project, n_with, n_alone = _route_fixture(tmp_path)
    assert n_with > n_alone
    monkeypatch.setattr(preflight, "UNIVERSAL_ATOM_CAP", n_alone)
    both = map_instruction_files(project, [project / "CLAUDE.md", project / "ext" / "big.md"], spawn_daemon=False)
    err = preflight.preflight_oversized(project_payload(both, project), has_api_key=False)
    assert err is not None
    assert err.exclude_route == ("ext",)
    # The next run, with `ext` left out, checks CLAUDE.md alone (the import still counts inside it).
    next_run = map_instruction_files(project, [project / "CLAUDE.md"], spawn_daemon=False)
    assert preflight.preflight_oversized(project_payload(next_run, project), has_api_key=False) is None


@pytest.mark.unit
@pytest.mark.requires_model
@pytest.mark.subsys_funnel
def test_spliced_bulk_alone_over_the_cap_names_no_folder(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project, _n_with, n_alone = _route_fixture(tmp_path)
    monkeypatch.setattr(preflight, "UNIVERSAL_ATOM_CAP", n_alone - 1)
    alone = map_instruction_files(project, [project / "CLAUDE.md"], spawn_daemon=False)
    err = preflight.preflight_oversized(project_payload(alone, project), has_api_key=False)
    assert err is not None
    assert err.exclude_route == ()
