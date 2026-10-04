"""A Codex fallback instruction file named in the project config is detected and checked."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.discovery.agents import clear_agent_cache, detect_agents, detect_single_agent
from reporails_cli.core.lint.rule_runner import _classify_agent_files


def _project(root: Path, *, agents_md: bool) -> Path:
    (root / ".git").mkdir()
    (root / "TEAM_GUIDE.md").write_text("# Team guide\n\nRun `make test` before committing.\n")
    if agents_md:
        (root / "AGENTS.md").write_text("# Agents\n")
        (root / ".codex").mkdir()
        (root / ".codex" / "config.toml").write_text("# codex marker\n")
    (root / ".ails").mkdir()
    (root / ".ails" / "config.yml").write_text(
        'schema_version: "0.1.0"\nagents:\n  codex:\n    fallback_filenames: ["TEAM_GUIDE.md"]\n'
    )
    return root


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fallback_file_alone_makes_the_project_a_codex_project(tmp_path: Path) -> None:
    clear_agent_cache()
    _project(tmp_path, agents_md=False)

    detected = detect_agents(tmp_path)

    assert [a.agent_type.id for a in detected] == ["codex"]
    assert [p.name for p in detected[0].instruction_files] == ["TEAM_GUIDE.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fallback_file_is_kept_when_files_are_classified_for_rules(tmp_path: Path) -> None:
    clear_agent_cache()
    _project(tmp_path, agents_md=True)
    files = [tmp_path / "AGENTS.md", tmp_path / "TEAM_GUIDE.md"]

    classified, _generic = _classify_agent_files(tmp_path, files, "codex")

    assert {cf.path.name: cf.file_type for cf in classified} == {"AGENTS.md": "main", "TEAM_GUIDE.md": "main"}


def _rel(root: Path, files: list[Path]) -> list[str]:
    return sorted(str(p.relative_to(root)) for p in files)


def _codex_files(root: Path, *, single: bool) -> list[str]:
    clear_agent_cache()
    if single:
        found = detect_single_agent(root, "codex")
        return _rel(root, found.instruction_files) if found else []
    return next((_rel(root, a.instruction_files) for a in detect_agents(root) if a.agent_type.id == "codex"), [])


def _nested_project(root: Path, *, codex_marker: bool, nested_agents_md: bool = False) -> Path:
    _project(root, agents_md=codex_marker)
    (root / "TEAM_GUIDE.md").unlink()
    if not codex_marker:
        (root / "AGENTS.md").write_text("# Agents\n")
    (root / "services" / "api").mkdir(parents=True)
    (root / "services" / "api" / "TEAM_GUIDE.md").write_text("# API guide\n\nRun `make api`.\n")
    if nested_agents_md:
        (root / "services" / "api" / "AGENTS.md").write_text("# API agents\n")
    return root


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("single", [False, True])
def test_fallback_file_beside_agents_md_is_not_listed(tmp_path: Path, single: bool) -> None:
    _project(tmp_path, agents_md=True)

    assert _codex_files(tmp_path, single=single) == ["AGENTS.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fallback_file_beside_agents_md_without_codex_folder_is_not_listed(tmp_path: Path) -> None:
    _project(tmp_path, agents_md=True)
    for entry in (tmp_path / ".codex").iterdir():
        entry.unlink()
    (tmp_path / ".codex").rmdir()
    clear_agent_cache()

    listed = {p.name for a in detect_agents(tmp_path) for p in a.instruction_files}

    assert "TEAM_GUIDE.md" not in listed
    # The project's own config names Codex, so the project is a Codex project even without `.codex/`.
    assert [a.agent_type.id for a in detect_agents(tmp_path)] == ["codex"]
    assert _codex_files(tmp_path, single=True) == ["AGENTS.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fallback_file_beside_agents_override_is_not_listed(tmp_path: Path) -> None:
    _project(tmp_path, agents_md=False)
    (tmp_path / "AGENTS.override.md").write_text("# Override\n")

    assert _codex_files(tmp_path, single=True) == ["AGENTS.override.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("single", [False, True])
def test_fallback_file_in_subdirectory_is_listed_like_a_nested_agents_md(tmp_path: Path, single: bool) -> None:
    _nested_project(tmp_path, codex_marker=True)

    assert _codex_files(tmp_path, single=single) == ["AGENTS.md", "services/api/TEAM_GUIDE.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_fallback_file_in_subdirectory_is_listed_without_codex_marker_for_explicit_agent(tmp_path: Path) -> None:
    _nested_project(tmp_path, codex_marker=False)

    assert _codex_files(tmp_path, single=True) == ["AGENTS.md", "services/api/TEAM_GUIDE.md"]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("single", [False, True])
def test_subdirectory_fallback_file_beside_its_own_agents_md_is_not_listed(tmp_path: Path, single: bool) -> None:
    _nested_project(tmp_path, codex_marker=True, nested_agents_md=True)

    assert _codex_files(tmp_path, single=single) == ["AGENTS.md", "services/api/AGENTS.md"]
