"""A lone `CLAUDE.md` (or `AGENTS.md`) checked from its own parent directory.

Previously broken: `ails check <dir>` on a folder holding only a main instruction
file, run from outside it, treated the folder as a slice of the cwd. The cwd
carries no agent surfaces of its own, so agent detection at the cwd found nothing
and the target's own `CLAUDE.md` was silently dropped — "No instruction files
found." at exit 0, `--strict` included. The Action's `path:` input and every
`post-publish-smoke.yml` leg hit the same path on the most common minimal project.

Every test here runs with an isolated `HOME` (via the autouse `_isolate_home`
fixture in `conftest.py`) so a contributor's real `~/.claude` can never turn into
a hidden co-factor for whether the folder is found.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


def _json_run(monkeypatch: pytest.MonkeyPatch, cwd: Path, *args: str) -> tuple[int, dict]:
    monkeypatch.chdir(cwd)
    result = runner.invoke(app, ["check", *args, "-f", "json"])
    return result.exit_code, json.loads(result.output)


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_lone_main_file_checked_from_its_parent_is_its_own_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A folder holding only `CLAUDE.md`, checked from its parent (which has no agent
    surfaces of its own), is scanned as its own project rather than silently dropped."""
    parent = tmp_path / "workspace"
    proj = parent / "proj"
    proj.mkdir(parents=True)
    (proj / "CLAUDE.md").write_text(
        "# Project\n\nRun `uv run pytest tests/` before every commit.\nNever edit files under `dist/`.\n",
        encoding="utf-8",
    )

    exit_code, data = _json_run(monkeypatch, parent, "proj")

    assert sorted(data["files"]) == ["CLAUDE.md"], data["files"]
    assert exit_code == 0


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_lone_main_file_strict_exits_1_on_its_own_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`--strict` on the same lone-main-file target exits 1 when the file has findings —
    the parent-anchored bug always reported nothing and stayed green."""
    parent = tmp_path / "workspace"
    proj = parent / "proj"
    proj.mkdir(parents=True)
    (proj / "CLAUDE.md").write_text(
        "# Project\n\nRun `uv run pytest tests/` before every commit.\nNever edit files under `dist/`.\n",
        encoding="utf-8",
    )

    monkeypatch.chdir(parent)
    result = runner.invoke(app, ["check", "proj", "--strict"])

    assert "CLAUDE.md" in result.output
    assert result.exit_code == 1


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_lone_agents_md_checked_from_its_parent_is_its_own_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same anchoring applies to a bare `AGENTS.md` project, not only `CLAUDE.md`."""
    parent = tmp_path / "workspace"
    proj = parent / "proj"
    proj.mkdir(parents=True)
    (proj / "AGENTS.md").write_text(
        "# Project\n\nRun `uv run pytest tests/` before every commit.\nNever edit files under `dist/`.\n",
        encoding="utf-8",
    )

    exit_code, data = _json_run(monkeypatch, parent, "proj")

    assert sorted(data["files"]) == ["AGENTS.md"], data["files"]
    assert exit_code == 0


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_slice_of_a_real_project_keeps_the_existing_behaviour(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin the existing behaviour: a lone nested `CLAUDE.md` with no config dir, inside a
    real project (a parent that DOES carry its own main file), stays a SLICE narrowed
    from the project root — it must not start anchoring itself just because it has no
    config directory. Only the parent's own agentless-ness re-roots the child."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Root\n\nRoot guidance for agents.\n", encoding="utf-8")
    nested = project / "packages" / "web"
    nested.mkdir(parents=True)
    (nested / "CLAUDE.md").write_text(
        "# Web\n\nYou must always validate input before processing it.\n", encoding="utf-8"
    )

    exit_code, data = _json_run(monkeypatch, project, "packages/web")

    assert exit_code == 0, data
    assert sorted(data["files"]) == ["packages/web/CLAUDE.md"], data["files"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_bare_main_file_inside_ails_anchored_project_stays_a_slice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stray `CLAUDE.md` dropped two levels inside `.claude/` (a location no agent
    declares as a recognized main-file path, unlike `.claude/CLAUDE.md` itself, which
    Claude Code's own config already lists) must not anchor that subfolder as its own
    project when the enclosing root already carries an `.ails/` marker — `ails check
    .claude/agents` must keep resolving against the enclosing `.ails`-anchored project,
    not silently re-root onto the stray file's folder and lose the rest of the project."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".ails").mkdir()
    claude_dir = project / ".claude"
    (claude_dir / "rules").mkdir(parents=True)
    (claude_dir / "agents").mkdir(parents=True)
    (claude_dir / "rules" / "style.md").write_text(
        "# Style\n\nAlways use four-space indentation in every file.\n", encoding="utf-8"
    )
    (claude_dir / "agents" / "CLAUDE.md").write_text(
        "# Stray\n\nYou must always validate input before processing it.\n", encoding="utf-8"
    )

    exit_code, data = _json_run(monkeypatch, project, ".claude/agents", "--agent", "claude")

    assert exit_code == 0, data
    assert sorted(data["files"]) == [".claude/agents/CLAUDE.md"], data["files"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_bare_main_file_inside_rules_only_anchored_project_stays_a_slice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same guard applies to a project anchored only by an agent config directory
    (`.claude/rules/`), with no `.ails/` and no main file of its own at the project root."""
    project = tmp_path / "proj"
    project.mkdir()
    claude_dir = project / ".claude"
    (claude_dir / "rules").mkdir(parents=True)
    (claude_dir / "agents").mkdir(parents=True)
    (claude_dir / "rules" / "style.md").write_text(
        "# Style\n\nAlways use four-space indentation in every file.\n", encoding="utf-8"
    )
    (claude_dir / "agents" / "CLAUDE.md").write_text(
        "# Stray\n\nYou must always validate input before processing it.\n", encoding="utf-8"
    )

    exit_code, data = _json_run(monkeypatch, project, ".claude/agents", "--agent", "claude")

    assert exit_code == 0, data
    assert sorted(data["files"]) == [".claude/agents/CLAUDE.md"], data["files"]
