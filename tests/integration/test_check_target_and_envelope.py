"""`ails check` target resolution and the single machine envelope.

Three contracts, all previously broken and all reachable from one `ails check` run:

1. A **directory** positional (`ails check .claude/skills`) scores the instruction
   files beneath it. It used to re-root discovery AT that directory, so a subtree
   that is not itself a project root (`.claude/skills`, `.claude/agents`) resolved
   to zero files and reported the empty result at exit 0 — `--strict` stayed green
   on a CI job scoped to a subdirectory.
2. A run with **nothing in scope** (empty project, agent-filtered-to-nothing,
   config-only project) emits the SAME top-level JSON shape as a normal run —
   `offline` / `tier` / `quality` / `level` / `files` / `stats` / `server_error` —
   instead of a second, incompatible `{"violations": [], "score": 0, "level": "L0"}`
   envelope a machine consumer had to branch on.
3. An unknown `--format` is a usage error (exit 2) naming the formats that exist,
   instead of silently rendering the human scorecard at exit 0.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

# The top-level keys every machine consumer reads — the GitHub Action's
# `action/parse_result.py` reads `quality` / `level` / `stats` / `server_error` / `files`.
ENVELOPE_KEYS = {"offline", "server_error", "tier", "quality", "level", "files", "stats"}


def _skills_project(tmp_path: Path) -> Path:
    """A claude project with a main file and two skills under `.claude/skills/`."""
    project = tmp_path / "proj"
    (project / ".claude" / "skills" / "alpha").mkdir(parents=True)
    (project / ".claude" / "skills" / "beta").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Project\n\nGuidance for agents in this repository.\n", encoding="utf-8")
    (project / ".claude" / "skills" / "alpha" / "SKILL.md").write_text(
        "---\nname: alpha\ndescription: Alpha skill\n---\n\n# Alpha\n\n"
        "you should probably try to use the alpha tool when it seems right.\n",
        encoding="utf-8",
    )
    (project / ".claude" / "skills" / "beta" / "SKILL.md").write_text(
        "---\nname: beta\ndescription: Beta skill\n---\n\n# Beta\n\n"
        "maybe run the beta thing, it might work sometimes.\n",
        encoding="utf-8",
    )
    return project


def _json_run(monkeypatch: pytest.MonkeyPatch, project: Path, *args: str) -> tuple[int, dict]:
    """Run `ails check` from inside `project` and parse its JSON stdout."""
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", *args, "-f", "json"])
    return result.exit_code, json.loads(result.output)


# ---------------------------------------------------------------------------
# 1. Directory target
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_directory_target_scores_the_files_beneath_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`ails check .claude/skills` scores the skills, not an empty result."""
    project = _skills_project(tmp_path)
    exit_code, data = _json_run(monkeypatch, project, ".claude/skills")

    assert exit_code == 0, data
    assert set(data) >= ENVELOPE_KEYS, sorted(data)
    # `files` lists only the file(s) a finding attaches to — a project-wide
    # content check attaches its one finding to a single representative
    # file (content_checker.py: "A finding is emitted once per rule, not
    # per file"), so `files` is not a discovery-scope signal.
    # `capability_paths` is: it echoes every file the target resolved to,
    # scored or not, and is the field `test_check_single_file.py` already
    # reads for the same "which files did this target reach" question.
    assert sorted(data["capability_paths"]) == [
        ".claude/skills/alpha/SKILL.md",
        ".claude/skills/beta/SKILL.md",
    ], data["capability_paths"]
    assert data["stats"]["total_findings"] > 0


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_directory_target_matches_the_capability_target(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The path form and the capability form of the same set agree on the file set."""
    project = _skills_project(tmp_path)
    _, by_path = _json_run(monkeypatch, project, ".claude/skills")
    _, by_capability = _json_run(monkeypatch, project, "skills")

    assert sorted(by_path["files"]) == sorted(by_capability["files"])


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_directory_target_excludes_files_outside_the_subtree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A subtree target never scores the project's main file."""
    project = _skills_project(tmp_path)
    _, data = _json_run(monkeypatch, project, ".claude/skills")

    assert "CLAUDE.md" not in data["files"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_directory_target_strict_exits_1_on_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`--strict` on a directory with findings fails the build instead of passing green."""
    project = _skills_project(tmp_path)
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", ".claude/skills", "--strict", "-f", "json"])

    data = json.loads(result.output)
    assert data["stats"]["total_findings"] > 0, data
    assert result.exit_code == 1


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_trailing_slash_directory_target_behaves_the_same(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`.claude/skills/` resolves identically to `.claude/skills`."""
    project = _skills_project(tmp_path)
    _, bare = _json_run(monkeypatch, project, ".claude/skills")
    _, slashed = _json_run(monkeypatch, project, ".claude/skills/")

    assert sorted(bare["files"]) == sorted(slashed["files"])


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_single_file_target_still_scopes_to_that_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The single-file path stays narrowed to one file (regression guard)."""
    project = _skills_project(tmp_path)
    exit_code, data = _json_run(monkeypatch, project, ".claude/skills/alpha/SKILL.md")

    assert exit_code == 0, data
    assert list(data["files"]) == [".claude/skills/alpha/SKILL.md"] or data["files"] == {}
    assert data["capability_paths"] == [".claude/skills/alpha/SKILL.md"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_nested_project_directory_keeps_its_own_surfaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A monorepo package that is its own project root keeps its own anchoring.

    The scope-to-subtree fallback is reached only when anchoring AT the directory
    discovers nothing. A package carrying its own `.claude/` discovers plenty, so it
    stays a scan root: it keeps its nested surfaces (the outer scan never reaches a
    nested `.claude/rules/`) and its target-relative path keys. This is the shape
    `action.yml` runs for `path: ./packages/api`.
    """
    project = tmp_path / "proj"
    (project / "packages" / "api" / ".claude" / "rules").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Root\n\nRoot guidance for agents.\n", encoding="utf-8")
    (project / "packages" / "api" / "CLAUDE.md").write_text(
        "# API\n\nYou must always validate input before processing it.\n", encoding="utf-8"
    )
    (project / "packages" / "api" / ".claude" / "rules" / "style.md").write_text(
        "# Rules\n\nnever skip the tests, probably.\n", encoding="utf-8"
    )
    _, data = _json_run(monkeypatch, project, "./packages/api")

    assert sorted(data["files"]) == [".claude/rules/style.md", "CLAUDE.md"], data["files"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_agent_config_dir_target_lists_every_surface_under_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`ails check .claude` scopes to every surface under it, not just a stray `.claude/CLAUDE.md`.

    `.claude/` is an agent directory, never a project root — whatever it contains. A
    misplaced `CLAUDE.md` inside it used to be enough for discovery anchored AT
    `.claude/` to return one file, so the "anchored pass found nothing" fallback never
    fired and every rule and skill underneath was silently dropped from the run.
    """
    project = _skills_project(tmp_path)
    (project / ".claude" / "rules").mkdir()
    (project / ".claude" / "rules" / "style.md").write_text(
        "# Style\n\nnever skip the tests, probably.\n", encoding="utf-8"
    )
    (project / ".claude" / "CLAUDE.md").write_text(
        "# Stray\n\nA misplaced main file inside the agent directory.\n", encoding="utf-8"
    )
    exit_code, data = _json_run(monkeypatch, project, ".claude")

    assert exit_code == 0, data
    assert sorted(data["capability_paths"]) == [
        ".claude/CLAUDE.md",
        ".claude/rules/style.md",
        ".claude/skills/alpha/SKILL.md",
        ".claude/skills/beta/SKILL.md",
    ], data["capability_paths"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_nested_ails_directory_makes_a_subtree_its_own_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A subtree carrying `.ails/` is a project root, so it anchors itself.

    Its path keys are relative to IT, not to the enclosing project — the proof that
    the decision is made on the root marker and not on whether anchoring happened to
    discover something.
    """
    project = _skills_project(tmp_path)
    nested = project / "vendor" / "toolkit"
    (nested / ".ails").mkdir(parents=True)
    (nested / ".claude" / "skills" / "gamma").mkdir(parents=True)
    (nested / "CLAUDE.md").write_text("# Toolkit\n\nRoot guidance for the toolkit.\n", encoding="utf-8")
    (nested / ".claude" / "skills" / "gamma" / "SKILL.md").write_text(
        "---\nname: gamma\ndescription: Gamma skill\n---\n\n# Gamma\n\nmaybe do the gamma thing.\n",
        encoding="utf-8",
    )
    exit_code, data = _json_run(monkeypatch, project, "vendor/toolkit")

    assert exit_code == 0, data
    assert sorted(data["files"]) == [".claude/skills/gamma/SKILL.md", "CLAUDE.md"], data["files"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_plain_subtree_is_scoped_from_the_project_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A subtree with a nested main file but no config dir is NOT a root.

    It keeps project-root-relative path keys and is narrowed to the subtree — a lone
    `CLAUDE.md` is a child instruction file of THIS project, not another project.
    """
    project = _skills_project(tmp_path)
    (project / "packages" / "web").mkdir(parents=True)
    (project / "packages" / "web" / "CLAUDE.md").write_text(
        "# Web\n\nYou must always validate input before processing it.\n", encoding="utf-8"
    )
    exit_code, data = _json_run(monkeypatch, project, "packages/web")

    assert exit_code == 0, data
    assert sorted(data["files"]) == ["packages/web/CLAUDE.md"], data["files"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_whole_project_run_still_scores_every_surface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No target still means the whole project (regression guard for the re-root change)."""
    project = _skills_project(tmp_path)
    _, data = _json_run(monkeypatch, project)

    assert "CLAUDE.md" in data["files"]


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_directory_target_with_no_instruction_files_is_the_standard_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An in-project directory holding nothing scorable reports the ONE envelope, honestly empty."""
    project = _skills_project(tmp_path)
    (project / "docs").mkdir()
    (project / "docs" / "notes.txt").write_text("not an instruction file\n", encoding="utf-8")
    exit_code, data = _json_run(monkeypatch, project, "docs")

    assert exit_code == 0, data
    assert set(data) >= ENVELOPE_KEYS, sorted(data)
    assert data["files"] == {}
    assert "violations" not in data


# ---------------------------------------------------------------------------
# 2. One envelope
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_empty_project_json_is_the_standard_envelope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An empty project emits the normal-run shape, not `{"violations": [], ...}`."""
    project = tmp_path / "empty"
    project.mkdir()
    exit_code, data = _json_run(monkeypatch, project)

    assert exit_code == 0, data
    assert set(data) >= ENVELOPE_KEYS, sorted(data)
    assert "violations" not in data
    assert data["quality"] is None
    assert data["level"] == "L0"
    assert data["files"] == {}
    assert data["stats"]["total_findings"] == 0
    assert data["server_error"] is None


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_codex_config_only_project_is_the_standard_envelope(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A project with only `.codex/config.toml` is honestly empty — in the SAME envelope."""
    project = tmp_path / "proj"
    (project / ".codex").mkdir(parents=True)
    (project / ".codex" / "config.toml").write_text('model = "gpt-5"\n', encoding="utf-8")
    exit_code, data = _json_run(monkeypatch, project, "--agent", "codex")

    assert exit_code == 0, data
    assert set(data) >= ENVELOPE_KEYS, sorted(data)
    assert "violations" not in data
    assert data["files"] == {}


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_empty_project_text_still_names_the_absence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The human surface keeps its honest message — the envelope change is machine-only."""
    project = tmp_path / "empty"
    project.mkdir()
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check"])

    assert result.exit_code == 0, result.output
    assert "No instruction files found" in result.output
    assert "L0" in result.output


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_empty_project_parses_through_the_github_action_reader(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`action/parse_result.py` reads the empty envelope without a KeyError."""
    import subprocess
    import sys

    project = tmp_path / "empty"
    project.mkdir()
    _, data = _json_run(monkeypatch, project)

    parser = Path(__file__).resolve().parents[2] / "action" / "parse_result.py"
    proc = subprocess.run(
        [sys.executable, str(parser)], input=json.dumps(data), capture_output=True, text=True, check=True
    )
    assert "_SCORE=" in proc.stdout
    assert "_LEVEL=L0" in proc.stdout
    assert "_VIOLATIONS=0" in proc.stdout
    assert "_RESULT=ok" in proc.stdout


# ---------------------------------------------------------------------------
# 3. `--format` validation
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_unknown_format_is_a_usage_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An unknown `--format` exits 2 and names the formats that exist."""
    project = _skills_project(tmp_path)
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "-f", "bogus"])

    assert result.exit_code == 2, result.output
    assert "bogus" in result.output
    for known in ("text", "json", "github"):
        assert known in result.output


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_retired_compact_format_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`-f compact` names a formatter deleted this release — it must not silently become text."""
    project = _skills_project(tmp_path)
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", "-f", "compact"])

    assert result.exit_code == 2, result.output


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_known_formats_are_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every dispatched format still runs."""
    project = _skills_project(tmp_path)
    monkeypatch.chdir(project)
    for fmt in ("text", "json", "github"):
        result = runner.invoke(app, ["check", "-f", fmt])
        assert result.exit_code == 0, (fmt, result.output)
