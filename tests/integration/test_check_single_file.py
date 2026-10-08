"""End-to-end coverage for `ails check <single-file>` discovery scope.

`ails check <file>` was enumerating user-scope
`~/.claude/CLAUDE.md` even when the operator named one explicit project
file. The display surfaced findings from a file the operator hadn't
asked about; per-file count and summary count failed to reconcile.

The fix narrows the display to `{target.resolve()}` when arg1 is an
existing file path (not capability mode), reusing the existing
`filter_result_to_paths` machinery.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_single_file_target_does_not_surface_user_scope(tmp_path: Path) -> None:
    """`ails check <project-CLAUDE.md>` filters out user-scope `~/.claude/CLAUDE.md`."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Project\n\nA minimal CLAUDE.md.\n", encoding="utf-8")

    target = project / "CLAUDE.md"
    result = runner.invoke(app, ["check", str(target), "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    # capability_paths echo back the narrowed display set.
    paths = data.get("capability_paths", [])
    assert len(paths) == 1
    assert paths[0].endswith("CLAUDE.md")

    # No finding may reference a `~/...`-prefixed (user-scope) file.
    files = data.get("files", {})
    for key in files:
        assert not key.startswith("~/"), f"User-scope file leaked into display: {key}"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_single_file_target_reconciles_summary_and_panel_counts(tmp_path: Path) -> None:
    """Total findings count equals the per-file finding count for the single target."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Project\n\nA minimal CLAUDE.md.\n", encoding="utf-8")

    target = project / "CLAUDE.md"
    result = runner.invoke(app, ["check", str(target), "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)

    summary_total = int(data.get("stats", {}).get("total_findings", 0))
    per_file_total = sum(len(v.get("findings", [])) for v in data.get("files", {}).values())
    assert summary_total == per_file_total


_VIOLATION_LADEN = (
    "# Project\n\n"
    "You must always use the API key for authentication.\n"
    "Do not ever hardcode credentials in the source code.\n"
    "Never commit secrets to the repository under any circumstances whatsoever here.\n"
)


def _claude_findings(data: dict) -> int:
    """Count findings attributed to the project CLAUDE.md in a check JSON payload."""
    files = data.get("files", {})
    return sum(len(v.get("findings", [])) for k, v in files.items() if k.endswith("CLAUDE.md"))


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_single_file_scan_finds_violations(tmp_path: Path, monkeypatch) -> None:
    """Regression: `ails check <file>` on a non-clean CLAUDE.md returns findings, not 'No findings.'

    Before the scan_root-normalization fix, a single-file target classified
    as empty (no file_type), so no rules applied and the scan returned zero
    findings even when the file had real violations.

    Run from the project directory with a relative target — the canonical
    usage — so path normalization stays single-drive (on Windows pytest's
    tmp_path and the repo checkout can land on different drives, which breaks
    the cross-drive `relative_to` the display filter relies on).
    """
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text(_VIOLATION_LADEN, encoding="utf-8")
    monkeypatch.chdir(project)

    result = runner.invoke(app, ["check", "CLAUDE.md", "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert _claude_findings(data) > 0, "single-file scan surfaced no findings for a non-clean CLAUDE.md"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_single_file_scan_matches_whole_project(tmp_path: Path) -> None:
    """A single-file scan and a whole-project scan agree on findings for that file."""
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text(_VIOLATION_LADEN, encoding="utf-8")

    target = project / "CLAUDE.md"
    single = runner.invoke(app, ["check", str(target), "--agent", "claude", "-f", "json"])
    whole = runner.invoke(app, ["check", str(project), "--agent", "claude", "-f", "json"])
    assert single.exit_code == 0, single.output
    assert whole.exit_code == 0, whole.output

    assert _claude_findings(json.loads(single.output)) == _claude_findings(json.loads(whole.output))


def _nested_project(tmp_path: Path, *, sub_has_config_dir: bool) -> Path:
    """A project with a root `CLAUDE.md` + `.claude/` and a `sub/CLAUDE.md` (optionally with its own `.claude/`)."""
    project = tmp_path / "b3proj"
    (project / ".git").mkdir(parents=True)
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / "CLAUDE.md").write_text(
        "# Project\n\nRun `uv run pytest tests/` before every commit.\n", encoding="utf-8"
    )
    (project / ".claude" / "rules" / "style.md").write_text(
        '---\npaths: ["**/*.py"]\n---\n# Style\n\nUse type hints.\n', encoding="utf-8"
    )
    sub = project / "sub"
    sub.mkdir()
    (sub / "CLAUDE.md").write_text(_VIOLATION_LADEN, encoding="utf-8")
    if sub_has_config_dir:
        (sub / ".claude").mkdir()
    return project


def _classification(data: dict) -> tuple[list[str], list[tuple[str, int]], str, dict[str, list[tuple]]]:
    """File keys, surfaces, level and per-file findings of a check JSON payload."""
    findings = {
        key: sorted((f["rule"], f["line"], f["severity"], f["message"]) for f in entry["findings"])
        for key, entry in data["files"].items()
    }
    surfaces = [(s["name"], s["file_count"]) for s in data["surface_health"]]
    return sorted(data["files"]), surfaces, data["level"], findings


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
@pytest.mark.parametrize("mode", ["relative", "absolute", "outside-cwd", "parent-cwd"])
def test_subdir_target_classifies_its_main_file_like_the_file_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    """Naming `sub/` and naming `sub/CLAUDE.md` read the same file the same way.

    `sub/` carries a `CLAUDE.md` but no `.claude/` of its own, so it is a slice of the project, not a
    root: the directory target must keep the project anchor (key `sub/CLAUDE.md`, a Nested surface,
    the nested level) instead of rerooting at `sub/` and reading its `CLAUDE.md` as the project's main file.
    The same holds when the command runs from a folder outside the project (`outside-cwd`) or from
    a parent folder that is no project (`parent-cwd`).
    """
    project = _nested_project(tmp_path, sub_has_config_dir=False)
    if mode == "outside-cwd":
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
    elif mode == "parent-cwd":
        monkeypatch.chdir(tmp_path)
    else:
        monkeypatch.chdir(project)
    dir_target, file_target = (
        ("sub", "sub/CLAUDE.md") if mode == "relative" else (str(project / "sub"), str(project / "sub" / "CLAUDE.md"))
    )

    by_dir = runner.invoke(app, ["check", dir_target, "--agent", "claude", "-f", "json"])
    by_file = runner.invoke(app, ["check", file_target, "--agent", "claude", "-f", "json"])
    assert by_dir.exit_code == 0, by_dir.output
    assert by_file.exit_code == 0, by_file.output

    dir_view, file_view = _classification(json.loads(by_dir.output)), _classification(json.loads(by_file.output))
    assert file_view[0] == ["sub/CLAUDE.md"], file_view[0]
    assert file_view[1] == [("Nested", 1)], file_view[1]
    assert dir_view == file_view
    assert file_view[3]["sub/CLAUDE.md"], "the violation-laden sub/CLAUDE.md surfaced no findings"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_subdir_with_its_own_config_dir_is_its_own_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Contrast: `sub/` holding `CLAUDE.md` AND `.claude/` is a project root of its own, so the
    directory target keeps `sub/` path keys and reads its `CLAUDE.md` as the main file."""
    project = _nested_project(tmp_path, sub_has_config_dir=True)
    monkeypatch.chdir(project)

    result = runner.invoke(app, ["check", "sub", "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output

    keys, surfaces, _level, _findings = _classification(json.loads(result.output))
    assert keys == ["CLAUDE.md"], keys
    assert surfaces == [("Main", 1)], surfaces


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_subdir_with_its_own_config_dir_named_from_outside_is_its_own_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Contrast: from a folder outside the project, a `sub/` holding `CLAUDE.md` AND `.claude/`
    still keeps `sub/` path keys and reads its `CLAUDE.md` as the main file."""
    project = _nested_project(tmp_path, sub_has_config_dir=True)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    result = runner.invoke(app, ["check", str(project / "sub"), "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output

    keys, surfaces, _level, _findings = _classification(json.loads(result.output))
    assert keys == ["CLAUDE.md"], keys
    assert surfaces == [("Main", 1)], surfaces


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_explicit_subagent_memory_target_reaches_user_scope(tmp_path: Path, monkeypatch) -> None:
    """`ails check subagent_memory` reaches global `~/.claude/agent-memory/` files.

    Regression guard for the cap_paths union: a whole-project scan excludes
    cross-project subagent memory, so without the union the intersection drops
    the global files and the run bails with "No instruction files found". The
    explicit capability target must re-include them.
    """
    home = tmp_path / "home"
    agent_mem = home / ".claude" / "agent-memory" / "lead"
    agent_mem.mkdir(parents=True)
    (agent_mem / "note.md").write_text("# Lead memory\n\nPin every dependency.\n", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))  # `Path.home()` reads USERPROFILE on Windows, not HOME

    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Project\n\nUse the API key.\n", encoding="utf-8")
    monkeypatch.chdir(project)

    result = runner.invoke(app, ["check", "subagent_memory", "--agent", "claude", "-f", "json"])
    assert result.exit_code == 0, result.output
    assert "No instruction files found" not in result.output
    data = json.loads(result.output)
    paths = data.get("capability_paths", [])
    assert any("agent-memory" in p for p in paths), f"global subagent_memory not reached: {paths}"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_exclude_files_explicit_target_overrides_exclusion(tmp_path: Path, monkeypatch) -> None:
    """`exclude_files` drops a file from whole-project discovery, but an explicit target scans it.

    Exclusion applies to discovery only — naming the excluded file directly
    (single-file mode) bypasses the discovery filter, which is the intended
    override for symlinked / externally-owned harness files.
    """
    project = tmp_path / "proj"
    agents_dir = project / ".claude" / "agents"
    agents_dir.mkdir(parents=True)
    (project / "CLAUDE.md").write_text(_VIOLATION_LADEN, encoding="utf-8")
    (agents_dir / "lead.md").write_text(_VIOLATION_LADEN, encoding="utf-8")
    ails = project / ".ails"
    ails.mkdir()
    (ails / "config.yml").write_text(
        'schema_version: "0.1.0"\nexclude_files:\n  - ".claude/agents/lead.md"\n', encoding="utf-8"
    )
    monkeypatch.chdir(project)

    whole = runner.invoke(app, ["check", "--agent", "claude", "-f", "json"])
    assert whole.exit_code == 0, whole.output
    whole_files = json.loads(whole.output).get("files", {})
    assert not any(k.endswith("agents/lead.md") for k in whole_files), "excluded file must be dropped from discovery"

    explicit = runner.invoke(app, ["check", "./.claude/agents/lead.md", "--agent", "claude", "-f", "json"])
    assert explicit.exit_code == 0, explicit.output
    paths = json.loads(explicit.output).get("capability_paths", [])
    assert any(p.endswith("lead.md") for p in paths), "explicit target must override exclusion and scan"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_mixed_agent_capability_target_errors_clearly(tmp_path: Path, monkeypatch) -> None:
    """A capability target on a multi-agent repo (no resolved agent) errors clearly.

    Regression: it used to degrade to `generic`, yielding "capability X is not
    declared for agent generic" or "Create a AGENTS.md" — misleading when the
    files exist. Now it names the detected agents and asks for `--agent`.
    """
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Claude\n\nUse the key.\n", encoding="utf-8")
    gh = project / ".github"
    gh.mkdir()
    (gh / "copilot-instructions.md").write_text("# Copilot\n\nUse the key.\n", encoding="utf-8")
    monkeypatch.chdir(project)

    result = runner.invoke(app, ["check", "skills"])
    assert result.exit_code == 2, result.output
    assert "multiple agents detected" in result.output
    assert "--agent" in result.output

    # Explicit --agent bypasses the mixed-agent guard (no false 'multiple agents').
    forced = runner.invoke(app, ["check", "skills", "--agent", "claude"])
    assert "multiple agents detected" not in forced.output
