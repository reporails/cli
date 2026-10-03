"""`ails check` scores AGENTS.md under Claude exactly when Claude Code reads it, and finds
a Claude plugin's own skills and agents.

Claude Code reads `AGENTS.md` through its built-in `agents-md` plugin: by default only
when no `CLAUDE.md`, `.claude/CLAUDE.md` or `CLAUDE.local.md` sits in the working
directory or above it; the user's `instructionFiles` setting can make it read both files
or `CLAUDE.md` only. A root `AGENTS.md` that Codex, Cursor or Copilot reads natively
stays with that agent. A Claude plugin (`.claude-plugin/plugin.json`) keeps its skills
and agents at the plugin root, which a whole-project check now reads.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.core.platform.config import claude_settings
from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

# The whole-file checks reported on a flat file; the others of the seven (C:0022, S:0016,
# S:0019, E:0005) are covered by one of these and stay unreported.
REPORTED = {
    "CORE:C:0019",
    "CORE:S:0002",
    "CORE:C:0037",
}

# Flat, headingless, prohibition-free: the shape every one of the seven detects.
FLAT_FOUR = (
    "Run `uv run pytest` before committing.\n"
    "Use `ruff` for formatting.\n"
    "Keep modules under 300 lines.\n"
    "Follow the project conventions.\n"
)
CLAUDE_MD = "# Project\n\nRun `uv run pytest tests/` before every commit.\nNever edit files under `dist/`.\n"
RULE = '---\npaths:\n  - "src/**"\n---\n\nUse `ruff format` on every changed Python file.\n'
SKILL = "---\nname: fmt\ndescription: Formats Python files\n---\n\nRun `ruff format` on each changed file.\n"
AGENT = "---\nname: reviewer\ndescription: Reviews diffs\n---\n\nReview the diff for missing tests.\n"

# The `.claude/` shapes a Claude project with an AGENTS.md and no CLAUDE.md takes.
CLAUDE_DIRS = {
    "settings": (".claude/settings.json", "{}\n"),
    "rules": (".claude/rules/style.md", RULE),
    "skills": (".claude/skills/fmt/SKILL.md", SKILL),
}


def _write(project: Path, rel: str, text: str) -> None:
    path = project / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _mode(mode: str) -> None:
    """Set the user's Claude Code `instructionFiles` setting in the test's HOME."""
    settings = {"pluginConfigs": {"agents-md@builtin": {"options": {"instructionFiles": mode}}}}
    _write(Path.home(), ".claude/settings.json", json.dumps(settings))


@pytest.fixture(autouse=True)
def _no_managed_settings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep the machine's own managed Claude settings out of every run."""
    real = claude_settings._settings_patterns

    def patterns() -> dict[str, list[str]]:
        scopes = real()
        scopes["managed"] = [str(tmp_path / "managed" / "managed-settings.json")]
        scopes["managed_dropin"] = [str(tmp_path / "managed" / "managed-settings.d" / "*.json")]
        return scopes

    monkeypatch.setattr(claude_settings, "_settings_patterns", patterns)


def _json(monkeypatch: pytest.MonkeyPatch, project: Path, *args: str) -> dict:
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", ".", *args, "-f", "json"])
    assert result.exit_code == 0, result.output
    return json.loads(result.output)


def _text(monkeypatch: pytest.MonkeyPatch, project: Path, *args: str) -> str:
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", ".", *args])
    assert result.exit_code == 0, result.output
    return result.output


def _rules_on(data: dict, rel: str) -> set[str]:
    return {f["rule"] for f in ((data.get("files") or {}).get(rel, {}).get("findings") or [])}


def _resolution(project: Path) -> tuple[str, bool, dict[str, str], set[str]]:
    """(effective agent, mixed, per-file rule-running owner, claude's own discovered files)."""
    from reporails_cli.core.discovery.agent_discovery import discover_from_config, partition_by_native_owner
    from reporails_cli.core.discovery.agents import clear_agent_cache, detect_agents
    from reporails_cli.core.pipeline.mapping import resolve_agent_filters

    clear_agent_cache()
    detected = detect_agents(project)
    effective, _assumed, mixed, filtered = resolve_agent_filters("", detected, project, None, None)
    owners = {
        Path(p).relative_to(project).as_posix(): o for p, o in partition_by_native_owner(filtered, project).items()
    }
    discovered = discover_from_config(project, "claude", repo_scoped=True)
    claude_files = {p.relative_to(project).as_posix() for p in (discovered[0] if discovered else [])}
    return effective, mixed, owners, claude_files


# ── 1. `.claude/` + AGENTS.md, no CLAUDE.md, default mode ────────────


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.parametrize("shape", sorted(CLAUDE_DIRS))
@pytest.mark.requires_model
def test_agents_md_is_scored_under_claude_when_no_claude_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str
) -> None:
    project = tmp_path / "proj"
    _write(project, *CLAUDE_DIRS[shape])
    _write(project, "AGENTS.md", FLAT_FOUR)

    effective, mixed, owners, claude_files = _resolution(project)
    assert "AGENTS.md" in claude_files
    assert (effective, mixed, owners["AGENTS.md"]) == ("claude", False, "claude")

    assert "Agent: Claude" in _text(monkeypatch, project)
    fired = _rules_on(_json(monkeypatch, project), "AGENTS.md")
    assert fired >= REPORTED, f"missing {sorted(REPORTED - fired)}"


def _tuples(payload: dict) -> set[tuple[str, str, int]]:
    return {
        (f["rule"], path, f["line"])
        for path, entry in (payload.get("files") or {}).items()
        for f in entry.get("findings") or []
    }


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_claude_as_the_projects_agent_reads_an_agents_md_only_project(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`--agent claude` (or `default_agent: claude`) on a project with only an AGENTS.md
    scores it as Claude's AGENTS.md, and MCP `validate` returns the same findings."""
    from reporails_cli.interfaces.mcp import tools

    project = tmp_path / "proj"
    _write(project, "AGENTS.md", FLAT_FOUR)
    fired = _rules_on(_json(monkeypatch, project, "--agent", "claude"), "AGENTS.md")
    assert fired >= REPORTED, f"missing {sorted(REPORTED - fired)}"

    _write(project, ".ails/config.yml", "default_agent: claude\n")
    cli = _json(monkeypatch, project)
    assert _tuples(cli) == _tuples(tools.validate_tool(str(project), full=True))


# ── 2. the same plus a CLAUDE.md ─────────────────────────────────────


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.parametrize("claude_file", ["CLAUDE.md", "CLAUDE.local.md", "../CLAUDE.md"])
@pytest.mark.requires_model
def test_agents_md_is_not_part_of_the_claude_check_beside_a_claude_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, claude_file: str
) -> None:
    """A CLAUDE.md or CLAUDE.local.md at the project root, or a CLAUDE.md above it."""
    project = tmp_path / "proj"
    _write(project, *CLAUDE_DIRS["rules"])
    _write(project, "AGENTS.md", FLAT_FOUR)
    _write(project, claude_file, CLAUDE_MD)

    _effective, _mixed, owners, claude_files = _resolution(project)
    assert "AGENTS.md" not in claude_files
    assert owners.get("AGENTS.md") != "claude"
    data = _json(monkeypatch, project, "--agent", "claude")
    assert "AGENTS.md" not in (data.get("files") or {})


# ── 3. the user's `instructionFiles` setting ────────────────────────


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_claude_md_and_agents_md_mode_scores_both(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Both files join the Claude check. The CLAUDE.md here already carries a heading and
    a prohibition for the session, so of the seven only the ones graded file by file
    (layering, stable-before-dynamic) land on the flat AGENTS.md; single topic and grouping
    depend on layering and are not reported beside it."""
    project = tmp_path / "proj"
    _write(project, "CLAUDE.md", CLAUDE_MD)
    _write(project, "AGENTS.md", FLAT_FOUR)
    _mode("claude-md-and-agents-md")

    effective, _mixed, owners, claude_files = _resolution(project)
    assert {"CLAUDE.md", "AGENTS.md"} <= claude_files
    assert (effective, owners["AGENTS.md"]) == ("claude", "claude")
    fired = _rules_on(_json(monkeypatch, project), "AGENTS.md")
    per_file = {"CORE:S:0016", "CORE:C:0037"}
    assert fired >= per_file, f"missing {sorted(per_file - fired)}"


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.parametrize("mode", ["claude-md", "managed-only"])
def test_claude_md_mode_never_reads_agents_md(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    project = tmp_path / "proj"
    _write(project, *CLAUDE_DIRS["settings"])
    _write(project, "AGENTS.md", FLAT_FOUR)
    _mode(mode)

    effective, _mixed, owners, claude_files = _resolution(project)
    assert "AGENTS.md" not in claude_files
    assert effective != "claude"
    assert owners.get("AGENTS.md") != "claude"
    assert "Agent: Claude" not in _text(monkeypatch, project)


# ── multi-agent: a root AGENTS.md another agent reads natively ──────


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_claude_and_codex_with_agents_md_and_no_claude_md(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """`.claude/` + `.codex/` + `AGENTS.md`, no `CLAUDE.md`: Claude reads the AGENTS.md too,
    but Codex reads it as its own main file, so it stays Codex's and runs Codex's rules.
    Claude's own rule file keeps Claude's rules; the scorecard names both agents."""
    project = tmp_path / "proj"
    _write(project, *CLAUDE_DIRS["rules"])
    _write(project, ".codex/config.toml", 'model = "gpt-5"\n')
    _write(project, "AGENTS.md", FLAT_FOUR)

    _effective, mixed, owners, claude_files = _resolution(project)
    assert "AGENTS.md" in claude_files
    assert mixed is True
    assert owners["AGENTS.md"] == "codex"
    assert owners[".claude/rules/style.md"] == "claude"

    data = _json(monkeypatch, project)
    assert not {r for r in _rules_on(data, "AGENTS.md") if r.startswith("CLAUDE:")}
    assert "Agent: Claude + Codex" in _text(monkeypatch, project)


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("marker", "content", "agent", "label"),
    [
        (".codex/config.toml", 'model = "gpt-5"\n', "codex", "Codex"),
        (".cursor/rules/style.mdc", "---\nalwaysApply: true\n---\n\nUse `ruff`.\n", "cursor", "Cursor"),
        (".github/copilot-instructions.md", "# Copilot\n\nUse `ruff`.\n", "copilot", "Copilot"),
    ],
)
@pytest.mark.requires_model
def test_claude_settings_alone_never_takes_another_agents_agents_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, marker: str, content: str, agent: str, label: str
) -> None:
    """With nothing of Claude's own to read beyond its settings, a project whose AGENTS.md
    Codex, Cursor or Copilot reads natively stays that agent's project."""
    project = tmp_path / "proj"
    _write(project, *CLAUDE_DIRS["settings"])
    _write(project, marker, content)
    _write(project, "AGENTS.md", FLAT_FOUR)

    effective, mixed, owners, _claude_files = _resolution(project)
    assert (effective, mixed, owners["AGENTS.md"]) == (agent, False, agent)
    assert f"Agent: {label}" in _text(monkeypatch, project)


# ── 4. a Claude plugin's own skills and agents ──────────────────────


def _surfaces(data: dict) -> dict[str, int]:
    return {s["name"]: s["file_count"] for s in data.get("surface_health") or []}


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.parametrize("root", [".", "plugins/demo"])
@pytest.mark.requires_model
def test_a_plugins_skills_and_agents_are_claude_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, root: str
) -> None:
    """A plugin at the project root, and a marketplace's plugin in `plugins/<name>/`."""
    project = tmp_path / "proj"
    base = project / root
    _write(base, ".claude-plugin/plugin.json", '{"name": "demo", "description": "Demo plugin"}\n')
    _write(base, "skills/fmt/SKILL.md", SKILL)
    _write(base, "agents/reviewer.md", AGENT)
    prefix = "" if root == "." else f"{root}/"

    effective, _mixed, owners, claude_files = _resolution(project)
    assert {f"{prefix}skills/fmt/SKILL.md", f"{prefix}agents/reviewer.md"} <= claude_files
    assert effective == "claude"
    assert owners[f"{prefix}skills/fmt/SKILL.md"] == owners[f"{prefix}agents/reviewer.md"] == "claude"

    data = _json(monkeypatch, project)
    assert _surfaces(data) == {"Skills": 1, "Agents": 1}
    assert "Agent: Claude" in _text(monkeypatch, project)


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_top_level_skills_without_a_plugin_manifest_are_not_claudes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    _write(project, "CLAUDE.md", CLAUDE_MD)
    _write(project, "skills/fmt/SKILL.md", SKILL)
    _write(project, "agents/reviewer.md", AGENT)

    _effective, _mixed, _owners, claude_files = _resolution(project)
    assert claude_files == {"CLAUDE.md"}
    data = _json(monkeypatch, project)
    assert "Skills" not in _surfaces(data)
    assert "Agents" not in _surfaces(data)


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.requires_model
def test_a_skills_supporting_files_are_checked_without_the_skill_only_rules(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`reference.md` and `examples/a.md` beside a SKILL.md are checked like any instruction file;
    the frontmatter rules that name `SKILL.md` do not report on them."""
    project = tmp_path / "proj"
    # Over 500 lines, with bare file names the format check reports on.
    long_notes = "# Notes\n\n" + "Edit config.yaml and run pytest before you commit.\n" * 520
    _write(project, "CLAUDE.md", CLAUDE_MD)
    _write(project, ".claude/skills/fmt/SKILL.md", SKILL)
    _write(project, ".claude/skills/fmt/reference.md", long_notes)
    _write(project, ".claude/skills/fmt/examples/a.md", long_notes + "Open src/app.py before you start.\n")
    _write(project, ".claude/skills/fmt/scripts/run.py", "print('x')\n")

    files = _json(monkeypatch, project)["files"]

    supporting = {".claude/skills/fmt/reference.md", ".claude/skills/fmt/examples/a.md"}
    assert supporting <= set(files)  # checked like any instruction file
    assert not any(rel.endswith(".py") for rel in files)
    skill_only = {"CORE:S:0040", "CORE:S:0018", "CORE:S:0031"}  # description, kebab-case name, 500 lines
    for rel in supporting:
        assert not _rules_on({"files": files}, rel) & skill_only
