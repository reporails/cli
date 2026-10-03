"""Regression: fixing the cross-read mislabel must never narrow discovery.

The cross-read-exclusion fix correctly stopped a cross-reading agent (Copilot) from
winning the `Agent:` label, but `resolve_agent_filters` used the SAME distinctiveness
decision to narrow the DISCOVERY scope too -- so a project where Copilot cross-reads
both Claude's own `.claude/**` namespace AND files no agent natively owns (the shared
`.agents/skills/**` standard, a nested `AGENTS.md`) lost those extra files from the scan
entirely. Fixing a label must never drop an instruction file discovery found.

This project mixes `.claude/{rules,skills}` (Claude's own, real files) + `.agents/skills/**`
(Copilot's cross-read of the shared standard, mirroring the same skill content) + a nested
`AGENTS.md` for a subproject no agent's own namespace claims. The fix: discovery's scope
is always the union of every
non-generic detected agent's own files (never narrowed by distinctiveness); a separate
per-file partition (`core.discovery.agent_discovery.partition_by_native_owner`) routes
each file to its native owner's rules, or to the core rule set when no distinctive agent
owns it -- so the file count never shrinks and the right ruleset still applies.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

# The 6 skill names mirrored under both `.claude/skills/` (Claude's own) and
# `.agents/skills/` (the shared Agent Skills standard, cross-read by Copilot and others).
_SKILLS = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta")


def _claude_smart_shaped_project(tmp_path: Path) -> Path:
    """`.claude/{rules,skills}` (Claude's own) + `.agents/skills/**` (the shared standard,
    mirroring the same content) + a nested `plugin/dashboard/AGENTS.md` subproject file no
    agent's own namespace claims. No `CLAUDE.md`, no root `AGENTS.md`, no Copilot main
    file -- matching the sample that caught the regression."""
    project = tmp_path / "proj"
    (project / ".claude" / "rules").mkdir(parents=True)
    (project / ".claude" / "rules" / "style.md").write_text(
        "# Style\n\nUse `ruff format` on every changed Python file.\n", encoding="utf-8"
    )
    for name in _SKILLS:
        for base in (".claude/skills", ".agents/skills"):
            skill_dir = project / base / name
            skill_dir.mkdir(parents=True)
            (skill_dir / "SKILL.md").write_text(
                f"---\nname: {name}\ndescription: The {name} skill\n---\n\nRun `make {name}` after tests pass.\n",
                encoding="utf-8",
            )
    (project / "plugin" / "dashboard").mkdir(parents=True)
    (project / "plugin" / "dashboard" / "AGENTS.md").write_text(
        "# Dashboard subproject\n\nBefore writing route handlers, read the framework guide.\n",
        encoding="utf-8",
    )
    return project


def _json_run(project: Path) -> dict:
    import json

    result = runner.invoke(app, ["check", str(project), "-f", "json"])
    return json.loads(result.output)


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
def test_scope_equals_the_full_union_never_narrowed_by_distinctiveness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every file a detected agent claims stays in scope -- Claude's own 7
    (`.claude/rules/style.md` + 6 `.claude/skills/*/SKILL.md`) PLUS the 6
    `.agents/skills/*/SKILL.md` mirrors PLUS the nested `plugin/dashboard/AGENTS.md` = 14.
    None of them silently drops out because Copilot (the cross-reading, non-distinctive
    agent) lost its `Agent:` label."""
    from reporails_cli.core.discovery.agents import clear_agent_cache, detect_agents, get_all_instruction_files
    from reporails_cli.core.pipeline.mapping import resolve_agent_filters
    from reporails_cli.core.platform.config.config import get_project_config

    project = _claude_smart_shaped_project(tmp_path)
    monkeypatch.chdir(project)

    clear_agent_cache()
    config = get_project_config(project)
    detected = detect_agents(project)
    effective_agent, _assumed, mixed, filtered = resolve_agent_filters(
        config.default_agent, detected, project, config.exclude_dirs, config.exclude_files
    )
    scope = get_all_instruction_files(project, agents=filtered)

    assert effective_agent == "claude"
    assert mixed is False
    rel = {str(f.relative_to(project)) for f in scope}
    expected = {".claude/rules/style.md"}
    expected |= {f".claude/skills/{name}/SKILL.md" for name in _SKILLS}
    expected |= {f".agents/skills/{name}/SKILL.md" for name in _SKILLS}
    expected.add("plugin/dashboard/AGENTS.md")
    assert rel == expected, f"scope narrowed or widened unexpectedly: missing={expected - rel}, extra={rel - expected}"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_claude_owned_files_carry_claude_rules_unowned_files_carry_core_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Claude's own 7 files run under Claude's ruleset (a `CLAUDE:*` rule fires); the 7
    files no distinctive agent natively owns (`.agents/skills/**` mirrors, the nested
    `AGENTS.md`) run under the core rule set only -- never Claude's, never dropped."""
    project = _claude_smart_shaped_project(tmp_path)
    monkeypatch.chdir(project)

    data = _json_run(project)

    claude_owned = {".claude/rules/style.md"} | {f".claude/skills/{name}/SKILL.md" for name in _SKILLS}
    unowned = {f".agents/skills/{name}/SKILL.md" for name in _SKILLS} | {"plugin/dashboard/AGENTS.md"}

    rules_by_file = {path: {f["rule"] for f in entry["findings"]} for path, entry in data["files"].items()}

    # At least one Claude-owned file must carry a CLAUDE:* rule (proves Claude's own
    # ruleset ran on Claude's own files, not just CORE).
    claude_rule_hits = {
        path: rules
        for path, rules in rules_by_file.items()
        if path in claude_owned and any(r.startswith("CLAUDE:") for r in rules)
    }
    assert claude_rule_hits, f"no CLAUDE:* rule fired on any Claude-owned file; rules_by_file={rules_by_file}"

    # No unowned file may carry a CLAUDE:* (or any other agent-specific) rule -- core only.
    for path in unowned:
        rules = rules_by_file.get(path, set())
        non_core = {r for r in rules if not r.startswith("CORE:")}
        assert not non_core, f"{path} carries a non-core rule under core-only attribution: {non_core}"


@pytest.mark.e2e
@pytest.mark.subsys_cli_ux
@pytest.mark.requires_model
def test_agent_label_still_reads_claude(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The scorecard `Agent:` line still names Claude, unaffected by keeping the
    unowned `.agents/skills` / nested `AGENTS.md` files in scope."""
    project = _claude_smart_shaped_project(tmp_path)
    monkeypatch.chdir(project)

    result = runner.invoke(app, ["check", str(project)])

    assert "Agent: Claude" in result.output
    assert "Agent: Copilot" not in result.output
