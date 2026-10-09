"""Rule targeting on the `format: schema_validated` config surfaces.

Three contracts, all previously broken, all reachable from one `ails check` run.

1. **The hook / permission family reaches the canonical settings file.**
   `framework/rules/claude/config.yml` declared `hooks:` and `config:` with the
   SAME pattern (`.claude/settings.json`); `classify_files` takes the first
   declaration whose pattern matches, so the file resolved to `hooks` and the 30
   rules that declare `match: {type: config}` — every hook rule, every per-agent
   hook overlay, `CORE:G:0003` permission-config-declared — were silent on the one
   file they exist to validate. Only the gitignored `.claude/settings.local.json`
   resolved to `config`. Antigravity had the same collision on
   `.gemini/settings.json` at the time, but has since moved its hooks surface to
   a DEDICATED `.agents/hooks.json` — cursor / codex / copilot keep a dedicated
   `hooks` file_type too (`.cursor/hooks.json`, `.codex/hooks.json`,
   `.github/hooks/*.json`) that no rule targeted at all.

2. **A prose rule never scores a machine-config file.** `content_checker`
   fell back to EVERY mapped file whenever a rule's `match` named no `type`, so
   `match: {format: freeform}` rules scored JSON and TOML: `ails check .mcp.json`
   answered "Missing section headers" and "No safety constraints found", and
   `ails check hooks` told the user to wrap 107 JSON string literals in backticks.

3. **`hook_files` still detects from `settings.json`.** The L6 governance gate
   reads the settings file directly; the collision fix must not cost the level.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

# A hooks block with an unrecognized event name and a handler that declares a
# type but no `command` — the two defects the hook rules exist to catch.
BROKEN_HOOKS = json.dumps(
    {"hooks": {"NotARealEvent": [{"matcher": "Bash", "hooks": [{"type": "command"}]}]}},
    indent=2,
)

MAIN_FILE = "# Test Project\n\nAlways run the tests before pushing.\n\nNEVER force-push to main.\n"

# (agent, main instruction filename, settings path, the agent's own hook rules)
COLLISION_AGENTS = [
    pytest.param(
        "claude",
        "CLAUDE.md",
        ".claude/settings.json",
        # CLAUDE:S:0005 supersedes CORE:S:0027 (valid event types);
        # CLAUDE:S:0004 supersedes CORE:S:0029 (command handler has command).
        {"CLAUDE:S:0005", "CLAUDE:S:0004"},
        id="claude",
    ),
]

# Agents whose hooks live in a file of their own rather than inside settings.
# Antigravity moved here with its own migration: hooks now live at the
# dedicated ".agents/hooks.json" (antigravity.google/docs/hooks/), not inside
# ".gemini/settings.json" — so it no longer collides with `config` the way
# `COLLISION_AGENTS` above does.
DEDICATED_HOOKS_AGENTS = [
    pytest.param("cursor", "AGENTS.md", ".cursor/hooks.json", {"CURSOR:S:0002", "CURSOR:S:0004"}, id="cursor"),
    pytest.param("codex", "AGENTS.md", ".codex/hooks.json", {"CODEX:S:0003", "CODEX:S:0005"}, id="codex"),
    pytest.param(
        "copilot",
        ".github/copilot-instructions.md",
        ".github/hooks/precommit.json",
        {"COPILOT:S:0003", "COPILOT:S:0005"},
        id="copilot",
    ),
    pytest.param(
        "antigravity",
        "AGENTS.md",
        ".agents/hooks.json",
        {"ANTIGRAVITY:S:0001", "ANTIGRAVITY:S:0003"},
        id="antigravity",
    ),
]


def _project(tmp_path: Path, main_name: str, settings_rel: str, settings_body: str) -> Path:
    """A project with one main instruction file and one machine-config file."""
    project = tmp_path / "proj"
    main = project / main_name
    main.parent.mkdir(parents=True, exist_ok=True)
    main.write_text(MAIN_FILE, encoding="utf-8")
    settings = project / settings_rel
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text(settings_body, encoding="utf-8")
    return project


def _fired(monkeypatch: pytest.MonkeyPatch, project: Path, *args: str) -> set[str]:
    """Run `ails check` inside `project` and return the set of rule ids that fired."""
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", *args, "-f", "json"])
    data = json.loads(result.output[result.output.index("{") :])
    return {f["rule"] for record in data.get("files", {}).values() for f in record["findings"]}


# ---------------------------------------------------------------------------
# 1. The `type: config` family reaches the canonical settings file
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.parametrize(("agent", "main_name", "settings_rel", "hook_rules"), COLLISION_AGENTS)
@pytest.mark.requires_model
def test_hook_rules_fire_on_the_canonical_settings_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    main_name: str,
    settings_rel: str,
    hook_rules: set[str],
) -> None:
    """A broken hooks block in `settings.json` draws the agent's hook findings.

    Reddens if the hook rules stop naming the surface the settings file resolves
    to — the shipped state before the fix, where `settings.json` classified
    `hooks` and every hook rule targeted `config` alone.
    """
    project = _project(tmp_path, main_name, settings_rel, BROKEN_HOOKS)
    fired = _fired(monkeypatch, project, "hooks", "--agent", agent)

    assert hook_rules <= fired, f"{agent}: missing {sorted(hook_rules - fired)} (fired: {sorted(fired)})"


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.parametrize(("agent", "main_name", "settings_rel", "hook_rules"), COLLISION_AGENTS)
@pytest.mark.requires_model
def test_permission_rule_fires_on_the_canonical_settings_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    main_name: str,
    settings_rel: str,
    hook_rules: set[str],
) -> None:
    """`CORE:G:0003` (permission config declared) reaches the committed settings file.

    This is the guard on the collision itself. It is the non-hook half of the
    `{type: config}` family — permissions, MCP servers, settings scope — which
    names only `config`, so it reddens the moment `hooks:` is declared ahead of
    `config:` again and the settings file stops resolving to `config`.
    """
    project = _project(tmp_path, main_name, settings_rel, BROKEN_HOOKS)
    fired = _fired(monkeypatch, project, "hooks", "--agent", agent)

    assert "CORE:G:0003" in fired, sorted(fired)


@pytest.mark.e2e
@pytest.mark.subsys_classify
@pytest.mark.parametrize(("agent", "main_name", "hooks_rel", "hook_rules"), DEDICATED_HOOKS_AGENTS)
@pytest.mark.requires_model
def test_hook_rules_fire_on_a_dedicated_hooks_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    agent: str,
    main_name: str,
    hooks_rel: str,
    hook_rules: set[str],
) -> None:
    """Cursor / codex / copilot / antigravity keep hooks in their own file — the rules must reach it.

    Cursor, codex and copilot's hooks file classifies `hooks`, never `config`,
    so their hook rules had to name both surfaces (`match: {type: [config,
    hooks]}`). Antigravity's dedicated hooks file has no `config` overlap at
    all, so its hook rules name `type: hooks` alone. Either way, reddens if
    the rules stop reaching the file the agent actually writes.
    """
    project = _project(tmp_path, main_name, hooks_rel, BROKEN_HOOKS)
    fired = _fired(monkeypatch, project, "hooks", "--agent", agent)

    assert hook_rules <= fired, f"{agent}: missing {sorted(hook_rules - fired)} (fired: {sorted(fired)})"


# ---------------------------------------------------------------------------
# 2. Prose rules stay off machine config
# ---------------------------------------------------------------------------


def _prose_only_rule_ids() -> set[str]:
    """Every shipped rule whose `match` names `freeform` and NOT `schema_validated`.

    Derived from the bundled registry rather than hardcoded so a newly authored
    prose rule is covered by this guard the day it ships. A rule that names both
    (`CORE:G:0001` vcs-tracked, `match: {format: [freeform, frontmatter,
    schema_validated]}`) has declared the machine-config surface in scope and is
    deliberately excluded.
    """
    from reporails_cli.core.platform.adapters.registry import load_rules

    out: set[str] = set()
    for rule_id, rule in load_rules(agent="claude").items():
        fmt = getattr(rule.match, "format", None) if rule.match else None
        values = fmt if isinstance(fmt, list) else [fmt]
        if "freeform" in values and "schema_validated" not in values:
            out.add(rule_id)
    return out


# `CORE:E:0003` (backticks / bold) and `CORE:S:0039` (heading-as-instruction) are
# raised by the client-check path, which reads atoms and never consults `match`;
# they are held off machine config by `surface_mutations: {config: {applies: false}}`.
CLIENT_CHECK_PROSE_RULES = {"CORE:E:0003", "CORE:S:0039"}


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.parametrize(
    ("settings_rel", "body"),
    [
        pytest.param(".claude/settings.json", BROKEN_HOOKS, id="settings.json"),
        pytest.param(
            ".mcp.json",
            json.dumps({"mcpServers": {"reporails": {"command": "uvx", "args": ["reporails-mcp"]}}}, indent=2),
            id="mcp.json",
        ),
    ],
)
@pytest.mark.requires_model
def test_schema_validated_target_draws_no_prose_findings(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    settings_rel: str,
    body: str,
) -> None:
    """`ails check <machine-config>` reports zero markdown-prose findings.

    Reddens if `content_checker._matching_files` falls back to every mapped file
    for a match that names a `format` but no `type` — the JSON file is then told
    to add section headers, safety directives and explicit prohibitions.
    """
    project = _project(tmp_path, "CLAUDE.md", settings_rel, body)
    fired = _fired(monkeypatch, project, settings_rel, "--agent", "claude")

    prose = fired & (_prose_only_rule_ids() | CLIENT_CHECK_PROSE_RULES)
    assert not prose, f"prose rules scored {settings_rel}: {sorted(prose)}"


# ---------------------------------------------------------------------------
# 3. The L6 governance gate still reads the settings file
# ---------------------------------------------------------------------------


@pytest.mark.e2e
@pytest.mark.subsys_classify
def test_hook_files_still_detect_from_settings_json(tmp_path: Path) -> None:
    """Hooks declared inside `settings.json` still light the L6 governance capability.

    The collision fix must not be paid for by retiring the `settings.json`
    pattern: `detect_features_filesystem` reads the file directly, and dropping
    it would silently demote every hooks-in-settings project below L6.
    """
    from reporails_cli.core.discovery.features import detect_features_filesystem
    from reporails_cli.core.platform.policy.levels import FEATURE_DETECTORS

    project = _project(tmp_path, "CLAUDE.md", ".claude/settings.json", BROKEN_HOOKS)
    features = detect_features_filesystem(project)

    assert features.hook_files == (project / ".claude/settings.json",)
    assert FEATURE_DETECTORS["governance"](features) is True
