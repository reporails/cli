"""The shipped hook handler rules, run the way a project check runs them.

Each test writes one agent's hook config into a project, runs the local rule pass
over it, and reads the findings the four per-handler rule families report: a command
handler needs a command, a handler's type is one the agent runs, a prompt handler
needs a prompt, and a command uses the agent's project-directory form.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from reporails_cli.core.lint.rule_runner import run_m_probes
from reporails_cli.core.pipeline.assemble import AssembleInputs, lint_request_local
from reporails_cli.core.platform.adapters.registry import load_rules, structural_rule_ids
from reporails_cli.formatters.text.display_constants import rule_aliases

HANDLER_RULE_SLUGS = {
    "hook-command-has-field",
    "hook-handler-has-type",
    "hook-prompt-has-field",
    "hook-uses-project-dir",
}

# (main instruction file, hook config file) per agent.
AGENT_FILES = {
    "claude": ("CLAUDE.md", ".claude/settings.json"),
    "codex": ("AGENTS.md", ".codex/hooks.json"),
    "copilot": (".github/copilot-instructions.md", ".github/hooks/hooks.json"),
    "cursor": ("AGENTS.md", ".cursor/hooks.json"),
    "antigravity": ("AGENTS.md", ".agents/hooks.json"),
}

MAIN_FILE = "# Test Project\n\nAlways run the tests before pushing.\n"


def _handler_rule_ids(agent: str) -> set[str]:
    """The per-handler hook rules active for `agent`."""
    return {rule_id for rule_id, rule in load_rules(agent=agent).items() if rule.slug in HANDLER_RULE_SLUGS}


def _project(tmp_path: Path, agent: str, body: str, config_rel: str | None = None) -> tuple[Path, list[Path]]:
    """A project holding the agent's main file and one hook config file."""
    main_rel, default_rel = AGENT_FILES[agent]
    project = tmp_path / "proj"
    files = []
    for rel, text in ((main_rel, MAIN_FILE), (config_rel or default_rel, body)):
        path = project / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        files.append(path)
    return project, files


def _handler_findings(tmp_path: Path, agent: str, body: str, config_rel: str | None = None) -> list[tuple[int, str]]:
    """(line, rule) for every per-handler hook finding on the agent's config file."""
    project, files = _project(tmp_path, agent, body, config_rel)
    wanted = _handler_rule_ids(agent)
    return sorted((f.line, f.rule) for f in run_m_probes(project, files, agent=agent) if f.rule in wanted)


# ---------------------------------------------------------------------------
# Objects that are not hook handlers draw no handler finding
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_empty_hooks_file_reports_no_command_handler(tmp_path: Path, dev_rules_dir: Path) -> None:
    """A hooks file holding only `{}` declares no handler to find fault with."""
    assert _handler_findings(tmp_path, "antigravity", "{}") == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_unrelated_top_level_array_reports_no_command_handler(tmp_path: Path, dev_rules_dir: Path) -> None:
    """Objects in an array beside the hook block are not command handlers lacking a command."""
    body = json.dumps(
        {"version": 1, "hooks": {"stop": [{"command": "./a.sh"}]}, "extra": [{"name": "n"}, {"name": "m"}]}
    )
    assert _handler_findings(tmp_path, "cursor", body) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_unrelated_objects_holding_a_command_key_report_no_untyped_handler(tmp_path: Path, dev_rules_dir: Path) -> None:
    """An array outside the hook block whose objects hold `command` is not a list of untyped handlers."""
    body = json.dumps(
        {
            "hooks": {
                "PreToolUse": [
                    {"matcher": "Bash", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/a.sh"}]}
                ]
            },
            "x": [{"command": "y"}, {"command": "z"}],
        }
    )
    assert _handler_findings(tmp_path, "claude", body) == []


# ---------------------------------------------------------------------------
# Every broken handler is found, on its own line
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_command_handler_holding_a_nested_object_and_no_command_is_reported(
    tmp_path: Path, dev_rules_dir: Path
) -> None:
    """A nested object inside a command handler does not hide that it has no command."""
    body = (
        "{\n"
        '  "hooks": {\n'
        '    "PreToolUse": [\n'
        '      {"matcher": "Bash", "hooks": [\n'
        '        {"type": "command", "env": {"A": "1"}}\n'
        "      ]}\n"
        "    ]\n"
        "  }\n"
        "}\n"
    )
    assert _handler_findings(tmp_path, "claude", body) == [(5, "CLAUDE:S:0004")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_two_broken_handlers_are_reported_on_their_own_lines(tmp_path: Path, dev_rules_dir: Path) -> None:
    body = (
        "{\n"
        '  "hooks": {\n'
        '    "PreToolUse": [\n'
        '      {"matcher": "Bash", "hooks": [\n'
        '        {"type": "command", "timeout": 5},\n'
        '        {"type": "command", "command": "\\"$CLAUDE_PROJECT_DIR\\"/.claude/hooks/guard.sh"}\n'
        "      ]},\n"
        '      {"matcher": "Edit", "hooks": [\n'
        '        {"type": "command", "timeout": 30}\n'
        "      ]}\n"
        "    ]\n"
        "  }\n"
        "}\n"
    )
    assert _handler_findings(tmp_path, "claude", body) == [(5, "CLAUDE:S:0004"), (9, "CLAUDE:S:0004")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_toml_hook_without_a_command_is_reported(tmp_path: Path, dev_rules_dir: Path) -> None:
    """Hooks declared inline in a TOML config are checked like those in a hooks file."""
    body = (
        'approval_policy = "on-request"\n'
        "\n"
        "[[hooks.PreToolUse]]\n"
        'matcher = "^Bash$"\n'
        "\n"
        "[[hooks.PreToolUse.hooks]]\n"
        'type = "command"\n'
        "timeout = 30\n"
        "\n"
        "[[hooks.PreToolUse.hooks]]\n"
        'command = "./scripts/audit.sh"\n'
    )
    findings = _handler_findings(tmp_path, "codex", body, config_rel=".codex/config.toml")
    assert findings == [(6, "CODEX:S:0005"), (10, "CODEX:S:0004")]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_toml_config_with_valid_hooks_is_clean(tmp_path: Path, dev_rules_dir: Path) -> None:
    body = (
        "[[hooks.PostToolUse]]\n"
        'matcher = "Write|Edit"\n'
        "\n"
        "[[hooks.PostToolUse.hooks]]\n"
        'type = "command"\n'
        'command = "./scripts/format.sh"\n'
    )
    assert _handler_findings(tmp_path, "codex", body, config_rel=".codex/config.toml") == []


# ---------------------------------------------------------------------------
# Each agent's rules keep their meaning
# ---------------------------------------------------------------------------

_BROKEN = [
    pytest.param(
        "claude",
        '{"hooks": {"Stop": [{"hooks": [\n'
        ' {"type": "command"},\n'
        ' {"command": "\\"$CLAUDE_PROJECT_DIR\\"/a.sh"},\n'
        ' {"type": "shell", "command": "$CLAUDE_PROJECT_DIR/b.sh"},\n'
        ' {"type": "prompt", "prompt": ""},\n'
        ' {"type": "agent", "timeout": 60}\n'
        "]}]}}\n",
        [
            (2, "CLAUDE:S:0004"),
            (3, "CLAUDE:S:0006"),
            (4, "CLAUDE:S:0006"),
            (5, "CLAUDE:S:0007"),
            (6, "CLAUDE:S:0007"),
        ],
        id="claude",
    ),
    pytest.param(
        "claude",
        '{"hooks": {"Stop": [{"hooks": [\n'
        ' {"type": "prompt", "prompt": "Check the task is complete."},\n'
        ' {"type": "command", "command": "/home/user/project/.claude/hooks/stop.sh"}\n'
        "]}]}}\n",
        [(3, "CLAUDE:G:0001")],
        id="claude-no-project-dir",
    ),
    pytest.param(
        "codex",
        '{"hooks": {"PreToolUse": [{"matcher": "^Bash$", "hooks": [\n'
        ' {"type": "command", "timeout": 30},\n'
        ' {"command": "./scripts/audit.sh"},\n'
        ' {"type": "prompt"},\n'
        ' {"type": "command", "command": "/home/user/project/guard.sh"}\n'
        "]}]}}\n",
        [
            (2, "CODEX:S:0005"),
            (3, "CODEX:S:0004"),
            (4, "CODEX:S:0004"),
            (4, "CORE:S:0030"),
            (5, "CORE:G:0006"),
        ],
        id="codex",
    ),
    pytest.param(
        "copilot",
        '{"version": 1, "hooks": {"sessionStart": [\n'
        ' {"type": "command", "bash": "./scripts/start.sh", "env": {"LOG_LEVEL": "INFO"}},\n'
        ' {"cwd": "scripts", "env": {"bash": "not the handler\'s own"}},\n'
        ' {"type": "shell", "bash": "./scripts/start.sh"}\n'
        "]}}\n",
        [(3, "COPILOT:S:0005"), (4, "COPILOT:S:0004")],
        id="copilot",
    ),
    pytest.param(
        "cursor",
        '{"version": 1, "hooks": {"afterFileEdit": [\n'
        ' {"command": ".cursor/hooks/format.sh"},\n'
        ' {"timeout": 30},\n'
        ' {"type": "shell", "command": "./a.sh"},\n'
        ' {"type": "prompt", "prompt": ""},\n'
        ' {"command": "/home/user/project/.cursor/hooks/audit.sh"}\n'
        "]}}\n",
        [(3, "CURSOR:S:0004"), (4, "CURSOR:S:0003"), (5, "CURSOR:S:0005"), (6, "CURSOR:G:0001")],
        id="cursor",
    ),
    pytest.param(
        "antigravity",
        "{\n"
        ' "lint": {"PostToolUse": [{"matcher": "run_command", "hooks": [\n'
        '  {"type": "command", "command": "./scripts/lint.sh", "timeout": 10},\n'
        '  {"type": "command", "timeout": 10},\n'
        '  {"type": "prompt", "command": "./scripts/check.sh"}\n'
        " ]}]},\n"
        ' "reminder": {"PreInvocation": [\n'
        '  {"timeout": 10}\n'
        " ]}\n"
        "}\n",
        [(4, "ANTIGRAVITY:S:0003"), (5, "ANTIGRAVITY:S:0002"), (8, "ANTIGRAVITY:S:0003")],
        id="antigravity",
    ),
]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("agent", "body", "expected"), _BROKEN)
def test_each_broken_handler_draws_its_rule_on_its_line(
    tmp_path: Path, dev_rules_dir: Path, agent: str, body: str, expected: list[tuple[int, str]]
) -> None:
    assert _handler_findings(tmp_path, agent, body) == expected


_VALID = [
    pytest.param(
        "claude",
        {
            "permissions": {"deny": ["Read(./secrets/**)"]},
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "Bash",
                        "hooks": [{"type": "command", "command": '"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard.sh'}],
                    }
                ],
                "PostToolUse": [
                    {
                        "matcher": "Edit",
                        "hooks": [
                            {"type": "http", "url": "https://hooks.example.test/edit", "headers": {"X": "1"}},
                            {"type": "mcp_tool", "server": "scanner", "tool": "scan"},
                        ],
                    }
                ],
                "Stop": [{"hooks": [{"type": "prompt", "prompt": "Check that the task is complete."}]}],
            },
            "statusLine": {"type": "command"},
        },
        id="claude",
    ),
    pytest.param(
        "codex",
        {
            "hooks": {
                "PostToolUse": [
                    {
                        "matcher": "Write|Edit",
                        "hooks": [
                            {"type": "command", "command": "./scripts/format.sh"},
                            {"type": "mcp_tool", "server": "scanner", "tool": "scan_patch", "input": {"p": "x"}},
                        ],
                    }
                ]
            }
        },
        id="codex",
    ),
    pytest.param(
        "copilot",
        {
            "version": 1,
            "hooks": {
                "preToolUse": [
                    {"bash": "./scripts/guard.sh", "powershell": "./scripts/guard.ps1", "env": {"A": "1"}},
                    {"type": "http", "url": "https://hooks.example.test/pre"},
                    {"type": "prompt", "prompt": "Check the change."},
                ]
            },
        },
        id="copilot",
    ),
    pytest.param(
        "cursor",
        {
            "version": 1,
            "hooks": {
                "beforeShellExecution": [{"command": "./.cursor/hooks/guard.sh"}],
                "afterFileEdit": [{"command": "$CURSOR_PROJECT_DIR/hooks/format.sh", "matcher": "Write"}],
                "beforeSubmitPrompt": [{"type": "prompt", "prompt": "Is this prompt safe to send?"}],
            },
        },
        id="cursor",
    ),
    pytest.param(
        "antigravity",
        {
            "safety-gate": {
                "PreToolUse": [{"matcher": "run_command", "hooks": [{"command": "./scripts/safety-check.sh"}]}]
            },
            "reminder": {"PreInvocation": [{"type": "command", "command": "./scripts/reminder.sh", "timeout": 10}]},
        },
        id="antigravity",
    ),
]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize(("agent", "config"), _VALID)
def test_a_config_in_the_agents_documented_form_is_clean(
    tmp_path: Path, dev_rules_dir: Path, agent: str, config: dict[str, object]
) -> None:
    """Handlers in the form the agent documents draw no per-handler finding."""
    assert _handler_findings(tmp_path, agent, json.dumps(config, indent=2)) == []


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("agent", ["claude", "codex"])
def test_a_handler_listed_directly_under_an_event_is_judged_too(
    tmp_path: Path, dev_rules_dir: Path, agent: str
) -> None:
    """A handler written straight into an event's list, with no matcher group, is still checked."""
    command_rule = {"claude": "CLAUDE:S:0004", "codex": "CODEX:S:0005"}[agent]
    type_rule = {"claude": "CLAUDE:S:0006", "codex": "CODEX:S:0004"}[agent]
    body = '{"hooks": {"PreToolUse": [\n {"type": "command", "matcher": "Edit"},\n {"command": "npm run lint"}\n]}}\n'
    assert _handler_findings(tmp_path, agent, body) == [(2, command_rule), (3, type_rule)]


# ---------------------------------------------------------------------------
# What the findings carry stays as it was
# ---------------------------------------------------------------------------


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("agent", sorted(AGENT_FILES))
def test_handler_findings_keep_their_message_and_severity(tmp_path: Path, dev_rules_dir: Path, agent: str) -> None:
    """A command handler with no command is reported as a warning, with the rule's own message."""
    body = json.dumps({"hooks": {"Stop": [{"matcher": "x", "hooks": [{"type": "command"}]}]}})
    if agent == "antigravity":
        body = json.dumps({"gate": {"Stop": [{"matcher": "x", "hooks": [{"type": "command"}]}]}})
    project, files = _project(tmp_path, agent, body)
    command_rule = next(
        rule_id for rule_id, rule in load_rules(agent=agent).items() if rule.slug == "hook-command-has-field"
    )
    found = [f for f in run_m_probes(project, files, agent=agent) if f.rule == command_rule]
    expected = (
        "Command handler has no bash, powershell, command, or exec field"
        if agent == "copilot"
        else "Command handler has no command field"
    )
    assert [(f.file, f.severity, f.message) for f in found] == [(AGENT_FILES[agent][1], "warning", expected)]


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("agent", ["", *sorted(AGENT_FILES)])
def test_handler_rules_are_not_structural_rules(dev_rules_dir: Path, agent: str) -> None:
    """The per-handler hook rules stay out of the structural family under every agent."""
    every_agent = {
        rule_id
        for name in ["", *AGENT_FILES]
        for rule_id, rule in load_rules(agent=name).items()
        if rule.slug in HANDLER_RULE_SLUGS
    }
    assert len(every_agent) == 18
    assert every_agent & structural_rule_ids(agent) == set()


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("agent", sorted(AGENT_FILES))
def test_handler_finding_is_sent_as_a_located_entry(tmp_path: Path, dev_rules_dir: Path, agent: str) -> None:
    """A handler finding reaches the diagnostics request as a located entry."""
    body = json.dumps({"hooks": {"Stop": [{"matcher": "x", "hooks": [{"type": "command"}]}]}})
    if agent == "antigravity":
        body = json.dumps({"gate": {"Stop": [{"matcher": "x", "hooks": [{"type": "command"}]}]}})
    project, files = _project(tmp_path, agent, body)
    inputs = AssembleInputs(
        m_findings=run_m_probes(project, files, agent=agent),
        content_findings=[],
        client_findings=[],
        ruleset_map=None,
        scan_root=project,
        filter_agents=None,
        effective_agent=agent,
        lint_result=None,
        alias_fn=rule_aliases,
    )
    entries, structural_total = lint_request_local(inputs)
    wanted = _handler_rule_ids(agent)
    sent = [(e.file, e.line, e.severity) for e in entries if e.rule in wanted]
    assert sent == [(str(project / AGENT_FILES[agent][1]), 1, "warning")]
    assert structural_total == len(structural_rule_ids(agent))
