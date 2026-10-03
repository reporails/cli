"""Hook handler findings as `ails check` reports them.

A hook config is read as data: only the handlers it declares are judged, each broken
handler is reported on the line where it starts, and hooks declared inline in a TOML
config are checked like those in a hooks file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from reporails_cli.interfaces.cli.main import app

runner = CliRunner()

MAIN_FILE = "# Test Project\n\nAlways run the tests before pushing.\n\nNEVER force-push to main.\n"


def _config_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, agent: str, main_rel: str, config_rel: str, body: str
) -> list[tuple[int, str, str]]:
    """Run `ails check <config file>` in a project and return (line, rule, severity) on that file."""
    project = tmp_path / "proj"
    for rel, text in ((main_rel, MAIN_FILE), (config_rel, body)):
        path = project / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    monkeypatch.chdir(project)
    result = runner.invoke(app, ["check", config_rel, "--agent", agent, "-f", "json"])
    data = json.loads(result.output[result.output.index("{") :])
    findings = data.get("files", {}).get(config_rel, {}).get("findings", [])
    return sorted((f["line"], f["rule"], f["severity"]) for f in findings)


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_each_broken_command_handler_is_reported_on_its_own_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Two command handlers with no command — one of them holding a nested object — give two findings."""
    body = (
        "{\n"
        '  "hooks": {\n'
        '    "PreToolUse": [\n'
        '      {"matcher": "Bash", "hooks": [\n'
        '        {"type": "command", "env": {"A": "1"}},\n'
        '        {"type": "command", "command": "\\"$CLAUDE_PROJECT_DIR\\"/.claude/hooks/guard.sh"}\n'
        "      ]},\n"
        '      {"matcher": "Edit", "hooks": [\n'
        '        {"type": "command", "timeout": 30}\n'
        "      ]}\n"
        "    ]\n"
        "  }\n"
        "}\n"
    )
    findings = _config_findings(tmp_path, monkeypatch, "claude", "CLAUDE.md", ".claude/settings.json", body)

    assert [f for f in findings if f[1] == "CLAUDE:S:0004"] == [
        (5, "CLAUDE:S:0004", "warning"),
        (9, "CLAUDE:S:0004", "warning"),
    ]


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_objects_outside_the_hook_block_are_not_reported_as_handlers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Valid hooks beside an unrelated array of objects holding `command` draw no handler finding."""
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
    findings = _config_findings(tmp_path, monkeypatch, "claude", "CLAUDE.md", ".claude/settings.json", body)

    handler_rules = {"CLAUDE:S:0004", "CLAUDE:S:0006", "CLAUDE:S:0007", "CLAUDE:G:0001"}
    assert [f for f in findings if f[1] in handler_rules] == []


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_empty_hooks_file_reports_no_command_handler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A hooks file holding only `{}` is reported for its missing events, not for a handler it does not have."""
    findings = _config_findings(tmp_path, monkeypatch, "antigravity", "AGENTS.md", ".agents/hooks.json", "{}")

    rules = {rule for _, rule, _ in findings}
    assert "ANTIGRAVITY:S:0001" in rules
    assert "ANTIGRAVITY:S:0003" not in rules


@pytest.mark.e2e
@pytest.mark.subsys_lint
@pytest.mark.requires_model
def test_toml_hooks_are_checked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A command hook with no command in a TOML config is reported on its table's line."""
    body = (
        'approval_policy = "on-request"\n'
        "\n"
        "[[hooks.PreToolUse]]\n"
        'matcher = "^Bash$"\n'
        "\n"
        "[[hooks.PreToolUse.hooks]]\n"
        'type = "command"\n'
        "timeout = 30\n"
    )
    findings = _config_findings(tmp_path, monkeypatch, "codex", "AGENTS.md", ".codex/config.toml", body)

    assert (6, "CODEX:S:0005", "warning") in findings
