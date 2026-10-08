"""Host hooks: the fingerprint of the hooks in a project, and the ones that can intercept heal's file access."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from reporails_cli.core.discovery.agents import detect_agents
from reporails_cli.core.discovery.features import detect_features_filesystem
from reporails_cli.core.platform.config.config import get_agent_config
from reporails_cli.core.platform.dto.results import HookEntry
from reporails_cli.core.platform.policy.host_hooks import intercepted_tools
from reporails_cli.core.platform.runtime.merger import CombinedResult
from reporails_cli.formatters.host_hooks import host_hooks_field
from reporails_cli.formatters.json import format_combined_result
from reporails_cli.formatters.mcp import bound_validate_payload

HUB_SETTINGS = {
    "permissions": {"deny": ["Read(./.env)"]},
    "hooks": {
        "PreToolUse": [
            {"matcher": "Edit|Write", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/guard.sh"}]},
            {"matcher": "Read", "hooks": [{"type": "command", "command": "$CLAUDE_PROJECT_DIR/secrets.sh"}]},
        ],
        "PostToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "fmt.sh"}]}],
    },
}


def _write(root: Path, rel: str, body: Any) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body if isinstance(body, str) else json.dumps(body), encoding="utf-8")


def _hooks(root: Path) -> tuple[HookEntry, ...]:
    return detect_features_filesystem(root, agents=detect_agents(root)).hooks


def _entry(agent: str, event: str, matcher: str) -> HookEntry:
    return HookEntry(agent, event, matcher, "project", "f.json")


@pytest.mark.unit
@pytest.mark.subsys_gates
@pytest.mark.parametrize(
    ("agent", "event", "matcher", "tools"),
    [
        ("claude", "PreToolUse", "Edit|Write", ("Edit", "Write")),
        ("claude", "PreToolUse", "Read", ("Read",)),
        ("claude", "PreToolUse", "", ("Read", "Edit", "Write")),
        ("claude", "PreToolUse", "*", ("Read", "Edit", "Write")),
        ("claude", "PreToolUse", "MultiEdit", ("Edit",)),
        ("claude", "PreToolUse", "Bash", ()),
        ("claude", "PreToolUse", "Edit.*|Bash", ("Edit",)),
        ("claude", "PreToolUse", "Re(", ()),
        ("claude", "PostToolUse", "Edit", ()),
        ("codex", "PreToolUse", "Write", ("Write",)),
        ("antigravity", "PreToolUse", "", ("Read", "Edit", "Write")),
        ("cursor", "preToolUse", "", ("Read", "Edit", "Write")),
        ("copilot", "preToolUse", "Read", ("Read",)),
        ("copilot", "PreToolUse", "Read", ("Read",)),
        ("cursor", "postToolUse", "Read", ()),
        ("cursor", "beforeReadFile", "", ("Read",)),
        ("cursor", "afterFileEdit", "", ()),
        ("unknown-agent", "PreToolUse", "", ()),
    ],
)
def test_intercepted_tools(agent: str, event: str, matcher: str, tools: tuple[str, ...]) -> None:
    assert intercepted_tools(_entry(agent, event, matcher), get_agent_config(agent)) == tools


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_fingerprint_lists_every_hook_of_a_claude_settings_file(tmp_path: Path) -> None:
    _write(tmp_path, "CLAUDE.md", "# Project\n")
    _write(tmp_path, ".claude/settings.json", HUB_SETTINGS)
    assert [(h.agent, h.event, h.matcher, h.scope, h.file) for h in _hooks(tmp_path)] == [
        ("claude", "PreToolUse", "Edit|Write", "project", ".claude/settings.json"),
        ("claude", "PreToolUse", "Read", "project", ".claude/settings.json"),
        ("claude", "PostToolUse", "Edit", "project", ".claude/settings.json"),
    ]


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_fingerprint_reads_the_user_scope_of_a_surface(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    _write(home, ".cursor/hooks.json", {"version": 1, "hooks": {"preToolUse": [{"command": "u.sh"}]}})
    monkeypatch.setenv("HOME", str(home))
    project = tmp_path / "proj"
    _write(
        project, ".cursor/hooks.json", {"version": 1, "hooks": {"preToolUse": [{"command": "p.sh", "matcher": "Read"}]}}
    )
    _write(project, ".cursor/rules/a.mdc", "---\nalwaysApply: true\n---\nBe brief.\n")
    found = {(h.scope, h.file, h.matcher) for h in _hooks(project)}
    assert found == {("project", ".cursor/hooks.json", "Read"), ("user", "~/.cursor/hooks.json", "")}


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_a_claude_user_level_hook_is_listed_but_does_not_raise_the_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from reporails_cli.core.platform.policy.levels import determine_level_from_gates

    home = tmp_path / "home"
    user_hooks = {"hooks": {"PreToolUse": [{"matcher": "Edit", "hooks": [{"type": "command", "command": "u.sh"}]}]}}
    _write(home, ".claude/settings.json", user_hooks)
    monkeypatch.setenv("HOME", str(home))
    project = tmp_path / "proj"
    _write(project, "CLAUDE.md", "# Project\n")
    features = detect_features_filesystem(project, agents=detect_agents(project))
    data = host_hooks_field(features.hooks)
    assert [(h["agent"], h["scope"], h["file"], h["tools"]) for h in data["host_hooks"]] == [
        ("claude", "user", "~/.claude/settings.json", ["Edit"])
    ]
    assert features.hook_files == ()
    assert determine_level_from_gates(features).value != "L6"


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_settings_without_hooks_gives_no_entries_and_no_hook_file(tmp_path: Path) -> None:
    _write(tmp_path, "CLAUDE.md", "# Project\n")
    _write(tmp_path, ".claude/settings.json", {"permissions": {}})
    features = detect_features_filesystem(tmp_path, agents=detect_agents(tmp_path))
    assert (features.hooks, features.hook_files) == ((), ())


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_a_dedicated_hooks_file_with_no_entries_still_counts_for_the_level(tmp_path: Path) -> None:
    _write(tmp_path, "AGENTS.md", "# Project\n")
    _write(tmp_path, ".codex/hooks.json", {"hooks": {}})
    features = detect_features_filesystem(tmp_path, agents=detect_agents(tmp_path))
    assert features.hooks == ()
    assert features.hook_files == (tmp_path / ".codex/hooks.json",)


def _combined(root: Path) -> CombinedResult:
    return CombinedResult(hooks=_hooks(root))


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_validate_names_the_hub_hooks_that_can_intercept_reads_and_writes(tmp_path: Path) -> None:
    _write(tmp_path, "CLAUDE.md", "# Project\n")
    _write(tmp_path, ".claude/settings.json", HUB_SETTINGS)
    data = host_hooks_field(_combined(tmp_path).hooks)
    assert [(h["event"], h["matcher"], h["tools"]) for h in data["host_hooks"]] == [
        ("PreToolUse", "Edit|Write", ["Edit", "Write"]),
        ("PreToolUse", "Read", ["Read"]),
    ]
    first = data["host_hooks"][0]
    assert set(first) == {
        "agent",
        "event",
        "matcher",
        "scope",
        "file",
        "tools",
        "identity_fields",
        "fires_in_subagents",
        "opt_out",
    }
    assert (first["agent"], first["scope"], first["file"]) == ("claude", "project", ".claude/settings.json")


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_cursor_pre_tool_hook_with_empty_matcher_covers_all_three_tools(tmp_path: Path) -> None:
    _write(tmp_path, ".cursor/rules/a.mdc", "---\nalwaysApply: true\n---\nBe brief.\n")
    _write(
        tmp_path, ".cursor/hooks.json", {"version": 1, "hooks": {"preToolUse": [{"command": "./g.sh", "matcher": ""}]}}
    )
    (hook,) = host_hooks_field(_combined(tmp_path).hooks)["host_hooks"]
    assert (hook["agent"], hook["tools"]) == ("cursor", ["Read", "Edit", "Write"])


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_host_hooks_key_is_omitted_when_no_hook_intercepts(tmp_path: Path) -> None:
    assert host_hooks_field(CombinedResult().hooks) == {}
    _write(tmp_path, "CLAUDE.md", "# Project\n")
    _write(
        tmp_path,
        ".claude/settings.json",
        {"hooks": {"PostToolUse": [{"matcher": "Edit", "hooks": [{"command": "f"}]}]}},
    )
    assert host_hooks_field(_combined(tmp_path).hooks) == {}


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_facts_are_unconfirmed_when_the_agent_config_has_none(tmp_path: Path) -> None:
    _write(tmp_path, ".cursor/rules/a.mdc", "---\nalwaysApply: true\n---\nBe brief.\n")
    _write(
        tmp_path, ".cursor/hooks.json", {"version": 1, "hooks": {"preToolUse": [{"command": "./g.sh", "matcher": ""}]}}
    )
    first = host_hooks_field(_combined(tmp_path).hooks)["host_hooks"][0]
    assert (first["fires_in_subagents"], first["identity_fields"], first["opt_out"]) == (
        "unconfirmed",
        [],
        "unconfirmed",
    )


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_get_agent_config_reads_subagent_hook_facts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.platform.config.config import get_agent_config

    config = tmp_path / "config.yml"
    config.write_text(
        "agent: claude\n"
        "subagent_hooks:\n"
        "  fire_in_subagents: {value: 'yes', source: https://example.test/a}\n"
        "  identifies_agent: {value: 'yes', fields: [agent_id, agent_type], source: https://example.test/b}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("reporails_cli.core.platform.config.bootstrap.get_agent_config_path", lambda _agent: config)
    facts = get_agent_config("claude").subagent_hooks
    assert (facts.fire_in_subagents.value, facts.fire_in_subagents.source) == ("yes", "https://example.test/a")
    assert facts.identifies_agent.fields == ("agent_id", "agent_type")
    assert facts.extension_opt_out.value == "unconfirmed"


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_get_agent_config_without_the_key_reads_unconfirmed() -> None:
    from reporails_cli.core.platform.config.config import get_agent_config

    facts = get_agent_config("cursor").subagent_hooks
    assert (facts.fire_in_subagents.value, facts.identifies_agent.value, facts.extension_opt_out.value) == (
        "unconfirmed",
    ) * 3


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_bounded_validate_reply_keeps_host_hooks() -> None:
    hooks = [{"agent": "claude", "event": "PreToolUse", "matcher": "Read", "tools": ["Read"]}]
    files = {f"f{i}.md": {"count": 1, "findings": [{"rule": "r", "line": 1}]} for i in range(40)}
    bounded = bound_validate_payload({"files": files, "level": "L2", "host_hooks": hooks})
    assert bounded["host_hooks"] == hooks
    assert bound_validate_payload({"files": {}, "host_hooks": hooks})["host_hooks"] == hooks


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_check_json_never_carries_host_hooks(tmp_path: Path) -> None:
    """`ails check -f json` stays the same on every machine: no hook list, even with hooks found."""
    _write(tmp_path, "CLAUDE.md", "# Project\n")
    _write(tmp_path, ".claude/settings.json", HUB_SETTINGS)
    assert _combined(tmp_path).hooks
    assert "host_hooks" not in format_combined_result(_combined(tmp_path))


@pytest.mark.unit
@pytest.mark.subsys_server
def test_validate_payload_carries_host_hooks(tmp_path: Path) -> None:
    from reporails_cli.interfaces.mcp.tools import with_host_hooks

    _write(tmp_path, "CLAUDE.md", "# Project\n")
    _write(tmp_path, ".claude/settings.json", HUB_SETTINGS)
    combined = _combined(tmp_path)
    payload = with_host_hooks(format_combined_result(combined), combined)
    assert [h["matcher"] for h in payload["host_hooks"]] == ["Edit|Write", "Read"]
    assert "host_hooks" not in with_host_hooks({"a": 1}, CombinedResult())


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_one_reader_parses_a_hook_config_in_both_discovery_and_the_hook_check(tmp_path: Path) -> None:
    """A BOM-prefixed JSON file and a TOML file read the same way everywhere; one over the size cap reads as nothing."""
    from reporails_cli.core.platform.utils.hook_config import read_hook_config

    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf" + json.dumps({"hooks": {"Stop": [{"command": "x"}]}}).encode())
    toml = tmp_path / "h.toml"
    toml.write_text('[[hooks.Stop]]\ncommand = "x"\n', encoding="utf-8")
    big = tmp_path / "big.json"
    big.write_text(" " * 1_048_577 + "{}", encoding="utf-8")
    assert read_hook_config(bom).data["hooks"]["Stop"][0]["command"] == "x"  # type: ignore[union-attr]
    assert read_hook_config(toml).data["hooks"]["Stop"][0]["command"] == "x"  # type: ignore[union-attr]
    assert read_hook_config(big) is None
    assert read_hook_config(tmp_path / "missing.json") is None


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_discovery_parses_each_hook_file_once(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.discovery import features
    from reporails_cli.core.platform.utils import hook_config

    _write(tmp_path, "CLAUDE.md", "# Project\n")
    _write(tmp_path, ".claude/settings.json", HUB_SETTINGS)
    reads: list[Path] = []
    real = hook_config.read_hook_config

    def counting(path: Path) -> object:
        reads.append(path)
        return real(path)

    monkeypatch.setattr(features, "read_hook_config", counting)
    assert _hooks(tmp_path)
    assert len(reads) == len(set(reads)) == 1


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_a_cursor_before_read_file_hook_is_listed_with_the_read_tool(tmp_path: Path) -> None:
    _write(tmp_path, ".cursor/rules/a.mdc", "---\nalwaysApply: true\n---\nBe brief.\n")
    _write(tmp_path, ".cursor/hooks.json", {"version": 1, "hooks": {"beforeReadFile": [{"command": "g.sh"}]}})
    data = host_hooks_field(_hooks(tmp_path))
    assert [(h["event"], h["tools"]) for h in data["host_hooks"]] == [("beforeReadFile", ["Read"])]


@pytest.mark.unit
@pytest.mark.subsys_gates
def test_the_agent_config_is_read_once_per_agent_for_many_hooks(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.formatters import host_hooks

    calls: list[str] = []
    real = host_hooks.get_agent_config

    def counting(agent: str) -> object:
        calls.append(agent)
        return real(agent)

    monkeypatch.setattr(host_hooks, "get_agent_config", counting)
    hooks = [_entry("claude", "PreToolUse", m) for m in ("Read", "Edit", "Write")]
    assert len(host_hooks.host_hooks_field(hooks)["host_hooks"]) == 3
    assert calls == ["claude"]
