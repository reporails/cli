"""Where the page says a hook or an MCP server is declared, and where an out-of-project link leads."""

from __future__ import annotations

import errno
import json
from pathlib import Path

import pytest

from reporails_cli.core.platform.config.claude_settings import mcp_declarations
from reporails_cli.core.platform.dto.xray_build import Frame
from reporails_cli.core.platform.dto.xray_sources import ArtifactFile
from reporails_cli.core.xray.artifacts import build_artifacts, left_out_files
from reporails_cli.core.xray.graph.hook_sources import _declared_commands

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

SERVER = {"command": "x"}


def test_mcp_declarations_list_the_winning_scope_first(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"both": SERVER}}))
    claude = {"mcpServers": {"both": SERVER}, "projects": {str(root): {"mcpServers": {"both": SERVER}}}}
    (Path.home() / ".claude.json").write_text(json.dumps(claude))
    found = [item.scope for item in mcp_declarations(root, []) if item.name == "both"]
    assert found == ["local", "project", "user"]


def test_hook_config_named_under_home_is_read_where_it_lives(tmp_path: Path) -> None:
    hooks = Path.home() / ".claude" / "plugins" / "p" / "hooks" / "hooks.json"
    hooks.parent.mkdir(parents=True)
    hooks.write_text(json.dumps({"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "echo hi"}]}]}}))
    listed = ArtifactFile(str(hooks), "hook", "plugin", "p", "hooks", None, None)
    shown = build_artifacts([listed], {}, tmp_path, advertised={})
    frame = Frame(0.0, tmp_path, {}, {}, {}, False)
    assert _declared_commands(shown, frame) == [("echo hi", "~/.claude/plugins/p/hooks/hooks.json")]


def test_a_link_out_of_the_project_leads_to_a_path_shown_under_home(tmp_path: Path) -> None:
    root = tmp_path / "proj"
    root.mkdir()
    target = Path.home() / "shared" / "CLAUDE.md"
    target.parent.mkdir()
    target.write_text("# shared\n")
    link = root / "CLAUDE.md"
    link.symlink_to(target)
    item = ArtifactFile(str(link), "instructions", "project", None, "CLAUDE.md", None, None)
    assert left_out_files([item], root)[str(link)].outside == "~/shared/CLAUDE.md"


def test_launch_settings_show_when_no_launch_recorded_a_request() -> None:
    from reporails_cli.core.platform.dto.events import SubagentMeta
    from reporails_cli.core.xray.graph.shapes import launched_with

    metas = {"a1": SubagentMeta(None, None, None, 1, None, False, True, "opus", False)}
    launch = launched_with(["a1"], {}, metas)
    assert launch is not None
    assert launch.system_tokens_est is None
    assert ("Model asked for", "opus") in launch.settings
    assert launched_with(["a2"], {}, metas) is None


def test_code_stamp_skips_a_file_that_vanishes_while_it_is_read(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.platform.utils import version

    real_stat = Path.stat
    gone = {"seen": 0}

    def stat_once_missing(self: Path, **kwargs: bool) -> object:
        # The file passes the `is_file` test, then is gone when its size is read.
        if self.suffix == ".py":
            gone["seen"] += 1
            if gone["seen"] == 2:
                raise FileNotFoundError(errno.ENOENT, "gone", str(self))
        return real_stat(self, **kwargs)

    monkeypatch.setattr(Path, "stat", stat_once_missing)
    assert version.installed_code_stamp()
    assert gone["seen"] >= 2


def test_hook_output_says_when_it_was_cut(tmp_path: Path) -> None:
    from reporails_cli.core.xray.session import HOOK_OUTPUT_CHARS, XraySession

    attachment = {
        "type": "hook_success",
        "hookName": "PreToolUse:Bash",
        "hookEvent": "PreToolUse",
        "toolUseID": "toolu_1",
        "command": "echo",
        "exitCode": 0,
        "durationMs": 7,
        "stdout": "x" * (HOOK_OUTPUT_CHARS + 5),
        "stderr": "",
        "content": "",
    }
    row = {
        "type": "attachment",
        "timestamp": "2026-10-30T20:11:01.000Z",
        "sessionId": "s",
        "version": "2.1.308",
        "cwd": str(tmp_path),
        "attachment": attachment,
        "uuid": "row-1",
    }
    session_file = tmp_path / "session.jsonl"
    session_file.write_text(json.dumps(row) + "\n", encoding="utf-8")
    session = XraySession(tmp_path, session_file)
    session.refresh()
    found = session.hook_output("row-1")
    assert found is not None
    assert (len(found[0]), found[1]) == (HOOK_OUTPUT_CHARS, True)
