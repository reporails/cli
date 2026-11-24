"""The Hooks group lists every declared hook with whether it can fire, built from settings and transcript alone."""

from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.xray import XrayView
from reporails_cli.core.platform.dto.xray_sources import HookDetail
from tests.unit.xray.test_xray_session import HANDOFFS, _project, _session, _view

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]


def _declare(root: Path) -> None:
    hooks = root / ".claude" / "hooks"
    hooks.mkdir()
    for name, mode in (("ran.sh", 0o755), ("silent.sh", 0o644)):
        (hooks / name).write_text("#!/bin/sh\nexit 0\n")
        (hooks / name).chmod(mode)
    handlers = [
        {"type": "command", "command": '"$CLAUDE_PROJECT_DIR"/.claude/hooks/ran.sh'},
        {"type": "command", "command": '"$CLAUDE_PROJECT_DIR"/.claude/hooks/silent.sh'},
    ]
    settings = {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": handlers}]}}
    (root / ".claude" / "settings.json").write_text(json.dumps(settings))


def _fire(session_file: Path, command: str) -> None:
    attachment = {
        "type": "hook_success",
        "hookName": "PreToolUse:Bash",
        "hookEvent": "PreToolUse",
        "command": command,
        "exitCode": 0,
        "durationMs": 3,
        "stdout": "",
        "stderr": "",
        "content": "",
    }
    row = {"type": "attachment", "timestamp": "2026-10-17T16:54:55.000Z", "sessionId": "s", "uuid": "h1"}
    with session_file.open("a") as handle:
        handle.write(json.dumps({**row, "attachment": attachment}) + "\n")


def _hooks(view: XrayView) -> dict[str, HookDetail]:
    details = {source.name: source.detail for source in view.sources if source.kind == "hook"}
    return {name: detail for name, detail in details.items() if isinstance(detail, HookDetail)}


def test_a_declared_hook_that_never_fired_and_cannot_is_listed_with_its_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    _declare(root)
    session = _session(tmp_path, HANDOFFS, root)

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise OSError("network blocked")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    _fire(tmp_path / HANDOFFS / "session.jsonl", f'"{root}"/.claude/hooks/ran.sh')
    view = _view(session)
    hooks = _hooks(view)
    ran = hooks["PreToolUse:Bash"]
    assert ran.firing_count == 1 and ran.status.startswith("fired 1\u00d7 \u00b7 last ")
    never = hooks["PreToolUse:Bash \u00b7 silent.sh"]
    assert never.status == "never fired \u00b7 not executable"
    assert never.health.recovery == f"chmod +x {root / '.claude' / 'hooks' / 'silent.sh'}"
    assert (never.event, never.matcher) == ("PreToolUse", "Bash")
    funnel = next(row for row in view.verdict.funnel if row.kind == "hook")
    assert funnel.on_disk - funnel.loaded == 1  # only the non-executable hook did not fire
