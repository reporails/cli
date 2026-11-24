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


def _fire(
    session_file: Path,
    command: str | None,
    name: str = "PreToolUse:Bash",
    event: str = "PreToolUse",
    uuid: str = "h1",
) -> None:
    attachment = {
        "type": "hook_success",
        "hookName": name,
        "hookEvent": event,
        "exitCode": 0,
        "durationMs": 3,
        "stdout": "",
        "stderr": "",
        "content": "",
    }
    if command is not None:
        attachment["command"] = command
    row = {"type": "attachment", "timestamp": "2026-10-17T16:54:55.000Z", "sessionId": "s", "uuid": uuid}
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


def _settings(root: Path, hooks: dict[str, list[dict[str, object]]]) -> None:
    script = root / ".claude" / "hooks" / "guard.sh"
    script.parent.mkdir(exist_ok=True)
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o755)
    (root / ".claude" / "settings.json").write_text(json.dumps({"hooks": hooks}))


def _never_fired(hooks: dict[str, HookDetail]) -> set[str]:
    """The declared guard hooks no firing ran."""
    return {name for name, detail in hooks.items() if name.endswith("\u00b7 guard.sh") and not detail.firing_count}


def _guard(matcher: str | None = None) -> dict[str, object]:
    handler = {"type": "command", "command": '"$CLAUDE_PROJECT_DIR"/.claude/hooks/guard.sh'}
    return {"hooks": [handler]} if matcher is None else {"matcher": matcher, "hooks": [handler]}


def test_one_command_declared_under_two_matchers_is_marked_run_under_each(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Bash"), _guard("Edit")]})
    session = _session(tmp_path, HANDOFFS, root)
    command = f'"{root}"/.claude/hooks/guard.sh'
    _fire(tmp_path / HANDOFFS / "session.jsonl", command, "PreToolUse:Bash", uuid="h1")
    _fire(tmp_path / HANDOFFS / "session.jsonl", command, "PreToolUse:Edit", uuid="h2")
    assert _never_fired(_hooks(_view(session))) == set()


def test_a_firing_marks_every_declaration_of_its_command_it_matches(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Edit|Write"), _guard("Edit"), _guard("Read")]})
    session = _session(tmp_path, HANDOFFS, root)
    command = f'"{root}"/.claude/hooks/guard.sh'
    _fire(tmp_path / HANDOFFS / "session.jsonl", command, "PreToolUse:Edit")
    assert _never_fired(_hooks(_view(session))) == {"PreToolUse:Read \u00b7 guard.sh"}


def test_a_hook_whose_output_names_no_command_is_marked_run_when_one_declaration_fits(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"UserPromptSubmit": [_guard()]})
    session = _session(tmp_path, HANDOFFS, root)
    _fire(tmp_path / HANDOFFS / "session.jsonl", None, "UserPromptSubmit", "UserPromptSubmit")
    hooks = _hooks(_view(session))
    assert _never_fired(hooks) == set()
    assert hooks["UserPromptSubmit"].firing_count == 1


def test_a_hook_whose_output_names_no_command_is_not_guessed_among_several_declarations(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"UserPromptSubmit": [_guard(), _guard()]})
    session = _session(tmp_path, HANDOFFS, root)
    _fire(tmp_path / HANDOFFS / "session.jsonl", None, "UserPromptSubmit", "UserPromptSubmit")
    assert _never_fired(_hooks(_view(session))) == {"UserPromptSubmit \u00b7 guard.sh"}


def test_a_hook_reports_when_it_last_fired_in_seconds_from_the_session_start_with_its_time_left_to_the_page(
    tmp_path: Path,
) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Bash")]})
    session = _session(tmp_path, HANDOFFS, root)
    _fire(tmp_path / HANDOFFS / "session.jsonl", f'"{root}"/.claude/hooks/guard.sh')
    ran = _hooks(_view(session))["PreToolUse:Bash"]
    assert ran.status == "fired 1\u00d7 \u00b7 last {time}"
    assert isinstance(ran.last_fired, float) and ran.last_fired >= 0
    assert ran.to_json()["last_fired"] == ran.last_fired
