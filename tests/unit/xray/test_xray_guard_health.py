"""The Hooks group lists every declared hook with whether it can fire, built from settings and transcript alone."""

from __future__ import annotations

import json
import socket
from collections.abc import Callable
from pathlib import Path

import pytest

from reporails_cli.core.discovery.agent_discovery import claude_project_dir
from reporails_cli.core.platform.config import claude_settings
from reporails_cli.core.platform.dto.xray import XrayView
from reporails_cli.core.platform.dto.xray_sources import HookDetail
from reporails_cli.core.xray import session as xray_session
from tests.unit.xray.test_xray_session import HANDOFFS, _project, _session, _view

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]


@pytest.fixture(autouse=True)
def _home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A home of its own, so no setting or session of the machine's user reaches the view."""
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    return home


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


def _funnel(view: XrayView) -> tuple[int, int | None]:
    """The header's declared and fired counts, less the fixture session's own SessionStart and PreToolUse:Edit hooks,
    which no file declares and which count as an entry each."""
    row = next(row for row in view.verdict.funnel if row.kind == "hook")
    assert row.loaded is not None
    return row.on_disk - 2, row.loaded - 2


def test_one_handler_that_fired_under_two_names_counts_once_in_the_header(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Grep|Glob")]})
    session = _session(tmp_path, HANDOFFS, root)
    command = f'"{root}"/.claude/hooks/guard.sh'
    _fire(tmp_path / HANDOFFS / "session.jsonl", command, "PreToolUse:Grep", uuid="h1")
    _fire(tmp_path / HANDOFFS / "session.jsonl", command, "PreToolUse:Glob", uuid="h2")
    assert _funnel(_view(session)) == (1, 1)


def test_two_handlers_that_fired_under_one_name_count_twice_in_the_header(tmp_path: Path) -> None:
    root = _project(tmp_path)
    other = root / ".claude" / "hooks" / "other.sh"
    _settings(root, {"PreToolUse": [_guard("Bash")]})
    other.write_text("#!/bin/sh\nexit 0\n")
    other.chmod(0o755)
    settings = json.loads((root / ".claude" / "settings.json").read_text())
    settings["hooks"]["PreToolUse"][0]["hooks"].append(
        {"type": "command", "command": '"$CLAUDE_PROJECT_DIR"/.claude/hooks/other.sh'}
    )
    (root / ".claude" / "settings.json").write_text(json.dumps(settings))
    session = _session(tmp_path, HANDOFFS, root)
    _fire(tmp_path / HANDOFFS / "session.jsonl", f'"{root}"/.claude/hooks/guard.sh', uuid="h1")
    _fire(tmp_path / HANDOFFS / "session.jsonl", f'"{root}"/.claude/hooks/other.sh', uuid="h2")
    assert _funnel(_view(session)) == (2, 2)


def test_a_hook_that_fired_but_no_read_file_declares_counts_as_its_own_entry(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Bash")]})
    session = _session(tmp_path, HANDOFFS, root)
    _fire(tmp_path / HANDOFFS / "session.jsonl", "/plugins/other/run.sh", "PostToolUse:Bash", "PostToolUse")
    assert _funnel(_view(session)) == (2, 1)  # the hook that fired undeclared is one more entry, and fired


def _turn_off(path: Path, *, value: bool) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.loads(path.read_text()) if path.is_file() else {}
    path.write_text(json.dumps({**data, "disableAllHooks": value}))


def test_disable_all_hooks_in_a_settings_file_gives_every_declared_hook_the_reason(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Bash"), _guard("Edit")]})
    _turn_off(root / ".claude" / "settings.json", value=True)
    hooks = _hooks(_view(_session(tmp_path, HANDOFFS, root)))
    assert {detail.status for name, detail in hooks.items() if "guard.sh" in name} == {
        "never fired \u00b7 all hooks are turned off"
    }
    assert {detail.health.cannot_fire for name, detail in hooks.items() if "guard.sh" in name} == {"all_hooks_off"}
    assert {detail.health.recovery for name, detail in hooks.items() if "guard.sh" in name} == {
        "disableAllHooks is true in .claude/settings.json; set it to false there"
    }


def test_a_project_setting_turns_hooks_back_on_over_the_users_disable_all_hooks(tmp_path: Path, _home: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Bash")]})
    _turn_off(_home / ".claude" / "settings.json", value=True)
    _turn_off(root / ".claude" / "settings.json", value=False)
    hooks = _hooks(_view(_session(tmp_path, HANDOFFS, root)))
    assert hooks["PreToolUse:Bash \u00b7 guard.sh"].health.cannot_fire is None


def test_only_managed_settings_turn_off_the_hooks_managed_settings_declare(
    tmp_path: Path, _home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    _settings(root, {})
    managed = tmp_path / "managed" / "managed-settings.json"
    managed.parent.mkdir()
    managed.write_text(json.dumps({"hooks": {"PreToolUse": [_guard("Read")]}}))
    patterns = claude_settings._settings_patterns()
    monkeypatch.setattr(
        claude_settings, "_settings_patterns", lambda: {**patterns, "managed": [str(managed)], "managed_dropin": []}
    )
    _turn_off(_home / ".claude" / "settings.json", value=True)
    session = _session(tmp_path, HANDOFFS, root)
    hooks = _hooks(_view(session))
    assert hooks["PreToolUse:Read \u00b7 guard.sh"].health.cannot_fire is None
    _turn_off(managed, value=True)
    hooks = _hooks(_view(session))
    assert hooks["PreToolUse:Read \u00b7 guard.sh"].health.cannot_fire == "all_hooks_off"


Spawned = list[Callable[[], None]]


def _earlier_session(root: Path, name: str, command: str, tool: str = "Bash") -> None:
    folder = claude_project_dir(root)
    folder.mkdir(parents=True, exist_ok=True)
    _fire(folder / f"{name}.jsonl", command, f"PreToolUse:{tool}")


def test_a_hook_that_fired_in_an_earlier_session_reads_so_once_the_background_read_is_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Bash")]})
    jobs: Spawned = []
    monkeypatch.setattr(xray_session, "_in_background", jobs.append)
    session = _session(tmp_path, HANDOFFS, root)
    _earlier_session(root, "previous", f'"{root}"/.claude/hooks/guard.sh')
    first = _view(session)
    waiting = _hooks(first)["PreToolUse:Bash \u00b7 guard.sh"]
    assert waiting.status == "not fired this session \u00b7 checking earlier sessions\u2026"
    assert len(jobs) == 1
    jobs[0]()
    after = _view(session)
    found = _hooks(after)["PreToolUse:Bash \u00b7 guard.sh"]
    assert found.status == "not this session \u00b7 last fired {when} (session {session})"
    assert found.earlier is not None and found.earlier.session == "previous"
    assert found.to_json()["earlier"] == {"session": "previous", "at": found.earlier.at}
    assert after.version > first.version
    assert len(jobs) == 1  # one read per session, not one per view


def test_a_hook_no_earlier_session_fired_reads_never_fired_once_the_read_is_done(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Bash"), _guard("Grep")]})
    session = _session(tmp_path, HANDOFFS, root)
    _earlier_session(root, "previous", f'"{root}"/.claude/hooks/guard.sh', "Grep")
    hooks = _hooks(_view(session))
    assert hooks["PreToolUse:Bash \u00b7 guard.sh"].status == "never fired"
    assert hooks["PreToolUse:Grep \u00b7 guard.sh"].earlier is not None


def test_a_hook_that_cannot_fire_and_fired_earlier_says_both(tmp_path: Path) -> None:
    root = _project(tmp_path)
    _settings(root, {"PreToolUse": [_guard("Bash")]})
    (root / ".claude" / "hooks" / "guard.sh").chmod(0o644)
    session = _session(tmp_path, HANDOFFS, root)
    _earlier_session(root, "previous", f'"{root}"/.claude/hooks/guard.sh')
    found = _hooks(_view(session))["PreToolUse:Bash \u00b7 guard.sh"]
    assert found.status == "not this session \u00b7 last fired {when} (session {session}) \u00b7 not executable"
