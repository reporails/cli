"""Which session the x-ray opens, the switcher's facts per session, and the page a project has running."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest

from reporails_cli.core.discovery.agent_discovery import claude_project_dir
from reporails_cli.core.eventbus.transcript import first_prompt_text, session_transcript
from reporails_cli.core.platform.config import bootstrap
from reporails_cli.core.platform.contract.errors import XrayPageError
from reporails_cli.core.platform.dto.xray import PickedSession, XrayPage
from reporails_cli.core.xray import pages
from reporails_cli.core.xray.pages import forget_page, register_page, running_page, start_page
from reporails_cli.core.xray.sessions import pick_session, session_entries

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "eventbus" / "transcript" / "2.1.308" / "session.jsonl"
SESSION_ENV = "CLAUDE_CODE_SESSION_ID"
PROMPT_ROW = {
    "type": "user",
    "uuid": "u-1",
    "timestamp": "2026-10-30T20:10:30.000Z",
    "sessionId": "x",
    "promptSource": "typed",
    "origin": {"kind": "human"},
    "message": {"role": "user", "content": "open the settings page"},
}


@pytest.fixture(name="project")
def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A project folder whose Claude transcripts live under a temporary HOME."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setattr(bootstrap, "REPORAILS_HOME", tmp_path / "home" / ".reporails")
    monkeypatch.delenv(SESSION_ENV, raising=False)
    root = tmp_path / "proj"
    (root / ".git").mkdir(parents=True)
    return root


def _session(root: Path, name: str, age_s: int, *, rows: list[dict[str, object]] | None = None) -> Path:
    """A transcript `name` of the project last written `age_s` seconds ago."""
    path = session_transcript(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    if rows is None:
        shutil.copy(FIXTURE, path)
    else:
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    stamp = path.stat().st_mtime - age_s
    os.utime(path, (stamp, stamp))
    return path


def test_no_flags_open_the_newest_session(project: Path) -> None:
    _session(project, "old", 100)
    newest = _session(project, "new", 0)
    assert pick_session(project, None, current=False) == PickedSession(project, newest, "newest")


def test_a_project_without_sessions_has_nothing_to_pick(project: Path) -> None:
    assert pick_session(project, None, current=False) is None
    assert pick_session(project, None, current=True) is None


def test_a_named_session_of_the_project_is_picked_and_an_unknown_or_unsafe_one_is_not(project: Path) -> None:
    old = _session(project, "old", 100)
    _session(project, "new", 0)
    claude_project_dir(project).parent.joinpath("x.jsonl").write_text("{}\n", encoding="utf-8")
    assert pick_session(project, "old", current=False) == PickedSession(project, old, "named")
    assert pick_session(project, "missing", current=False) is None
    assert pick_session(project, "../x", current=False) is None
    assert pick_session(project, "", current=False) is None


def _stamp(epoch_s: float) -> str:
    return datetime.fromtimestamp(epoch_s, tz=UTC).isoformat().replace("+00:00", "Z")


def _timed_session(root: Path, name: str, began: float, ended: float, *, cleared: bool = False) -> Path:
    """A transcript `name` of the project whose first timed row is at epoch `began` and which was last written at
    `ended`. With `cleared` it opens as a `/clear` does: a harness note, then the command row, then the first
    prompt."""
    row = {"sessionId": name, "cwd": str(root)}
    opening = [
        {
            **row,
            "type": "user",
            "isMeta": True,
            "timestamp": _stamp(began),
            "uuid": f"{name}-caveat",
            "message": {
                "role": "user",
                "content": "<local-command-caveat>The command below was run directly</local-command-caveat>",
            },
        },
        {
            **row,
            "type": "user",
            "timestamp": _stamp(began - 0.03),
            "uuid": f"{name}-command",
            "message": {
                "role": "user",
                "content": "<command-name>/clear</command-name>\n<command-message>clear</command-message>",
            },
        },
    ]
    rows = (
        [*opening, {**PROMPT_ROW, **row, "timestamp": _stamp(began + 1)}]
        if cleared
        else [{**PROMPT_ROW, **row, "timestamp": _stamp(began)}]
    )
    path = _session(root, name, 0, rows=rows)
    os.utime(path, (ended, ended))
    return path


def test_current_after_a_clear_opens_the_session_the_clear_began_though_the_old_one_was_written_after_it(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`CLAUDE_CODE_SESSION_ID` is updated on `/clear`, but an MCP server keeps the id it was spawned with. The
    cleared session's last write, a cost-state row, lands just after the new session's first row: 0.056 s after it
    in a recorded pair."""
    now = time.time()
    _timed_session(project, "before-clear", now - 600, now - 100 + 0.056)
    after = _timed_session(project, "after-clear", now - 100, now - 10, cleared=True)
    monkeypatch.setenv(SESSION_ENV, "before-clear")
    assert pick_session(project, None, current=True) == PickedSession(project, after, "current")


def test_current_after_two_clears_follows_the_chain_to_the_session_in_use(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    _timed_session(project, "first", now - 900, now - 600 + 0.056)
    _timed_session(project, "middle", now - 600, now - 300 + 0.056, cleared=True)
    in_use = _timed_session(project, "in-use", now - 300, now - 1, cleared=True)
    monkeypatch.setenv(SESSION_ENV, "first")
    assert pick_session(project, None, current=True) == PickedSession(project, in_use, "current")


def test_current_stays_on_the_env_session_it_keeps_writing_after_another_terminal_ran_clear(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    mine = _timed_session(project, "mine", now - 900, now)
    _timed_session(project, "other-terminal", now - 2, now, cleared=True)
    monkeypatch.setenv(SESSION_ENV, "mine")
    assert pick_session(project, None, current=True) == PickedSession(project, mine, "current")


def test_current_stays_on_the_env_session_while_a_parallel_one_began_without_a_clear(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    mine = _timed_session(project, "mine", now - 600, now - 100)
    _timed_session(project, "parallel", now - 100, now - 10)
    monkeypatch.setenv(SESSION_ENV, "mine")
    assert pick_session(project, None, current=True) == PickedSession(project, mine, "current")


def test_current_stays_on_the_env_session_when_the_clear_began_long_after_its_last_write(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    mine = _timed_session(project, "mine", now - 600, now - 300)
    _timed_session(project, "later", now - 100, now - 10, cleared=True)
    monkeypatch.setenv(SESSION_ENV, "mine")
    assert pick_session(project, None, current=True) == PickedSession(project, mine, "current")


def test_current_with_two_clears_beginning_at_its_last_write_shows_the_newest_and_says_so(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = time.time()
    _timed_session(project, "mine", now - 600, now - 100)
    _timed_session(project, "clear-a", now - 100, now - 50, cleared=True)
    newest = _timed_session(project, "clear-b", now - 99, now - 10, cleared=True)
    monkeypatch.setenv(SESSION_ENV, "mine")
    assert pick_session(project, None, current=True) == PickedSession(project, newest, "current_unknown")


def test_current_opens_the_calling_session_even_when_a_newer_one_exists(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mine = _session(project, "mine", 100, rows=[{**PROMPT_ROW, "sessionId": "mine", "cwd": str(project)}])
    _session(project, "newer", 0)
    monkeypatch.setenv(SESSION_ENV, "mine")
    assert pick_session(project, None, current=True) == PickedSession(project, mine, "current")


@pytest.mark.parametrize("value", [None, "someone-elses", "../x"])
def test_current_without_a_session_of_this_folder_shows_the_newest_and_says_so(
    project: Path, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    _session(project, "mine", 100)
    newest = _session(project, "newer", 0)
    if value is not None:
        monkeypatch.setenv(SESSION_ENV, value)
    assert pick_session(project, None, current=True) == PickedSession(project, newest, "current_unknown")


def test_a_subfolder_has_no_sessions_of_its_own(project: Path) -> None:
    _session(project, "mine", 100)
    deep = project / "src" / "pkg"
    deep.mkdir(parents=True)
    assert pick_session(deep, None, current=False) is None
    assert pick_session(deep, "mine", current=False) is None


def test_current_with_the_env_id_finds_a_session_recorded_under_another_project_folder(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    started = project.parent / "started-here"
    started.mkdir()
    rows = [{**PROMPT_ROW, "sessionId": "mine", "cwd": str(started)}]
    mine = _session(started, "mine", 100, rows=rows)
    _session(project, "newer", 0)
    monkeypatch.setenv(SESSION_ENV, "mine")
    assert pick_session(project, None, current=True) == PickedSession(started, mine, "current")


def test_current_with_an_unsafe_env_id_is_refused_and_falls_back(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    claude_project_dir(project).parent.mkdir(parents=True)
    claude_project_dir(project).parent.joinpath("x.jsonl").write_text("{}\n", encoding="utf-8")
    newest = _session(project, "newer", 0)
    monkeypatch.setenv(SESSION_ENV, "../x")
    assert pick_session(project, None, current=True) == PickedSession(project, newest, "current_unknown")


def test_current_with_an_id_no_transcript_carries_falls_back_to_the_newest_of_the_folder(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    newest = _session(project, "newer", 0)
    monkeypatch.setenv(SESSION_ENV, "nobody")
    assert pick_session(project, None, current=True) == PickedSession(project, newest, "current_unknown")


def test_the_switcher_lists_each_session_with_its_start_length_and_subagents(project: Path) -> None:
    _session(project, "plain", 0, rows=[PROMPT_ROW])
    (project_dir := claude_project_dir(project) / "plain" / "subagents").mkdir(parents=True)
    (project_dir / "agent-a1.jsonl").write_text("{}\n", encoding="utf-8")
    (project_dir / "agent-a2.jsonl").write_text("{}\n", encoding="utf-8")
    empty = _session(project, "empty", 50, rows=[])
    entries = {entry.session: entry for entry in session_entries(project)}
    assert list(entries) == ["plain", "empty"]
    plain = entries["plain"]
    assert plain.started_at == "2026-10-30T20:10:30.000Z"
    assert plain.subagents == 2
    assert plain.length_s is not None and plain.length_s > 0
    assert entries["empty"].started_at is None
    assert entries["empty"].length_s is None
    assert entries["empty"].subagents == 0
    assert empty.is_file()


def test_the_entry_serializes_its_facts(project: Path) -> None:
    _session(project, "s", 0, rows=[PROMPT_ROW])
    (entry,) = session_entries(project)
    assert entry.to_json()["session"] == "s"
    assert entry.to_json()["subagents"] == 0


def test_the_first_prompt_is_the_first_typed_prompt_and_a_session_without_one_has_none(project: Path) -> None:
    later = {**PROMPT_ROW, "uuid": "u-2", "message": {"role": "user", "content": "second"}}
    typed = _session(project, "typed", 0, rows=[PROMPT_ROW, later])
    assert first_prompt_text("claude", typed) == "open the settings page"
    assert first_prompt_text("claude", _session(project, "fixture", 0)) is None
    assert first_prompt_text("nobody", typed) is None


def test_a_record_whose_port_does_not_answer_is_removed(project: Path) -> None:
    register_page(project, 1, "launch-a")
    record = next(bootstrap.get_xray_pages_dir().glob("*.json"))
    if sys.platform != "win32":  # Windows has no POSIX permission bits
        assert oct(record.stat().st_mode & 0o777) == "0o600"
    assert running_page(project) is None
    assert not record.exists()


def test_a_page_forgets_only_its_own_launch(project: Path) -> None:
    register_page(project, 1, "launch-a")
    forget_page(project, "launch-b")
    assert next(bootstrap.get_xray_pages_dir().glob("*.json")).exists()
    forget_page(project, "launch-a")
    assert not list(bootstrap.get_xray_pages_dir().glob("*.json"))


def test_a_second_start_waits_for_the_page_the_first_registers(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert pages._take_lock(project)  # pylint: disable=protected-access
    page = XrayPage(7, 8, "launch-a")
    answers = iter([None, None, page])
    monkeypatch.setattr(pages, "running_page", lambda _root: next(answers))
    monkeypatch.setattr(pages, "_POLL_S", 0.01)
    assert start_page(project, "any") == (page, True)


def test_a_second_start_gives_up_when_no_page_answers_by_the_deadline(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert pages._take_lock(project)  # pylint: disable=protected-access
    monkeypatch.setattr(pages, "PAGE_START_S", 0.2)
    monkeypatch.setattr(pages, "_POLL_S", 0.01)
    with pytest.raises(XrayPageError, match="did not answer"):
        start_page(project, "any")


def test_a_stale_start_lock_is_replaced(project: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert pages._take_lock(project)  # pylint: disable=protected-access
    monkeypatch.setattr(pages, "PAGE_START_S", -1.0)
    assert pages._take_lock(project)  # pylint: disable=protected-access


@pytest.fixture(name="read_only_pages")
def _read_only_pages(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A pages folder whose parent cannot be written."""
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    monkeypatch.setattr(pages, "get_xray_pages_dir", lambda: locked / "xray-pages")
    yield locked
    locked.chmod(0o700)


@pytest.mark.skipif(sys.platform == "win32", reason="chmod does not make a folder unwritable on Windows")
def test_a_start_in_an_unwritable_settings_folder_is_a_page_error_naming_the_folder(
    project: Path, read_only_pages: Path
) -> None:
    with pytest.raises(XrayPageError, match=re.escape(str(read_only_pages / "xray-pages"))):
        start_page(project, "any")


def test_the_page_address_always_carries_how_the_session_was_chosen() -> None:
    page = XrayPage(1, 2, "launch-a")
    assert pages.page_url(page, "s", "current").endswith("/?session=s&pick=current")
    assert pages.page_url(page, "s", "named").endswith("/?session=s&pick=named")


@pytest.mark.skipif(sys.platform == "win32", reason="the user site layout differs on Windows")
def test_the_detached_page_start_keeps_user_site_packages_and_not_the_working_folder(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A `pip install --user` install lives in the user site; the page must start from it, not from the folder."""
    base_python = getattr(sys, "_base_executable", sys.executable)  # a venv's own python never enables user site
    user_base = tmp_path / "userbase"
    user_site = user_base / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages"
    user_site.mkdir(parents=True)
    (user_site / "user_site_probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    (project / "folder_probe.py").write_text("VALUE = 1\n", encoding="utf-8")
    started: list[list[str]] = []
    monkeypatch.setattr(sys, "executable", base_python)
    monkeypatch.setattr(pages, "launch_detached", lambda command, *, cwd: started.append(command) or 1)
    monkeypatch.setattr(pages, "_wait_for_page", lambda _root, _pid: XrayPage(1, 2, "launch-a"))
    start_page(project, "any")
    (command,) = started
    flags = command[: command.index("-m")]
    env = {**os.environ, "PYTHONUSERBASE": str(user_base)}

    def imports(module: str) -> bool:
        probe = [*flags, "-c", f"import {module}"]
        return subprocess.run(probe, cwd=project, env=env, capture_output=True, check=False).returncode == 0

    assert imports("user_site_probe")
    assert not imports("folder_probe")
