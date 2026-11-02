"""Which session the x-ray opens, the switcher's facts per session, and the page a project has running."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from reporails_cli.core.discovery.agent_discovery import claude_project_dir
from reporails_cli.core.eventbus.transcript import first_prompt_text, session_transcript
from reporails_cli.core.platform.config import bootstrap
from reporails_cli.core.platform.contract.errors import XrayPageError
from reporails_cli.core.platform.dto.xray import XrayPage
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
    root.mkdir()
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
    assert pick_session(project, None, current=False) == (newest, "newest")


def test_a_project_without_sessions_has_nothing_to_pick(project: Path) -> None:
    assert pick_session(project, None, current=False) is None
    assert pick_session(project, None, current=True) is None


def test_a_named_session_of_the_project_is_picked_and_an_unknown_or_unsafe_one_is_not(project: Path) -> None:
    old = _session(project, "old", 100)
    _session(project, "new", 0)
    claude_project_dir(project).parent.joinpath("x.jsonl").write_text("{}\n", encoding="utf-8")
    assert pick_session(project, "old", current=False) == (old, "named")
    assert pick_session(project, "missing", current=False) is None
    assert pick_session(project, "../x", current=False) is None
    assert pick_session(project, "", current=False) is None


def test_current_opens_the_calling_session_even_when_a_newer_one_exists(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    mine = _session(project, "mine", 100)
    _session(project, "newer", 0)
    monkeypatch.setenv(SESSION_ENV, "mine")
    assert pick_session(project, None, current=True) == (mine, "current")


@pytest.mark.parametrize("value", [None, "someone-elses", "../x"])
def test_current_without_a_session_of_this_folder_shows_the_newest_and_says_so(
    project: Path, monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    _session(project, "mine", 100)
    newest = _session(project, "newer", 0)
    if value is not None:
        monkeypatch.setenv(SESSION_ENV, value)
    assert pick_session(project, None, current=True) == (newest, "current_unknown")


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


def test_a_start_in_an_unwritable_settings_folder_is_a_page_error_naming_the_folder(
    project: Path, read_only_pages: Path
) -> None:
    with pytest.raises(XrayPageError, match=str(read_only_pages / "xray-pages")):
        start_page(project, "any")


def test_the_page_address_always_carries_how_the_session_was_chosen() -> None:
    page = XrayPage(1, 2, "launch-a")
    assert pages.page_url(page, "s", "current").endswith("/?session=s&pick=current")
    assert pages.page_url(page, "s", "named").endswith("/?session=s&pick=named")
