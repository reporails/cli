"""Which notices are due: a warning always, an info once per local day."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters.notices_seen import due_notices
from reporails_cli.core.platform.dto.diagnostics import Notice

WARN = Notice("w", "warn", "Payment failed")
INFO = Notice("i", "info", "Pro ends soon")
NOON = datetime(2026, 5, 10, 12, 0)


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _state(home: Path) -> dict[str, str]:
    return json.loads((home / ".reporails" / "notices-seen.json").read_text(encoding="utf-8"))


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_warn_is_due_every_time_and_never_recorded(home: Path) -> None:
    assert due_notices((WARN,), now=NOON) == (WARN,)
    assert due_notices((WARN,), now=NOON) == (WARN,)
    assert not (home / ".reporails" / "notices-seen.json").exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_info_is_due_once_per_day_then_again_the_next_day() -> None:
    assert due_notices((INFO,), now=NOON) == (INFO,)
    assert due_notices((INFO,), now=NOON.replace(hour=20)) == ()
    assert due_notices((INFO,), now=NOON + timedelta(days=1)) == (INFO,)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_mixed_batch_keeps_warn_and_drops_a_seen_info() -> None:
    due_notices((INFO,), now=NOON)
    assert due_notices((WARN, INFO), now=NOON) == (WARN,)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_entries_older_than_thirty_days_are_pruned(home: Path) -> None:
    state = home / ".reporails" / "notices-seen.json"
    state.parent.mkdir()
    state.write_text(json.dumps({"old": "2026-03-01", "recent": "2026-05-01", "junk": "not a date"}), encoding="utf-8")
    due_notices((INFO,), now=NOON)
    assert _state(home) == {"recent": "2026-05-01", "i": "2026-05-10"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '"text"', ""])
def test_unreadable_state_still_shows_the_notice(home: Path, content: str) -> None:
    state = home / ".reporails" / "notices-seen.json"
    state.parent.mkdir()
    state.write_text(content, encoding="utf-8")
    assert due_notices((INFO,), now=NOON) == (INFO,)
    assert _state(home) == {"i": "2026-05-10"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_unwritable_state_still_shows_the_notice(home: Path) -> None:
    (home / ".reporails").write_text("a file where the directory should be", encoding="utf-8")
    assert due_notices((INFO,), now=NOON) == (INFO,)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_no_notices_touches_nothing(home: Path) -> None:
    assert due_notices((), now=NOON) == ()
    assert not (home / ".reporails").exists()
