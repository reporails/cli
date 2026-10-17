"""Which notices are due: a warning or an announcement always, an info once per local day."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters import notices_seen
from reporails_cli.core.platform.adapters.notices_seen import visible_notices
from reporails_cli.core.platform.dto.diagnostics import Notice

WARN = Notice("w", "warn", "Payment failed")
INFO = Notice("i", "info", "Pro ends soon")
NOON = datetime(2026, 5, 10, 12, 0)


class _Clock(datetime):
    """The `datetime` the adapter reads, fixed to `moment` by `_due`."""

    moment = NOON

    @classmethod
    def now(cls, tz=None):  # type: ignore[no-untyped-def,override]
        return cls.moment


def _due(notices: tuple[Notice, ...], moment: datetime) -> tuple[Notice, ...]:
    """What `due_notices` returns when the local time is `moment`."""
    _Clock.moment = moment
    return notices_seen.due_notices(notices)


@pytest.fixture(autouse=True)
def clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(notices_seen, "datetime", _Clock)


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path


def _state(home: Path) -> dict[str, str]:
    return json.loads((home / ".reporails" / "notices-seen.json").read_text(encoding="utf-8"))


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_warn_is_due_every_time_and_never_recorded(home: Path) -> None:
    assert _due((WARN,), NOON) == (WARN,)
    assert _due((WARN,), NOON) == (WARN,)
    assert not (home / ".reporails" / "notices-seen.json").exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_info_is_due_once_per_day_then_again_the_next_day() -> None:
    assert _due((INFO,), NOON) == (INFO,)
    assert _due((INFO,), NOON.replace(hour=20)) == ()
    assert _due((INFO,), NOON + timedelta(days=1)) == (INFO,)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_mixed_batch_keeps_warn_and_drops_a_seen_info() -> None:
    _due((INFO,), NOON)
    assert _due((WARN, INFO), NOON) == (WARN,)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_entries_older_than_thirty_days_are_pruned(home: Path) -> None:
    state = home / ".reporails" / "notices-seen.json"
    state.parent.mkdir()
    state.write_text(json.dumps({"old": "2026-03-01", "recent": "2026-05-01", "junk": "not a date"}), encoding="utf-8")
    _due((INFO,), NOON)
    assert _state(home) == {"recent": "2026-05-01", "i": "2026-05-10"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("content", ["{not json", "[1, 2]", '"text"', ""])
def test_unreadable_state_still_shows_the_notice(home: Path, content: str) -> None:
    state = home / ".reporails" / "notices-seen.json"
    state.parent.mkdir()
    state.write_text(content, encoding="utf-8")
    assert _due((INFO,), NOON) == (INFO,)
    assert _state(home) == {"i": "2026-05-10"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_unwritable_state_still_shows_the_notice(home: Path) -> None:
    (home / ".reporails").write_text("a file where the directory should be", encoding="utf-8")
    assert _due((INFO,), NOON) == (INFO,)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_no_notices_touches_nothing(home: Path) -> None:
    assert _due((), NOON) == ()
    assert not (home / ".reporails").exists()


PROMO = Notice("p", "info", "Fixture promo", kind="promo")
WARN_PROMO = Notice("wp", "warn", "Loud announcement", kind="promo")


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_promo_shows_on_every_run_at_any_level_and_is_not_recorded(home: Path) -> None:
    assert _due((WARN_PROMO, PROMO), NOON) == (WARN_PROMO, PROMO)
    assert _due((WARN_PROMO, PROMO), NOON.replace(hour=20)) == (WARN_PROMO, PROMO)
    assert not (home / ".reporails" / "notices-seen.json").exists()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_an_info_that_is_not_a_promo_still_shows_once_a_day_beside_a_promo(home: Path) -> None:
    assert _due((PROMO, INFO), NOON) == (PROMO, INFO)
    assert _due((PROMO, INFO), NOON.replace(hour=20)) == (PROMO,)
    assert _state(home) == {"i": "2026-05-10"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_a_warn_notice_that_is_not_a_promo_shows_every_run(home: Path) -> None:
    assert _due((WARN,), NOON) == (WARN,)
    assert _due((WARN,), NOON) == (WARN,)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_visible_notices_drops_promos_with_the_flag() -> None:
    assert visible_notices((WARN, PROMO, WARN_PROMO, INFO), no_promo=True) == (WARN, INFO)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("value", ["1", "true", "YES"])
def test_visible_notices_drops_promos_with_the_env_var(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("AILS_NO_PROMO", value)
    assert visible_notices((WARN, PROMO, INFO)) == (WARN, INFO)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("value", [None, "", "0", "no"])
def test_visible_notices_keeps_everything_when_neither_is_set(
    monkeypatch: pytest.MonkeyPatch, value: str | None
) -> None:
    monkeypatch.delenv("AILS_NO_PROMO", raising=False)
    if value is not None:
        monkeypatch.setenv("AILS_NO_PROMO", value)
    both = (WARN, PROMO, INFO)
    assert visible_notices(both) == both


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, False),
        ("", False),
        ("0", False),
        ("false", False),
        ("NO", False),
        (" off ", False),
        ("1", True),
        ("true", True),
        ("yes", True),
        ("on", True),
        (" Yes ", True),
    ],
)
def test_env_flag_is_on_for_any_value_but_blank_0_false_no_off(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: bool
) -> None:
    from reporails_cli.core.platform.config.bootstrap import env_flag

    monkeypatch.delenv("AILS_TEST_FLAG", raising=False)
    if value is not None:
        monkeypatch.setenv("AILS_TEST_FLAG", value)
    assert env_flag("AILS_TEST_FLAG") is expected
