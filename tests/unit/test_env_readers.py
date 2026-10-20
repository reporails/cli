"""The config layer's environment readers: what each returns for unset, blank and padded values."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from reporails_cli.core.platform.config.bootstrap import (
    env_int,
    env_text,
    parse_idle_timeout_env,
    running_in_github_actions,
)
from reporails_cli.core.platform.config.credentials import env_tier
from reporails_cli.core.platform.config.endpoints import (
    DEFAULT_PLATFORM_URL,
    DEFAULT_SERVER_URL,
    platform_url,
    server_url,
)

_VAR = "AILS_TEST_ENV_READER"


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("var", "reader", "default"),
    [
        ("AILS_SERVER_URL", server_url, DEFAULT_SERVER_URL),
        ("AILS_PLATFORM_URL", platform_url, DEFAULT_PLATFORM_URL),
    ],
)
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        ("/", None),
        ("http://localhost:8001/", "http://localhost:8001"),
        ("  http://localhost:8001  ", "http://localhost:8001"),
        ("http://localhost:8001", "http://localhost:8001"),
    ],
)
def test_address_readers_are_stripped_without_trailing_slash_else_default(
    monkeypatch: pytest.MonkeyPatch,
    var: str,
    reader: Callable[[], str],
    default: str,
    value: str | None,
    expected: str | None,
) -> None:
    if value is None:
        monkeypatch.delenv(var, raising=False)
    else:
        monkeypatch.setenv(var, value)
    assert reader() == (expected or default)


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(("value", "expected"), [(None, ""), ("", ""), ("  ", ""), (" team ", "team")])
def test_env_text_and_env_tier_strip_and_default_to_empty(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: str
) -> None:
    for name in (_VAR, "AILS_TIER"):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    assert env_text(_VAR) == expected
    assert env_tier() == expected


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, None), ("", None), ("  ", None), ("abc", None), ("1.5", None), ("4", 4), (" 7 ", 7), ("0", 0), ("-3", -3)],
)
def test_env_int_is_none_unless_an_integer(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: int | None
) -> None:
    if value is None:
        monkeypatch.delenv(_VAR, raising=False)
    else:
        monkeypatch.setenv(_VAR, value)
    assert env_int(_VAR) == expected


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, 30), ("junk", 30), ("5", 5), ("0", None), ("-1", None)],
)
def test_idle_timeout_env_uses_the_shared_integer_parse(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: int | None
) -> None:
    if value is None:
        monkeypatch.delenv(_VAR, raising=False)
    else:
        monkeypatch.setenv(_VAR, value)
    assert parse_idle_timeout_env(_VAR, 30) == expected


@pytest.mark.unit
@pytest.mark.subsys_api
@pytest.mark.parametrize(
    ("value", "expected"), [(None, False), ("", False), ("false", False), ("True", False), ("true", True)]
)
def test_running_in_github_actions_only_for_exactly_true(
    monkeypatch: pytest.MonkeyPatch, value: str | None, expected: bool
) -> None:
    if value is None:
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    else:
        monkeypatch.setenv("GITHUB_ACTIONS", value)
    assert running_in_github_actions() is expected
