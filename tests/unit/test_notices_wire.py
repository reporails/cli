"""Notices off the wire: the header and the sign-in list decode to well-formed notices only."""

from __future__ import annotations

import base64
import json
import logging

import pytest

from reporails_cli.core.platform.adapters.notices_wire import (
    MAX_NOTICES,
    notices_from_header,
    notices_from_list,
)
from reporails_cli.core.platform.dto.diagnostics import Notice


def _header(payload: object, *, pad: bool = True) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return encoded if pad else encoded.rstrip("=")


GOOD = {"id": "a", "level": "warn", "text": "Payment failed", "url": "https://example.test/pay"}


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("pad", [True, False])
def test_header_decodes_with_or_without_padding(pad: bool) -> None:
    assert notices_from_header(_header([GOOD], pad=pad)) == (
        Notice("a", "warn", "Payment failed", "https://example.test/pay"),
    )


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_header_decodes_non_ascii_text() -> None:
    got = notices_from_header(_header([{"id": "u", "level": "info", "text": "Pro endet am 1. Mai — überprüfen"}]))
    assert got[0].text == "Pro endet am 1. Mai — überprüfen"
    assert got[0].url == ""


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "!!!not base64!!!",
        base64.urlsafe_b64encode(b"{not json").decode(),
        base64.urlsafe_b64encode(b"\xff\xfe\xfa").decode(),
        _header({"id": "a"}),
        _header("text"),
        _header(7),
    ],
    ids=["none", "empty", "bad-base64", "bad-json", "bad-utf8", "object", "string", "number"],
)
def test_header_that_cannot_be_read_gives_no_notices(value: str | None) -> None:
    assert notices_from_header(value) == ()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_undecodable_header_is_logged_as_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        notices_from_header("!!!not base64!!!")
    assert any("notices header" in r.message for r in caplog.records if r.levelno == logging.WARNING)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize(
    "entry",
    [
        "text",
        None,
        {"level": "info", "text": "no id"},
        {"id": "", "level": "info", "text": "empty id"},
        {"id": "x", "level": "info", "text": ""},
        {"id": "x", "level": "info"},
        {"id": "x", "level": "error", "text": "unknown level"},
        {"id": "x", "level": "info", "text": "t", "url": 5},
        {"id": 3, "level": "info", "text": "t"},
    ],
)
def test_malformed_entry_is_dropped_and_named(entry: object, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        got = notices_from_list([entry, GOOD])
    assert got == (Notice("a", "warn", "Payment failed", "https://example.test/pay"),)
    assert any("position 0" in r.message for r in caplog.records)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
@pytest.mark.parametrize("raw", [{"id": "a"}, "x", 4])
def test_list_that_is_not_a_list_gives_no_notices(raw: object) -> None:
    assert notices_from_list(raw) == ()


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_repeated_id_keeps_the_first() -> None:
    first = {"id": "a", "level": "info", "text": "first"}
    again = {"id": "a", "level": "warn", "text": "second"}
    assert notices_from_list([first, again]) == (Notice("a", "info", "first"),)


@pytest.mark.unit
@pytest.mark.subsys_cli_ux
def test_more_than_the_cap_keeps_the_first_ten() -> None:
    raw = [{"id": f"n{i}", "level": "info", "text": f"t{i}"} for i in range(MAX_NOTICES + 5)]
    got = notices_from_list(raw)
    assert [n.id for n in got] == [f"n{i}" for i in range(10)]
