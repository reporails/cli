"""`rewrite_accepted`: whether a rewritten file is kept, and the `accepted` field a file's `validate` reply carries."""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.preservation.compare import rewrite_accepted
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.formatters.mcp_view import render_text_view


def _pres(ok: bool = True, before: float | None = 5.0, after: float | None = 5.0) -> JsonObject:
    return {"ok": ok, "score_before": before, "score_after": after}


@pytest.mark.unit
@pytest.mark.subsys_server
@pytest.mark.parametrize(
    ("pres", "conformance", "kept"),
    [
        (_pres(), {"ok": True}, True),
        (_pres(after=6.0), {"ok": True}, True),
        (_pres(ok=False), {"ok": True}, False),
        (_pres(), {"ok": False}, False),
        (_pres(after=4.9), {"ok": True}, False),
        (_pres(), None, True),
        (_pres(ok=False), None, False),
        (_pres(after=4.9), None, False),
        (_pres(before=None, after=None), None, True),
    ],
)
def test_rewrite_accepted_needs_every_present_check(
    pres: JsonObject, conformance: JsonObject | None, kept: bool
) -> None:
    assert rewrite_accepted(pres, conformance) is kept


@pytest.mark.unit
@pytest.mark.subsys_server
def test_the_text_view_prints_accepted() -> None:
    assert "accepted: true" in render_text_view({"preservation": {"ok": True}, "accepted": True}).splitlines()
    assert "accepted: false" in render_text_view({"preservation": {"ok": True}, "accepted": False}).splitlines()
