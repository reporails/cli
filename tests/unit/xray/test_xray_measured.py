"""A reply whose request Claude Code recorded is split by that request's measured sizes; one whose request is not
recorded keeps the estimated split and its remainder."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.events import EventRecord, RequestSize, TokenUsage
from reporails_cli.core.platform.dto.xray_composition import COMPOSITION_KEYS, REMAINDER_KEY
from reporails_cli.core.platform.dto.xray_graph import XrayInContext
from tests.unit.xray.test_xray_composition import _files, _rows
from tests.unit.xray.test_xray_graph import _agent, _graph, _node, harness, launch, load, rec, reply

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

NOT_RECORDED = "Estimated: no complete recorded request for this reply."


def _size(request_id: str = "req", **fields: int) -> RequestSize:
    """A request of 4000 system characters, 8000 tool characters (12 tools) and 17200 characters in all."""
    base = {
        "system_chars": 4000,
        "tools_chars": 8000,
        "tool_count": 12,
        "user_text": 800,
        "notes": 0,
        "assistant_text": 400,
        "thinking": 0,
        "tool_calls": 800,
        "tool_results": 3200,
        "unresolved": 0,
    }
    return RequestSize(request_id, **{**base, **fields}, tool_names=())  # type: ignore[arg-type]


def _request(seconds: float, size: RequestSize, sub: str | None = None) -> EventRecord:
    return rec("api_request", seconds, sub, item=size)


def _answer(seconds: float, context: int, ref: str | None, sub: str | None = None) -> EventRecord:
    usage = TokenUsage(f"msg-{sub}-{seconds}", 1, 0, context - 1, request_ref=ref)
    return rec("assistant_usage", seconds, sub, usage=usage)


def _context(root: Path, records: list[EventRecord], node: str = "main") -> XrayInContext:
    ic = _agent(_node(_graph(root, records, _files(root)), node)).in_context
    assert ic is not None
    return ic


def _by_key(ic: XrayInContext) -> dict[str, int]:
    return {row.key: row.tokens_est for row in ic.rows}


def test_a_measured_peak_splits_the_total_by_the_request_with_no_remainder(tmp_path: Path) -> None:
    claude, _, _ = _files(tmp_path)
    records = [load(0.1, claude), _request(0.5, _size()), _answer(1, 17200, "req")]
    (row,) = _rows(tmp_path, records)
    assert row["measured"] is True and row["over_estimate"] is False
    assert sum(int(str(row[key])) for key in COMPOSITION_KEYS) == 17200
    assert row[REMAINDER_KEY] == 12000 and row["tool_results"] == 4000 and row["instructions"] == 100
    ic = _context(tmp_path, records)
    assert ic.measured and ic.note is None and not ic.over
    assert sum(r.tokens_est for r in ic.rows) == ic.total == 17200
    assert not any(r.key == "builtin" for r in ic.rows)
    values = _by_key(ic)
    assert values["system_prompt"] == 4000 and values["tool_definitions"] == 8000 and values["tool_io"] == 4000
    items = {item.key: item for item in _graph(tmp_path, records, _files(tmp_path)).builtin}
    assert not any(item.remainder for item in items.values())
    assert items["system_prompt"].tokens_est == 4000
    assert items["system_prompt"].note == "Measured from the request Claude Code recorded."
    assert items["tool_definitions"].tokens_est == 8000
    assert items["tool_definitions"].note == "12 tools sent with every request"


def test_the_measured_shares_are_scaled_to_the_exact_total(tmp_path: Path) -> None:
    values = _by_key(_context(tmp_path, [_request(0.5, _size()), _answer(1, 34400, "req")]))
    assert values["system_prompt"] == 8000 and values["tool_definitions"] == 16000 and values["tool_io"] == 8000


@pytest.mark.parametrize("recorded", [[], [_request(0.5, _size("other"))]], ids=["no request", "other request"])
def test_a_reply_with_no_recorded_request_keeps_the_estimated_split(
    tmp_path: Path, recorded: list[EventRecord]
) -> None:
    measured = [*recorded, _answer(1, 10000, "req")]
    plain = [reply(1, context=10000)]
    assert _rows(tmp_path, measured) == _rows(tmp_path, plain)
    ic = _context(tmp_path, measured)
    assert not ic.measured and ic.note == NOT_RECORDED
    assert [r.key for r in ic.rows] == [r.key for r in _context(tmp_path, plain).rows]
    assert any(r.key == "builtin" for r in ic.rows)
    builtin = _graph(tmp_path, measured, _files(tmp_path)).builtin
    assert any(item.remainder for item in builtin)
    assert not any(item.key == "tool_definitions" for item in builtin)


def test_load_estimates_over_the_measured_conversation_share_clamp_the_last_row(tmp_path: Path) -> None:
    claude, rule, _ = _files(tmp_path)
    small = _size(user_text=0, assistant_text=0, tool_calls=0, tool_results=0, system_chars=200, tools_chars=100)
    records = [load(0.1, claude), load(0.2, rule), _request(0.5, small), _answer(1, 300, "req")]
    ic = _context(tmp_path, records)
    assert ic.measured and ic.over
    assert ic.rows[-1].key == "rest" and ic.rows[-1].tokens_est == 0
    (row,) = _rows(tmp_path, records)
    assert row["over_estimate"] is True and row["measured"] is True and row["conversation"] == 0


def test_a_subagents_in_context_comes_from_the_requests_of_its_own_file(tmp_path: Path) -> None:
    sub_size = _size("sub-req", system_chars=1000, tools_chars=1000, tool_calls=0, tool_results=0)
    records = [
        _request(0.5, _size("main-req")),
        _answer(1, 17200, "main-req"),
        launch(4, "A", None, "tuA"),
        _request(4.5, sub_size, "A"),
        _answer(5, 3200, "sub-req", "A"),
    ]
    main, sub = _context(tmp_path, records), _context(tmp_path, records, "A")
    assert main.total == 17200 and _by_key(main)["system_prompt"] == 4000
    assert sub.measured and sub.total == 3200 and sum(r.tokens_est for r in sub.rows) == 3200
    assert _by_key(sub)["system_prompt"] == 1000 and _by_key(sub)["tool_definitions"] == 1000


def test_a_request_with_no_characters_is_unmeasured(tmp_path: Path) -> None:
    empty = _size(
        system_chars=0, tools_chars=0, user_text=0, assistant_text=0, tool_calls=0, tool_results=0, tool_count=0
    )
    assert not _context(tmp_path, [_request(0.5, empty), _answer(1, 1000, "req")]).measured


def test_a_request_with_unresolved_messages_is_not_measured(tmp_path: Path) -> None:
    records = [_request(0.5, _size(unresolved=3)), _answer(1, 17200, "req")]
    ic = _context(tmp_path, records)
    assert not ic.measured and ic.note == NOT_RECORDED
    (row,) = _rows(tmp_path, records)
    assert row["measured"] is False
    assert not any(item.key == "tool_definitions" for item in _graph(tmp_path, records, _files(tmp_path)).builtin)


def test_the_builtin_items_read_the_request_of_the_peak_reply_not_one_with_the_same_total(tmp_path: Path) -> None:
    peak_request, other_request = _size("a"), _size("b", system_chars=6000, tools_chars=6000)
    records = [
        _request(0.5, other_request),
        _answer(2, 17200, "b"),
        _request(0.4, peak_request),
        _answer(1, 17200, "a"),
    ]
    items = {item.key: item for item in _graph(tmp_path, records, _files(tmp_path)).builtin}
    assert items["system_prompt"].tokens_est == 4000 and items["tool_definitions"].tokens_est == 8000
    assert _by_key(_context(tmp_path, records))["system_prompt"] == 4000


def test_a_measured_peak_lists_the_skills_listing_apart_from_the_conversation(tmp_path: Path) -> None:
    records = [harness(0.2, "skill_list", "skills", 4000), _request(0.5, _size()), _answer(1, 17200, "req")]
    ic = _context(tmp_path, records)
    keys = [row.key for row in ic.rows]
    assert keys[-2:] == ["skill_listing", "rest"] and ic.measured and not ic.over
    values = _by_key(ic)
    assert values["skill_listing"] == 1000 and values["tool_io"] == 4000
    assert values["rest"] == 17200 - 4000 - 8000 - 4000 - 1000 == 200
    label = next(row.label for row in ic.rows if row.key == "skill_listing")
    assert label == "Skills listing" and sum(r.tokens_est for r in ic.rows) == 17200
    (row,) = _rows(tmp_path, records)
    assert row["skill_listing"] == 1000 and row["conversation"] == 200
