"""List-price cost of replies and agents: each token class at its rate, assumptions counted, unknown models named."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.events import EventRecord, TokenUsage
from reporails_cli.core.platform.dto.xray_build import SourceTable
from reporails_cli.core.xray.cost import agent_cost, load_price_list, prices_for, reply_cost

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

NO_SOURCES = SourceTable((), Path(), {}, {})
T0 = datetime(2026, 11, 1, 10, 0, 0, tzinfo=UTC)


def _usage(model: str | None, **counts: int | None) -> TokenUsage:
    fields: dict[str, int | None] = {
        "input_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
        **counts,
    }
    return TokenUsage(
        "m",
        fields["input_tokens"] or 0,
        fields["cache_creation_input_tokens"] or 0,
        fields["cache_read_input_tokens"] or 0,
        model=model,
        output_tokens=fields.get("output_tokens"),
        cache_write_5m_tokens=fields.get("cache_write_5m_tokens"),
        cache_write_1h_tokens=fields.get("cache_write_1h_tokens"),
    )


def _record(usage: TokenUsage, seconds: float) -> EventRecord:
    when = (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")
    return EventRecord(agent="claude", event="assistant_usage", session_id="s", time=when, usage=usage)


def test_a_reply_with_the_split_prices_each_class_of_token_at_its_rate() -> None:
    # Opus 4.8 list: input 5, 5m write 6.25, 1h write 10, read 0.5, output 25 per million tokens.
    usage = _usage(
        "claude-opus-4-8",
        input_tokens=1_000,
        cache_creation_input_tokens=3_000,
        cache_write_5m_tokens=1_000,
        cache_write_1h_tokens=2_000,
        cache_read_input_tokens=10_000,
        output_tokens=500,
    )
    expected = (1_000 * 5 + 1_000 * 6.25 + 2_000 * 10 + 10_000 * 0.5 + 500 * 25) / 1_000_000
    assert reply_cost(usage, load_price_list()) == pytest.approx(expected)
    assert expected == pytest.approx(0.04875)


def test_a_reply_without_the_split_prices_its_writes_at_the_5m_rate_and_is_counted() -> None:
    prices = load_price_list()
    usage = _usage("claude-opus-4-8", cache_creation_input_tokens=4_000, output_tokens=0)
    assert reply_cost(usage, prices) == pytest.approx(4_000 * 6.25 / 1_000_000)
    found = agent_cost([_record(usage, 0)], prices, T0.timestamp(), (), NO_SOURCES)
    assert (found.split_assumed, found.output_missing) == (1, 0)
    bare = agent_cost(
        [_record(_usage("claude-opus-4-8", input_tokens=1_000), 0)], prices, T0.timestamp(), (), NO_SOURCES
    )
    assert (bare.split_assumed, bare.output_missing) == (0, 1)
    assert bare.total_usd == pytest.approx(1_000 * 5 / 1_000_000)


def test_an_unknown_model_has_no_cost_and_is_named() -> None:
    prices = load_price_list()
    mystery = _usage("claude-mystery-9", input_tokens=1_000, output_tokens=1)
    assert reply_cost(mystery, prices) is None
    known = _usage("claude-sonnet-5-5", input_tokens=1_000_000, output_tokens=0)
    found = agent_cost(
        [_record(mystery, 0), _record(known, 10), _record(mystery, 20)], prices, T0.timestamp(), (), NO_SOURCES
    )
    assert (found.turns, found.unpriced, found.unpriced_models) == (3, 2, ("claude-mystery-9",))
    assert found.total_usd == pytest.approx(2.0)
    nothing = agent_cost([_record(mystery, 0)], prices, T0.timestamp(), (), NO_SOURCES)
    assert (nothing.total_usd, nothing.peak_turn_usd, nothing.peak_turn_t) == (None, None, None)


def test_haiku_5_5_switches_to_its_long_prompt_rates_above_100000_tokens() -> None:
    prices = load_price_list()
    at_limit = _usage("claude-haiku-5-5", input_tokens=100_000, output_tokens=1_000)
    over = _usage("claude-haiku-5-5", input_tokens=100_001, output_tokens=1_000)
    assert reply_cost(at_limit, prices) == pytest.approx((100_000 * 0.1 + 1_000 * 0.5) / 1_000_000)
    assert reply_cost(over, prices) == pytest.approx((100_001 * 0.5 + 1_000 * 2.5) / 1_000_000)
    # The prompt counts cache reads and writes too.
    cached = _usage("claude-haiku-5-5", input_tokens=1, cache_read_input_tokens=100_000, output_tokens=0)
    assert reply_cost(cached, prices) == pytest.approx((1 * 0.5 + 100_000 * 0.05) / 1_000_000)


def test_a_dated_model_id_matches_its_entry_and_a_longer_name_does_not() -> None:
    prices = load_price_list()
    dated = prices_for("claude-opus-4-5-20251101", prices)
    assert dated is not None and dated.rate.input == 5
    old = prices_for("claude-opus-4-20250514", prices)
    assert old is not None and old.rate.input == 15
    assert prices_for("claude-opus-4-5-preview", prices) is None
    assert prices_for(None, prices) is None


def test_cache_hit_rate_is_cache_reads_over_total_context_across_replies() -> None:
    prices = load_price_list()
    first = _usage("claude-sonnet-5-5", input_tokens=100, cache_creation_input_tokens=900, output_tokens=10)
    second = _usage("claude-sonnet-5-5", input_tokens=100, cache_read_input_tokens=900, output_tokens=10)
    found = agent_cost([_record(first, 5), _record(second, 65)], prices, T0.timestamp(), (), NO_SOURCES)
    assert found.cache_hit_rate == pytest.approx(900 / 2_000)
    assert found.turns == 2
    assert found.peak_turn_usd is not None and found.peak_turn_t == 5.0
    assert agent_cost([], prices, T0.timestamp(), (), NO_SOURCES).cache_hit_rate is None


def test_a_malformed_price_list_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    broken = tmp_path / "claude.yml"
    broken.write_text(
        "name: x\nas_of: '2026-11-02'\nsource: s\nunit: u\nmodels:\n  - ids: [claude-a]\n    input: cheap\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("reporails_cli.core.xray.cost.get_prices_path", lambda agent: broken)
    load_price_list.cache_clear()
    try:
        with pytest.raises(ValueError, match=r"models\[0\]\.input"):
            load_price_list()
    finally:
        monkeypatch.undo()
        load_price_list.cache_clear()
    assert load_price_list().info.name == "Claude API list prices"
