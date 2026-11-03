"""List-price cost of replies: the bundled price list, the cost of one reply and the cost of one agent's replies."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import replace
from functools import lru_cache

from reporails_cli.bundled import get_prices_path
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_list, as_object
from reporails_cli.core.platform.dto.events import EventRecord, TokenUsage
from reporails_cli.core.platform.dto.xray_build import SourceTable
from reporails_cli.core.platform.dto.xray_composition import CarriedReply
from reporails_cli.core.platform.dto.xray_cost import (
    LongPrompt,
    ModelPrices,
    PriceList,
    PriceListInfo,
    Rate,
    XrayAgentCost,
)
from reporails_cli.core.platform.utils.utils import load_yaml_file
from reporails_cli.core.xray.derive import context_of, epoch

_PRICED_AGENT = "claude"
_PER_TOKENS = 1_000_000
_DATED = re.compile(r"-\d{8}")
_RATE_KEYS = ("input", "cache_write_5m", "cache_write_1h", "cache_read", "output")


def _number(value: JsonValue, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float) or value < 0:
        raise ValueError(f"price list: {where} is not a non-negative number")
    return float(value)


def _text(value: JsonValue, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"price list: {where} is not text")
    return value


def _rate(entry: JsonObject, where: str) -> Rate:
    first, second, third, fourth, fifth = (_number(entry.get(key), f"{where}.{key}") for key in _RATE_KEYS)
    return Rate(first, second, third, fourth, fifth)


def _model(item: JsonValue, position: int) -> ModelPrices:
    where = f"models[{position}]"
    entry = as_object(item)
    ids = tuple(_text(name, f"{where}.ids") for name in as_list(entry.get("ids")))
    if not ids:
        raise ValueError(f"price list: {where}.ids names no model")
    long = entry.get("long_prompt")
    above = None
    if long is not None:
        block = as_object(long)
        threshold = block.get("above_tokens")
        if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold <= 0:
            raise ValueError(f"price list: {where}.long_prompt.above_tokens is not a whole number above zero")
        above = LongPrompt(threshold, _rate(block, f"{where}.long_prompt"))
    return ModelPrices(ids, _rate(entry, where), above)


# How `attributed_cost` works out what a source cost, in the words the page states it with.
SOURCE_METHOD = (
    "A source's cost is, for each reply of every agent that carried it, the tokens it carried (estimated from its "
    "size) times that reply's input-side price per context token (fresh input, cache writes and cache reads over "
    "the reply's context), summed; a reply of a model with no price adds nothing."
)


@lru_cache(maxsize=1)
def load_price_list() -> PriceList:
    """The bundled Claude price list, read and validated once per process; a malformed file raises."""
    document = as_object(load_yaml_file(get_prices_path(_PRICED_AGENT)))
    info = PriceListInfo(
        _text(document.get("name"), "name"),
        _text(document.get("as_of"), "as_of"),
        _text(document.get("source"), "source"),
        _text(document.get("unit"), "unit"),
        SOURCE_METHOD,
    )
    models = tuple(_model(item, position) for position, item in enumerate(as_list(document.get("models"))))
    if not models:
        raise ValueError("price list: no models")
    return PriceList(info, models)


def prices_for(model: str | None, prices: PriceList) -> ModelPrices | None:
    """The row whose id is `model` or `model` less a `-YYYYMMDD` snapshot suffix; None for an unknown model."""
    if model is None:
        return None
    for row in prices.models:
        for known in row.ids:
            if model == known or (model.startswith(known) and _DATED.fullmatch(model[len(known) :])):
                return row
    return None


def _write_split(usage: TokenUsage) -> tuple[int, int, bool]:
    """The 5-minute and 1-hour cache-write tokens, and whether the split was absent so all writes count as 5-minute."""
    if usage.cache_write_5m_tokens is None and usage.cache_write_1h_tokens is None:
        return usage.cache_creation_input_tokens, 0, usage.cache_creation_input_tokens > 0
    return usage.cache_write_5m_tokens or 0, usage.cache_write_1h_tokens or 0, False


def _reply_rate(usage: TokenUsage, prices: PriceList) -> Rate | None:
    """The rates one reply is priced at: its model's base rates, or the long-prompt rates when its context is over
    the threshold; None when its model has no price."""
    row = prices_for(usage.model, prices)
    if row is None:
        return None
    if row.long_prompt is not None and context_of(usage) > row.long_prompt.above_tokens:
        return row.long_prompt.rate
    return row.rate


def _input_side_usd(usage: TokenUsage, rate: Rate) -> float:
    """The USD the reply's input, cache writes and cache reads cost, with no output."""
    five, hour, _ = _write_split(usage)
    total = (
        usage.input_tokens * rate.input
        + five * rate.cache_write_5m
        + hour * rate.cache_write_1h
        + usage.cache_read_input_tokens * rate.cache_read
    )
    return total / _PER_TOKENS


def reply_cost(usage: TokenUsage, prices: PriceList) -> float | None:
    """The USD one reply cost at list price; None when its model has no price. A reply without the cache-write
    split prices all its writes at the 5-minute rate, and one without `output_tokens` prices no output."""
    rate = _reply_rate(usage, prices)
    if rate is None:
        return None
    return _input_side_usd(usage, rate) + (usage.output_tokens or 0) * rate.output / _PER_TOKENS


def input_rate(usage: TokenUsage, prices: PriceList) -> float | None:
    """The USD one token of the reply's context cost: the reply's input, cache-write and cache-read cost, with no
    output, over its context. None when the reply is unpriced or its context is empty."""
    rate = _reply_rate(usage, prices)
    context = context_of(usage)
    if rate is None or context == 0:
        return None
    return _input_side_usd(usage, rate) / context


def attributed_cost(
    carried: Sequence[CarriedReply], sources: SourceTable, prices: PriceList
) -> tuple[float | None, tuple[tuple[str, float], ...]]:
    """What the sources carried across the replies cost: the instruction files' total (None when no reply is
    priced) and each source's own sum. A source's cost in a reply is the tokens it carried times the reply's rate;
    an unpriced reply adds nothing."""
    per_source: dict[str, float] = {}
    instructions = 0.0
    priced = False
    for reply in carried:
        rate = input_rate(reply.usage, prices)
        if rate is None:
            continue
        priced = True
        for source, tokens in reply.by_source.items():
            usd = tokens * rate
            per_source[source] = per_source.get(source, 0.0) + usd
            entry = sources.get(source)
            if entry is not None and entry.kind == "instructions":
                instructions += usd
    return (instructions if priced else None), tuple(per_source.items())


def agent_cost(
    records: Sequence[EventRecord], prices: PriceList, t0: float, carried: Sequence[CarriedReply], sources: SourceTable
) -> XrayAgentCost:
    """What the `assistant_usage` records among `records` cost; `peak_turn_t` is seconds from `t0`, and `carried`
    is what each source carried per reply."""
    instructions, by_source = attributed_cost(carried, sources, prices)
    return replace(_replies_cost(records, prices, t0), instructions_usd_est=instructions, by_source_usd_est=by_source)


def _replies_cost(records: Sequence[EventRecord], prices: PriceList, t0: float) -> XrayAgentCost:
    """The cost of the replies among `records`, before any of it is attributed to a source."""
    priced: list[tuple[float, float | None]] = []
    unpriced: list[str] = []
    assumed = missing = unnamed = 0
    context = cached = 0
    for record in records:
        usage = record.usage
        if record.event != "assistant_usage" or usage is None:
            continue
        context += context_of(usage)
        cached += usage.cache_read_input_tokens
        cost = reply_cost(usage, prices)
        if cost is None:
            if usage.model is None:
                unnamed += 1
            else:
                unpriced.append(usage.model)
            continue
        moment = epoch(record.time)
        priced.append((cost, None if moment is None else moment - t0))
        assumed += _write_split(usage)[2]
        missing += usage.output_tokens is None
    peak = max(priced, key=lambda item: item[0], default=None)
    return XrayAgentCost(
        total_usd=sum(cost for cost, _ in priced) if priced else None,
        turns=len(priced) + len(unpriced) + unnamed,
        peak_turn_usd=None if peak is None else peak[0],
        peak_turn_t=None if peak is None else peak[1],
        cache_hit_rate=cached / context if context else None,
        unpriced=len(unpriced) + unnamed,
        unpriced_models=tuple(dict.fromkeys(unpriced)),
        split_assumed=assumed,
        output_missing=missing,
        instructions_usd_est=None,
        by_source_usd_est=(),
    )
