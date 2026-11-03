"""The price list of a model family and what an agent's replies cost, as numbers and names.

A value with no source is `None`, which reads as "not known here".
"""

from __future__ import annotations

from dataclasses import dataclass

from reporails_cli.core.platform.contract.json_value import JsonObject


@dataclass(frozen=True)
class Rate:
    """USD per million tokens of each class of token."""

    input: float
    cache_write_5m: float
    cache_write_1h: float
    cache_read: float
    output: float


@dataclass(frozen=True)
class LongPrompt:
    """The rates that replace a model's base rates for a reply whose prompt is over `above_tokens`."""

    above_tokens: int
    rate: Rate


@dataclass(frozen=True)
class ModelPrices:
    """The model ids one price row covers, its rates and the long-prompt rates when it has them."""

    ids: tuple[str, ...]
    rate: Rate
    long_prompt: LongPrompt | None


@dataclass(frozen=True)
class PriceListInfo:
    """Which list priced the view: its name, the day it was read, where and in what unit, and the sentence that
    states how a source's cost is worked out from it."""

    name: str
    as_of: str
    source: str
    unit: str
    source_method: str

    def to_json(self) -> JsonObject:
        """The list's identity as a JSON object; no price is in it."""
        return {
            "name": self.name,
            "as_of": self.as_of,
            "source": self.source,
            "unit": self.unit,
            "source_method": self.source_method,
        }


@dataclass(frozen=True)
class PriceList:
    """A bundled price list: its identity and one row per model family."""

    info: PriceListInfo
    models: tuple[ModelPrices, ...]


@dataclass(frozen=True)
class XrayAgentCost:
    """What an agent's replies cost at list price: the total, the dearest reply, the share of the context read from
    the cache, and how many replies could not be priced or were priced on an assumption."""

    total_usd: float | None
    turns: int
    peak_turn_usd: float | None
    peak_turn_t: float | None
    cache_hit_rate: float | None
    unpriced: int
    unpriced_models: tuple[str, ...]
    split_assumed: int
    output_missing: int
    # What the instruction files carried across the replies cost, an estimate (the carried tokens are estimated).
    instructions_usd_est: float | None
    # Each source id with the estimated USD it cost across the replies; the graph sums them onto the sources.
    by_source_usd_est: tuple[tuple[str, float], ...]

    def to_json(self) -> JsonObject:
        """The cost as a JSON object."""
        return {
            "total_usd": self.total_usd,
            "turns": self.turns,
            "peak_turn_usd": self.peak_turn_usd,
            "peak_turn_t": self.peak_turn_t,
            "cache_hit_rate": self.cache_hit_rate,
            "unpriced": self.unpriced,
            "unpriced_models": list(self.unpriced_models),
            "split_assumed": self.split_assumed,
            "output_missing": self.output_missing,
            "instructions_usd_est": self.instructions_usd_est,
        }
