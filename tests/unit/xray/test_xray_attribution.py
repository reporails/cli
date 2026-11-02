"""What a source cost: the tokens it carried in each reply times that reply's own per-token rate, summed over every
agent and every reply."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.events import EventRecord, TokenUsage
from reporails_cli.core.platform.dto.xray import Graph
from reporails_cli.core.xray.cost import input_rate, load_price_list
from tests.unit.xray.test_xray_graph import _agent, _file, _graph, _node, launch, load, rec

pytestmark = [pytest.mark.unit, pytest.mark.subsys_xray]

OPUS = "claude-opus-4-8"  # list: input 5, 5m write 6.25, read 0.5 per million
SONNET = "claude-sonnet-5-5"  # list: input 2, 5m write 2.5, read 0.1 per million
CLAUDE_MD_TOKENS = 100  # a 400-character file


def _reply(seconds: float, model: str, sub: str | None = None, **counts: int) -> EventRecord:
    usage = TokenUsage(
        f"m-{sub}-{seconds}",
        counts.get("input", 0),
        counts.get("write", 0),
        counts.get("read", 0),
        model=model,
        output_tokens=50,
    )
    return rec("assistant_usage", seconds, sub, usage=usage)


def _session(root: Path, sonnet_model: str = SONNET) -> Graph:
    """CLAUDE.md loads into main and into subagent A; each agent replies three times."""
    claude = _file(root, "CLAUDE.md", 400)
    records = [
        load(0.1, claude),
        _reply(1, OPUS, input=1_000),
        _reply(2, OPUS, input=100, read=900),
        _reply(3, OPUS, input=100, read=9_900),
        launch(4, "A", None, "tuA"),
        load(4.1, claude, "A"),
        _reply(5, sonnet_model, "A", input=1_000),
        _reply(6, sonnet_model, "A", input=100, read=900),
        _reply(7, sonnet_model, "A", input=100, read=9_900),
    ]
    return _graph(root, records, [claude])


def _cost(graph: Graph, path: str) -> float | None:
    return next(source.cost_usd_est for source in graph.sources if source.path == path)


def test_a_file_carried_across_three_replies_is_priced_at_each_replys_own_rate(tmp_path: Path) -> None:
    graph = _session(tmp_path)
    # Opus per token: reply 1 all input 5e-6; reply 2 (100*5 + 900*0.5)/1000 = 0.95e-6;
    # reply 3 (100*5 + 9900*0.5)/10000 = 0.545e-6.
    main = CLAUDE_MD_TOKENS * (5e-6 + 0.95e-6 + 0.545e-6)
    # Sonnet per token: reply 1 2e-6; reply 2 (100*2 + 900*0.1)/1000 = 0.29e-6;
    # reply 3 (100*2 + 9900*0.1)/10000 = 0.119e-6.
    sub = CLAUDE_MD_TOKENS * (2e-6 + 0.29e-6 + 0.119e-6)
    assert _cost(graph, "CLAUDE.md") == pytest.approx(main + sub)


def test_a_cache_read_heavy_reply_has_a_lower_rate_than_an_input_heavy_one() -> None:
    prices = load_price_list()
    heavy = input_rate(TokenUsage("a", 1_000, 0, 0, model=OPUS), prices)
    cached = input_rate(TokenUsage("b", 100, 0, 9_900, model=OPUS), prices)
    assert heavy is not None and cached is not None
    assert heavy == pytest.approx(5e-6)
    assert cached < heavy / 5


def test_an_unpriced_reply_has_no_rate_and_an_empty_one_neither() -> None:
    prices = load_price_list()
    assert input_rate(TokenUsage("a", 100, 0, 0, model="mystery-model"), prices) is None
    assert input_rate(TokenUsage("b", 0, 0, 0, model=OPUS), prices) is None


def test_an_unpriced_agents_replies_add_nothing_and_leave_the_source_to_the_priced_agent(tmp_path: Path) -> None:
    graph = _session(tmp_path, sonnet_model="mystery-model")
    assert _cost(graph, "CLAUDE.md") == pytest.approx(CLAUDE_MD_TOKENS * (5e-6 + 0.95e-6 + 0.545e-6))
    assert _agent(_node(graph, "A")).usage.cost.instructions_usd_est is None


def test_a_source_no_priced_reply_carried_has_no_cost(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    other = _file(tmp_path, "OTHER.md", 400)
    records = [load(0.1, claude), _reply(1, "mystery-model", input=1_000)]
    graph = _graph(tmp_path, records, [claude, other])
    assert [source.cost_usd_est for source in graph.sources] == [None, None]
    assert _agent(_node(graph, "main")).usage.cost.instructions_usd_est is None


def test_an_agents_instruction_cost_is_the_sum_of_its_instruction_files_costs(tmp_path: Path) -> None:
    claude = _file(tmp_path, "CLAUDE.md", 400)
    nested = _file(tmp_path, "pkg/CLAUDE.md", 800)
    rule = _file(tmp_path, "rules/r.md", 800, "rule")
    records = [load(0.1, claude), load(0.2, nested), load(0.3, rule), _reply(1, OPUS, input=1_000)]
    graph = _graph(tmp_path, records, [claude, nested, rule])
    by_path = {source.path: source.cost_usd_est for source in graph.sources}
    own = by_path["CLAUDE.md"], by_path["pkg/CLAUDE.md"]
    assert own[0] == pytest.approx(100 * 5e-6) and own[1] == pytest.approx(200 * 5e-6)
    assert by_path["rules/r.md"] == pytest.approx(200 * 5e-6)
    instructions = _agent(_node(graph, "main")).usage.cost.instructions_usd_est
    assert instructions == pytest.approx(sum(own))


def test_the_view_carries_both_estimates_under_their_est_names(tmp_path: Path) -> None:
    graph = _session(tmp_path)
    assert all("cost_usd_est" in source.to_json() for source in graph.sources)
    assert "instructions_usd_est" in _agent(_node(graph, "main")).usage.cost.to_json()
