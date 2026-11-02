"""The bursts of a node: children it launched in one quick run."""

from __future__ import annotations

from collections.abc import Sequence

from reporails_cli.core.platform.dto.xray import XrayBurstSettings
from reporails_cli.core.platform.dto.xray_graph import XrayBurst, XrayEdge


def _burst(group: Sequence[XrayEdge]) -> XrayBurst:
    returns = [edge.back_t for edge in group]
    back = [t for t in returns if t is not None]
    return XrayBurst(
        tuple(edge.child for edge in group),
        group[0].out_t,
        max(back) if len(back) == len(returns) else None,
        sum(edge.down for edge in group),
    )


def bursts(edges: Sequence[XrayEdge], span: float, settings: XrayBurstSettings) -> tuple[XrayBurst, ...]:
    """The bursts among the launches `edges` of one node whose run lasted `span` seconds: from a child, every
    following child launched within the larger of the window and its share of `span` joins it; a group of at least
    the minimum size is a burst, otherwise its first child stands alone and the walk goes on at the next one."""
    limit = max(settings.window_s, settings.window_share * span)
    ordered = sorted(edges, key=lambda edge: edge.out_t)
    found: list[XrayBurst] = []
    start = 0
    while start < len(ordered):
        end = start + 1
        while end < len(ordered) and ordered[end].out_t - ordered[start].out_t <= limit:
            end += 1
        if end - start >= settings.min_size:
            found.append(_burst(ordered[start:end]))
            start = end
        else:
            start += 1
    return tuple(found)
