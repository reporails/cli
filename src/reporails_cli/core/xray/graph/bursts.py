"""The bursts of a node: children it launched in one quick run."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from reporails_cli.core.platform.dto.xray import XrayBurstSettings
from reporails_cli.core.platform.dto.xray_graph import XrayBurst, XrayEdge


def _ends(group: Sequence[XrayEdge], node_ends: Mapping[str, float]) -> float | None:
    """When the last member ended: a member that is not running ends at its hand-back, else at its own end;
    None while any member is running."""
    if any(edge.outcome == "running" for edge in group):
        return None
    times = [edge.back_t if edge.back_t is not None else node_ends.get(edge.child) for edge in group]
    known = [t for t in times if t is not None]
    return max(known) if known else None


def _burst(group: Sequence[XrayEdge], node_ends: Mapping[str, float]) -> XrayBurst:
    return XrayBurst(
        tuple(edge.child for edge in group),
        group[0].out_t,
        _ends(group, node_ends),
        sum(edge.down for edge in group),
    )


def bursts(
    edges: Sequence[XrayEdge], span: float, settings: XrayBurstSettings, node_ends: Mapping[str, float]
) -> tuple[XrayBurst, ...]:
    """The bursts among the launches `edges` of one node whose run lasted `span` seconds: from a child, every
    following child launched within the larger of the window and its share of `span` joins it; a group of at least
    the minimum size is a burst, otherwise its first child stands alone and the walk goes on at the next one.
    `node_ends` holds each child's own end time."""
    limit = max(settings.window_s, settings.window_share * span)
    ordered = sorted(edges, key=lambda edge: edge.out_t)
    found: list[XrayBurst] = []
    start = 0
    while start < len(ordered):
        end = start + 1
        while end < len(ordered) and ordered[end].out_t - ordered[start].out_t <= limit:
            end += 1
        if end - start >= settings.min_size:
            found.append(_burst(ordered[start:end], node_ends))
            start = end
        else:
            start += 1
    return tuple(found)
