"""The seam node kinds plug into: a producer turns a session's records into nodes, and the builder links whatever the
registered producers return."""

from __future__ import annotations

from reporails_cli.core.platform.dto.xray_build import NodeProducer

# The registered producers, in the order their nodes are listed.
PRODUCERS: list[NodeProducer] = []


def register(producer: NodeProducer) -> None:
    """Add `producer` to the registered ones; raises `ValueError` when a producer of its kind is registered."""
    if any(item.kind == producer.kind for item in PRODUCERS):
        raise ValueError(f"a producer of node kind {producer.kind!r} is already registered")
    PRODUCERS.append(producer)
