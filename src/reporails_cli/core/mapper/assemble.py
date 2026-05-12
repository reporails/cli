"""Mapper Stage 7: Assemble — wire-format construction from per-stage outputs.

Mechanical row-building: takes the file metadata, classified atoms, and topic
clusters produced by Stages 0-6 and packs them into the `RulesetMap` wire
format. No I/O, no ML, no decisions; pure dataclass assembly with
`schema_version` / `embedding_model` / `generated_at` stamped at construction
time. The on-disk JSON round-trip lives separately in `serialize.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from reporails_cli.core.platform.dto.ruleset import (
    EMBEDDING_MODEL,
    SCHEMA_VERSION,
    Atom,
    ClusterRecord,
    FileRecord,
    RulesetMap,
    RulesetSummary,
    TopicCluster,
)


def build_ruleset_map(
    file_records: list[FileRecord],
    all_atoms: list[Atom],
    topics: list[TopicCluster],
) -> RulesetMap:
    """Assemble the final RulesetMap from classified and clustered data."""
    cluster_records = [
        ClusterRecord(
            id=tc.topic_id,
            n_atoms=len(tc.atoms),
            n_charged=len(tc.charged),
            n_neutral=len(tc.atoms) - len(tc.charged),
            centroid=tc.centroid,
        )
        for tc in topics
    ]

    n_charged = sum(1 for a in all_atoms if a.charge_value != 0)
    summary = RulesetSummary(
        n_atoms=len(all_atoms),
        n_charged=n_charged,
        n_neutral=len(all_atoms) - n_charged,
        n_topics=len(topics),
        n_topics_charged=sum(1 for tc in topics if tc.charged),
    )

    return RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at=datetime.now(UTC).isoformat(),
        files=tuple(file_records),
        atoms=tuple(all_atoms),
        clusters=tuple(cluster_records),
        summary=summary,
    )
