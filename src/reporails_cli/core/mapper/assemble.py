"""Assemble — wire-format construction from mapped file data.

Mechanical row-building: takes the file metadata and classified atoms and
packs them into the `RulesetMap` wire format. No I/O, no ML,
no decisions; pure dataclass assembly with
`schema_version` / `embedding_model` / `generated_at` stamped at construction
time. The on-disk JSON round-trip lives separately in `serialize.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from reporails_cli.core.platform.dto.ruleset import (
    EMBEDDING_MODEL,
    SCHEMA_VERSION,
    Atom,
    FileRecord,
    RulesetMap,
    RulesetSummary,
)


def build_ruleset_map(
    file_records: list[FileRecord],
    all_atoms: list[Atom],
) -> RulesetMap:
    """Assemble the final RulesetMap from classified data."""
    n_charged = sum(1 for a in all_atoms if a.charge_value != 0)
    summary = RulesetSummary(
        n_atoms=len(all_atoms),
        n_charged=n_charged,
        n_neutral=len(all_atoms) - n_charged,
    )

    return RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at=datetime.now(UTC).isoformat(),
        files=tuple(file_records),
        atoms=tuple(all_atoms),
        summary=summary,
    )
