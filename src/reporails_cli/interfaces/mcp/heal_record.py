"""Writing the heal record from a project-level `validate`: the files a heal kept, as that run found them."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.heal.record import record_healed
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object
from reporails_cli.interfaces.mcp import snapshots


def record_kept_files(payload: JsonObject, scan_root: Path) -> None:
    """Upsert into the project's heal record each briefed file under `scan_root` still at its accepted text:
    its score and its per-rule finding counts in this project `payload`. Writes nothing when none qualifies."""
    if "error" in payload or "needs_install" in payload:
        return
    scores = as_object(payload.get("file_scores"))
    kept: dict[str, tuple[float | None, dict[str, int]]] = {}
    for name in snapshots.kept_files(scan_root):
        score = scores.get(name)
        kept[name] = (
            float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else None,
            snapshots.file_rule_counts(payload, name),
        )
    record_healed(scan_root, kept)
