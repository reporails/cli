"""Writing the heal record from a project-level `validate`: the files a heal kept, as that run found them."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.heal.record import record_healed
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object, opt_float
from reporails_cli.interfaces.mcp import snapshots


def record_kept_files(payload: JsonObject, scan_root: Path) -> None:
    """Upsert into the project's heal record each briefed file under `scan_root` still at its accepted text,
    not yet recorded, and covered by this project `payload`: its score and per-rule finding counts. Writes
    nothing for a degraded run (offline, a server error, skipped content checks, no file scores) or when no
    file qualifies."""
    if any(
        payload.get(flag) for flag in ("error", "needs_install", "offline", "server_error", "content_checks_skipped")
    ):
        return
    scores = as_object(payload.get("file_scores"))
    if not scores:
        return
    covered = set(as_object(payload.get("files"))) | set(scores)
    keys_of = snapshots.kept_files(scan_root, covered)
    record_healed(
        scan_root,
        {name: (opt_float(scores.get(name)), snapshots.file_rule_counts(payload, name)) for name in keys_of},
    )
    snapshots.mark_recorded(keys_of.values())
