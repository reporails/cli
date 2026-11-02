"""The `preservation` and `conformance` blocks a `validate` reply carries for a file `remedy_brief` snapshotted."""

from pathlib import Path

from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.interfaces.mcp import snapshots


def with_preservation(
    payload: JsonObject, target: Path, ruleset_map: RulesetMap | None, score: float | None, scan_root: Path | None
) -> JsonObject:
    """Add the `preservation` block, and the `conformance` block (the file against the plan its
    brief listed), to `payload` when `target` is a file `remedy_brief` snapshotted.
    Carried on both the bounded and full replies — the caller bounds afterward.

    Runs entirely off the event loop (the caller wraps this whole function in
    `asyncio.to_thread`). `ruleset_map` / `score` are the file's own, reused from the
    `_CircuitState` cache on a cache-hit reply — this never re-runs the pipeline itself;
    a caller that has no map to hand it (an unusual, defensively-guarded case) sees no
    preservation block rather than paying a second pipeline run here. `scan_root` is the
    project root the preservation `invented_named` check resolves a path-shaped named token
    against. A file that cannot be read gets no block.
    """
    if "error" in payload or "needs_install" in payload:
        return payload
    if not target.is_file() or ruleset_map is None:
        return payload
    snap = snapshots.get_snapshot(target)
    if snap is None:
        return payload
    try:
        new_text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return payload
    block = snapshots.check_rewrite(snap, target, ruleset_map, new_text, score=score, scan_root=scan_root)
    block["introduced"] = snapshots.introduced_count(target, payload)
    out = {**payload, "preservation": block}
    conformance = snapshots.check_conformance(target, ruleset_map, new_text, scan_root)
    if conformance is not None:
        out["conformance"] = conformance
    return out
