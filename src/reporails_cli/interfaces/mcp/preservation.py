"""The `preservation` and `conformance` blocks a `validate` reply carries for a file `remedy_brief` snapshotted."""

import asyncio
from pathlib import Path

from reporails_cli.core.heal.preservation.compare import rewrite_accepted
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.interfaces.mcp import snapshots
from reporails_cli.interfaces.mcp.validate_state import CircuitState


def with_preservation(
    payload: JsonObject, target: Path, ruleset_map: RulesetMap | None, score: float | None, scan_root: Path | None
) -> JsonObject:
    """Add the `preservation` block, and the `conformance` block (the file against the plan its
    brief listed), and `accepted` (whether the file is kept), to `payload` when `target` is a file
    `remedy_brief` snapshotted.
    Carried on both the bounded and full replies — the caller bounds afterward.

    Runs entirely off the event loop (the caller wraps this whole function in
    `asyncio.to_thread`). `ruleset_map` / `score` are the file's own, reused from the
    `CircuitState` cache on a cache-hit reply — this never re-runs the pipeline itself;
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
    out["accepted"] = rewrite_accepted(block, conformance)
    if out["accepted"] is True:
        snapshots.record_accepted(target, new_text)
    return out


async def breaker_reply(state: CircuitState, target: Path, scan_root: Path) -> JsonObject:
    """The `circuit_breaker` reply. For a file `remedy_brief` snapshotted whose last full reply the
    state still holds, it also carries `accepted`, decided from that reply by `with_preservation`."""
    reply: JsonObject = {
        "error": "circuit_breaker",
        "message": (
            "STOP — circuit breaker triggered. "
            f"Validated this path {state.call_count} times "
            f"({state.consecutive_unchanged} consecutive unchanged). "
            "DO NOT call validate again for this path. Instead: "
            "1. Report the remaining violations to the user. "
            "2. Explain which ones you could not resolve and why. "
            "3. Let the user decide how to proceed."
        ),
    }
    if state.full_payload is None:
        return reply
    kept = await asyncio.to_thread(
        with_preservation, state.full_payload, target, state.last_ruleset_map, state.last_score, scan_root
    )
    return {**reply, "accepted": kept["accepted"]} if "accepted" in kept else reply
