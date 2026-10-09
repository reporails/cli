"""`heal_apply`'s pieces: the keyed heal over a validated project, its text view, and the state it releases."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from reporails_cli.formatters.mcp_view import render_heal_apply
from reporails_cli.interfaces.mcp import snapshots


def heal_apply_message(payload: dict[str, Any], *, mapped: bool = True) -> str:
    """Why `heal_apply` wrote nothing, in the words `ails check --heal` uses.

    A reply that is offline, carries a server error or funnel rejection, or came with no map to fix
    (`mapped` false) is "no fixes came"; only a clean reply without fixes means the account is not Pro.
    """
    from reporails_cli.core.heal.apply import heal_withheld_for_run

    if "error" in payload:
        return f"heal_apply: {payload.get('message') or payload['error']}"
    funnel = payload.get("funnel")
    funnel = funnel if isinstance(funnel, dict) else {}
    replied = mapped and not (payload.get("offline") or payload.get("server_error") or funnel)
    _, message = heal_withheld_for_run(
        error=funnel.get("error"), tier=payload.get("tier"), funnel_tier=funnel.get("tier"), server_replied=replied
    )
    return f"heal_apply: {message}"


def heal_apply_write(ruleset_map: Any, workflow: dict[str, Any], target: Path, scan_root: Path) -> str:
    """Write the workflow's keyed fixes within `target`'s scope; the text view of what was done."""
    from reporails_cli.core.heal.apply import apply_keyed_heal, resolved_within, suppressed_by_path
    from reporails_cli.core.platform.adapters.workflow_wire import deserialize_workflow

    files = sorted({Path(a.file_path) for a in ruleset_map.atoms})
    files = [f for f in files if resolved_within(f, target)]
    result = apply_keyed_heal(
        ruleset_map,
        scan_root,
        deserialize_workflow({"workflow": workflow}),
        dry_run=False,
        allowed_files=files,
        suppressed=suppressed_by_path(files, scan_root),
    )
    return render_heal_apply(result.fixes, result.decisions, result.put_back, scan_root)


def release_written(scan_root: Path, states: Mapping[str, Any]) -> None:
    """The next `validate` / `remedy_brief` read the written files as the new baseline: release the held
    snapshots and drop the stored reply of each validate state under `scan_root`."""
    snapshots.release_holds(scan_root)
    for key, state in states.items():
        if Path(key.split("|", 1)[0]).is_relative_to(scan_root):
            state.full_payload, state.last_mtime_hash = None, ""
