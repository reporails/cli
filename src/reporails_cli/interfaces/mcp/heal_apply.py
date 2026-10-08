"""`heal_apply`'s pieces: the keyed heal over a validated project, its text view, and the state it releases."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from reporails_cli.formatters.mcp_view import render_heal_apply
from reporails_cli.interfaces.mcp import snapshots


def heal_apply_message(payload: dict[str, Any]) -> str:
    """Why `heal_apply` wrote nothing, in the words `ails check --heal` uses."""
    from reporails_cli.core.heal.apply import HEAL_PRO_REQUIRED, HEAL_SIGN_IN
    from reporails_cli.core.platform.adapters.api_client import has_api_key

    if "error" in payload:
        return f"heal_apply: {payload.get('message') or payload['error']}"
    if not has_api_key():
        return f"heal_apply: {HEAL_PRO_REQUIRED} {HEAL_SIGN_IN}"
    return f"heal_apply: {HEAL_PRO_REQUIRED} Nothing was changed."


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
