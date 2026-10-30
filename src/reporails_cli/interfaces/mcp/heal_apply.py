"""`heal_apply`'s pieces: the keyed heal over a validated project, its text view, and the state it releases."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from reporails_cli.core.heal.apply import heal_server_replied, heal_withheld_for_run, heal_workflow_within
from reporails_cli.core.platform.adapters.workflow_wire import deserialize_workflow
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.formatters.mcp_view import render_heal_apply
from reporails_cli.interfaces.mcp import snapshots

if TYPE_CHECKING:
    from reporails_cli.interfaces.mcp.server import _CircuitState


def heal_apply_message(payload: JsonObject, *, mapped: bool = True) -> str:
    """Why `heal_apply` wrote nothing, in the words `ails check --heal` uses.

    A reply that is offline, carries a server error or funnel rejection, or came with no map to fix
    (`mapped` false) is "no fixes came"; only a clean reply without fixes means the account is not Pro.
    """

    if "error" in payload:
        return f"heal_apply: {payload.get('message') or payload['error']}"
    funnel = payload.get("funnel")
    funnel = funnel if isinstance(funnel, dict) else {}
    replied = heal_server_replied(
        mapped=mapped, offline=bool(payload.get("offline")), rejected=bool(payload.get("server_error") or funnel)
    )
    error, tier, funnel_tier = (
        v if isinstance(v, str) else None for v in (funnel.get("error"), payload.get("tier"), funnel.get("tier"))
    )
    _, message = heal_withheld_for_run(error=error, tier=tier, funnel_tier=funnel_tier, server_replied=replied)
    return f"heal_apply: {message}"


def heal_apply_write(ruleset_map: RulesetMap, workflow: JsonObject, target: Path, scan_root: Path) -> str:
    """Write the workflow's keyed fixes within `target`'s scope; the text view of what was done."""

    result = heal_workflow_within(ruleset_map, deserialize_workflow({"workflow": workflow}), target, scan_root)
    return render_heal_apply(result.fixes, result.decisions, result.put_back, scan_root)


def release_written(scan_root: Path, states: Mapping[str, _CircuitState]) -> None:
    """The next `validate` / `remedy_brief` read the written files as the new baseline: release the held
    snapshots and drop the stored reply of each validate state under `scan_root`."""
    snapshots.release_holds(scan_root)
    for key, state in states.items():
        if Path(key.split("|", 1)[0]).is_relative_to(scan_root):
            state.full_payload, state.last_mtime_hash = None, ""
