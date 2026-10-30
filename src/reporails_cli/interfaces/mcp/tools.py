"""MCP `validate` tool translation: a core check run into the reply payload.

`core/pipeline/check_one.py` decides what is checked and returns a typed `CheckRun` or a `Refusal`; this
module words the refusal as a structured reply and formats the run as the payload (findings, stats, surface
health and, on the paid plan, the remediation workflow). `preflight` and `explain` live in `rule_tools.py`.
"""

from pathlib import Path

from reporails_cli.core.discovery.agents import get_known_agents
from reporails_cli.core.pipeline.check_one import CheckRun, Refusal, check_path, model_refusal
from reporails_cli.core.platform.adapters.api_key import has_api_key
from reporails_cli.core.platform.config.config import get_rules_path
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import FunnelError, tiers_unpaid
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.runtime.merger import CombinedResult
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.formatters.host_hooks import host_hooks_field
from reporails_cli.formatters.text.funnel_cta import plain_cta


def _unknown_agent_error(agent: str) -> JsonObject:
    """The structured MCP equivalent of the CLI's `_validate_agent` exit.

    `ails --agent <bad>` (or a project's misconfigured `default_agent`) prints
    "Unknown agent: <bad>" + "Known agents: ..." and exits before ever discovering files.
    MCP has no console to print to, so it surfaces the same two facts as fields instead of
    masking the misconfiguration behind a generic "No instruction files found".
    """

    return {"error": f"Unknown agent: {agent}", "known_agents": [*sorted(get_known_agents())]}


def _rules_missing_payload() -> JsonObject:
    """The reply when the rules folder is missing or has no `core` rules: the rules ship inside
    the package, so this means a broken install or a `framework_path` setting that points at a
    folder without them."""

    return {
        "needs_install": True,
        "message": (
            f"The rules folder {get_rules_path()} has no `core` rules. The rules ship with the "
            "package: reinstall reporails-cli, or, if the config sets `framework_path`, point it "
            "at a folder that holds them or remove the setting."
        ),
    }


def refusal_payload(refusal: Refusal) -> JsonObject:
    """The structured reply for a path that was not checked."""
    match refusal.kind:
        case "rules_missing":
            return _rules_missing_payload()
        case "unknown_agent":
            return _unknown_agent_error(refusal.message)
        case "empty_project":
            return json_formatter.empty_result_payload(refusal.target, refusal.excluded)
        case "model_downloading" | "model_unavailable":
            return {"error": refusal.kind, "message": refusal.message}
        case "path_not_found" | "failed":
            return {"error": refusal.message}


def model_not_ready_error() -> JsonObject | None:
    """The error payload when the model set is not ready (downloading it once first), else `None`."""
    refusal = model_refusal()
    return None if refusal is None else refusal_payload(refusal)


def with_host_hooks(payload: JsonObject, result: CombinedResult) -> JsonObject:
    """`payload` plus the `host_hooks` entries of `result`, for the MCP `validate` reply only:
    `ails check -f json` never lists the machine's own hooks."""
    return {**payload, **host_hooks_field(result.hooks)}


def is_retryable_reply(payload: JsonObject) -> bool:
    """True when the reply's server failure is a temporary one (`funnel.retryable`)."""
    funnel = payload.get("funnel")
    return isinstance(funnel, dict) and funnel.get("retryable") is True


def _attach_funnel(payload: JsonObject, funnel_error: FunnelError | None) -> JsonObject:
    """Carry a server funnel rejection onto the payload as a top-level `funnel` object.

    Without this, a rate-limit / payload cap / atom cap / project-limit rejection was
    indistinguishable from an offline server: both left `offline: true` and no explanation. The CLI
    text path shows the same information via `_render_funnel_cta`
    (`formatters.text.funnel_cta::format_cta`); this mirrors it for MCP consumers.

    `payload["offline"]` is left exactly as `format_combined_result` already set it. A funnel
    rejection only ever reaches here when the server produced no diagnostics report — the same
    condition the CLI's own JSON `offline` field reports for the same run — so this never
    recomputes `offline` from the rejection's own HTTP status; a plain 404/500 with no
    parseable body carries a real status yet is still an offline run on both surfaces.

    `message` and the payload's `server_error` both build from the same `plain_cta` /
    `format_server_error` serializer `formatters/json.py::format_server_error` uses, so the
    MCP `funnel` object, the MCP `server_error` field, and the CLI JSON `server_error` field
    agree word for word instead of drifting under three renderings of one error.
    """

    if not isinstance(funnel_error, FunnelError):
        return payload
    server_error = json_formatter.format_server_error(funnel_error)
    payload = {**payload, "server_error": server_error}
    payload["funnel"] = {
        "error": funnel_error.error,
        "message": plain_cta(funnel_error),
        "upgrade_url": funnel_error.upgrade_url,
        "status": funnel_error.status,
        "tier": funnel_error.tier,
        "retryable": server_error["retryable"] if server_error else False,
        "retry_after": server_error["retry_after"] if server_error else None,
    }
    return payload


def unpaid_signed_in_reply(payload: JsonObject) -> bool:
    """True when a signed-in user's reply carries a non-paid tier (reported, or named by a funnel
    rejection). Anonymous replies and paid replies are False."""

    if not has_api_key():
        return False
    funnel = payload.get("funnel")
    tier = payload.get("tier")
    funnel_tier = funnel.get("tier") if isinstance(funnel, dict) else None
    return tiers_unpaid(tier if isinstance(tier, str) else None, funnel_tier if isinstance(funnel_tier, str) else None)


def format_run(run: CheckRun, *, full: bool) -> JsonObject:
    """The `validate` payload of a finished check. Unless `full` is set it is bounded to a
    top-N-per-file envelope (aggregate stats + surface_health stay whole), so a large repo stays under
    the harness per-tool-result token cap. A server funnel rejection is carried as a top-level `funnel`
    object; a mapper failure as a top-level `mapper_error` string, so a caller (`remedy_brief`'s
    `brief_unavailable`) can name the real cause instead of a bare "produced no map"."""
    payload = json_formatter.format_combined_result(
        run.result,
        ruleset_map=run.ruleset_map,
        project_root=run.scope.scan_root,
        file_type_by_path=run.scope.file_type_by_path,
    )
    payload = with_host_hooks(_attach_funnel(payload, run.funnel_error), run.result)
    if run.mapper_error is not None:
        payload["mapper_error"] = run.mapper_error
    return payload if full else mcp_formatter.bound_validate_payload(payload)


def run_pipeline_for_path(
    path: str, full: bool = False, named: frozenset[Path] = frozenset()
) -> tuple[JsonObject, RulesetMap | None, float | None]:
    """Check `path` (directory or file); returns `(payload, ruleset_map, file_score)`. `ruleset_map` and
    `file_score` are `None` on a structured error/needs-install payload — the caller checks `"error"` /
    `"needs_install"` in the payload. A file `path` narrows the validated set to that single file;
    `file_score` is that single file's own display score (`None` for a directory or an unscored file).
    `named` is read as in `core.pipeline.check_one.scope_for_path`.
    """
    try:
        run = check_path(path, named)
        if isinstance(run, Refusal):
            return refusal_payload(run), None, None
        return format_run(run, full=full), run.ruleset_map, run.file_score
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return {"error": str(e)}, None, None
