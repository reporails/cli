"""MCP `validate` tool implementation.

Runs the check pipeline over a path, scores the files and assembles the reply (findings, stats,
surface health and, on the paid plan, the remediation workflow). `preflight` and `explain` live
in `rule_tools.py`.
"""

import logging
from dataclasses import replace
from pathlib import Path
from typing import Any, NamedTuple

from reporails_cli.core.discovery.agents import get_known_agents
from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.discovery.project_root import resolve_project_root, resolve_project_root_for_file
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.lint.regex.not_evaluated import not_evaluated_scope
from reporails_cli.core.lint.rule_runner import run_content_quality_checks, run_m_probes_over_pairs
from reporails_cli.core.mapper.model_manifest import ModelFetchError, get_models_path, models_present
from reporails_cli.core.mapper.skills import skill_membership
from reporails_cli.core.pipeline.assemble import (
    AssembleInputs,
    assemble_result,
    lint_request_local,
    with_exclusions,
)
from reporails_cli.core.pipeline.mapping import (
    agent_file_pairs,
    apply_generic_scan,
    discover_scope,
    map_instruction_files,
)
from reporails_cli.core.platform.adapters.api_key import has_api_key
from reporails_cli.core.platform.adapters.notices_seen import visible_notices
from reporails_cli.core.platform.config.config import get_project_config, get_rules_path, is_initialized
from reporails_cli.core.platform.dto.diagnostics import FunnelError, tiers_unpaid
from reporails_cli.core.platform.runtime.merger import normalize_finding_path
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters import mcp as mcp_formatter
from reporails_cli.formatters.host_hooks import host_hooks_field
from reporails_cli.formatters.text.funnel_cta import plain_cta
from reporails_cli.formatters.text.rule_meta import rule_aliases

logger = logging.getLogger(__name__)

# The `(folders, file globs)` a run left out because the user set them.
Excluded = tuple[tuple[str, ...], tuple[str, ...]]


class LeftOut(NamedTuple):
    """What a run left out: the `(folders, file globs)` to report and the exclusion set behind them."""

    record: Excluded = ((), ())
    exclusions: RunExclusions | None = None


NOTHING_LEFT_OUT = LeftOut()


def _unknown_agent_error(agent: str) -> dict[str, Any]:
    """The structured MCP equivalent of the CLI's `_validate_agent` exit.

    `ails --agent <bad>` (or a project's misconfigured `default_agent`) prints
    "Unknown agent: <bad>" + "Known agents: ..." and exits before ever discovering files.
    MCP has no console to print to, so it surfaces the same two facts as fields instead of
    masking the misconfiguration behind a generic "No instruction files found".
    """

    return {"error": f"Unknown agent: {agent}", "known_agents": sorted(get_known_agents())}


def _discover_files(
    target: Path, single_file: Path | None = None, named: frozenset[Path] = frozenset()
) -> tuple[list[Any], str, list[Any], dict[str, str], Excluded, Any] | dict[str, Any]:
    """Detect agents and discover instruction files.

    Returns `(filter_agents, agent, files, file_type_by_path, excluded, exclusions)` on success, `excluded` being the
    `(folders, file globs)` the pass left out (empty for a single file) and `exclusions` the run's exclusion set, or a
    terminal payload dict when there is nothing to lint: a structured "Unknown agent" error
    (mirroring the CLI's `_validate_agent`) for a misconfigured `default_agent`, or the
    CLI's own benign empty-project envelope (`formatters/json.py::empty_result_payload` —
    the SAME top-level shape a normal run emits, with `files: {}` and zeroed `stats`)
    when discovery legitimately comes up empty. An empty set is not an error: an
    AGENTS.md-only project under a `default_agent: claude` misconfiguration, or a
    rules-only tree with no distinctive main file, reports "nothing to find" exactly as
    the CLI does.

    `target` is the discovery root (a directory). Discovery narrows against the resolved agent
    set after the exclusions, not the raw detected list. When `generic_scanning` is on, the
    `@`-import-reached files join the discovered set. When `single_file` is given the validated
    set is that one file, kept whatever is excluded, while agents resolve against `target`, and
    `named` is ignored. Otherwise `named` holds files the caller named, which stay in the set
    whatever is excluded.
    """

    config = get_project_config(target)
    normalized_agent = (config.default_agent or "").lower().strip()
    if normalized_agent and normalized_agent not in get_known_agents():
        return _unknown_agent_error(normalized_agent)

    # A `single_file` target always resolves (its own existence is checked by the caller); only
    # the whole-project scan can legitimately come up with nothing to lint. The whole-project
    # scan includes each agent's config surfaces (hooks, permissions, MCP declarations, plugin
    # manifests) alongside its instruction and rule files, matching `ails check`'s own scope.
    found = discover_scope(
        target,
        config.default_agent,
        None,
        None,
        scan_files=single_file is None,
        named=frozenset({single_file}) if single_file is not None else named,
    )
    instruction_files = [safe_resolve(single_file)] if single_file is not None else found.files
    if not instruction_files:
        return json_formatter.empty_result_payload(target, found.excluded)

    import_extra, file_type_by_path = apply_generic_scan(
        target, instruction_files, found.effective_agent, config.generic_scanning, found.exclusions
    )
    if import_extra:
        instruction_files = list(instruction_files) + import_extra
    return found.filtered, found.effective_agent, instruction_files, file_type_by_path, found.excluded, found.exclusions


def _build_map(
    target: Path, instruction_files: list[Any], filter_agents: list[Any] | None = None
) -> tuple[Any, str | None]:
    """Build the ruleset map via the shared warm path, so `validate` reuses a warm model
    instead of loading one on every call.

    Never spawns a background process from here: the MCP server runs inside a
    multi-threaded process, and forking one from it can leave a new process holding a
    half-initialized copy of an already-loaded model. It attaches to an already-running
    background helper when one answers, else maps in-process.

    `filter_agents` (the caller's already-resolved `resolve_agent_filters` `filtered` list)
    is forwarded so this surface's file records carry the same corrected agent attribution
    as the CLI (`map_instruction_files`'s `stamp_file_agents`) — otherwise a Codex/Cursor
    project's `validate` reply could name a different agent than `ails check` for the same
    files.

    Returns `(ruleset_map, error)`: `error` is `None` on success, else the swallowed
    exception's own text (`"<ExceptionType>: <message>"`) — logged here same as before,
    but also handed back so a caller (`_lint_discovered` attaches it to the payload as
    `mapper_error`) can surface WHY the map came back empty instead of only a bare `None`.
    """
    try:
        return (
            map_instruction_files(target, list(instruction_files), spawn_daemon=False, filtered_agents=filter_agents),
            None,
        )
    except (ImportError, RuntimeError) as exc:
        logger.warning("Mapper unavailable in MCP: %s", exc)
        return None, f"{type(exc).__name__}: {exc}"


def _resolve_scan_target(target: Path) -> tuple[Path, Path | None]:
    """Map a target to `(scan_root, single_file)`.

    A directory target roots at itself (`resolve_project_root`, CLI parity). A FILE
    target cannot use that same function — it resolves to `target.parent`, which is
    right for the CLI only because the CLI's actual single-file root is the invoking
    terminal's `cwd`, not the file's directory (see `resolve_project_root_for_file`'s
    docstring). MCP has no cwd to read, so a file target walks up to the real project
    root instead, matching what the CLI resolves when a human `cd`s there first —
    otherwise `validate(".claude/rules/style.md")` roots at `.claude/rules`, which
    misclassifies the file and never shares the CLI's whole-map cache entry for the
    same file.
    """

    if target.is_file():
        return resolve_project_root_for_file(target), target
    return resolve_project_root(target), None


def model_not_ready_error() -> dict[str, Any] | None:
    """Make the model set available (downloading it once); an error payload if it is not.

    While a download already runs in this process (the server's launch-time fetch),
    return `model_downloading` at once instead of blocking the tool call on it.
    """

    from reporails_cli.core.mapper import (  # pylint: disable=import-outside-toplevel  # startup: the model fetch loads off the MCP handshake path
        model_fetch,
    )
    from reporails_cli.core.mapper.model_store import (  # pylint: disable=import-outside-toplevel  # startup: the model fetch loads off the MCP handshake path
        ensure_models_available,
    )

    if models_present(get_models_path()):
        return None
    if model_fetch.download_in_progress():
        return {
            "error": "model_downloading",
            "message": "The reporails model (~275 MB) is downloading for first use. Call validate again shortly.",
        }
    try:
        ensure_models_available()
    except ModelFetchError as exc:
        return {"error": "model_unavailable", "message": str(exc)}
    return None


def _display_score(result: Any, target: Path | None = None, scan_root: Path | None = None) -> float | None:
    """A single-file run's own per-file display score: the `per_file_analysis` entry whose
    normalized path IS `target`, falling back to the run's aggregate quality score only when
    `target` has no entry (never the first entry blindly — with `generic_scanning` on,
    `@`-imported files join the scored set, so entry 0 is not reliably the target's).
    `None` when neither is scored. `target=None` keeps the old first-entry fallback, for a
    caller with no specific file to match."""

    per_file = getattr(result, "per_file_analysis", ())
    if target is not None:
        target_key = normalize_finding_path(str(target), scan_root)
        match = next((fa for fa in per_file if normalize_finding_path(fa.file, scan_root) == target_key), None)
        if match is not None and match.display_score is not None:
            return float(match.display_score)
    elif per_file and per_file[0].display_score is not None:
        return float(per_file[0].display_score)
    quality = getattr(result, "quality", None)
    if quality is not None and quality.display_score is not None:
        return float(quality.display_score)
    return None


def _run_pipeline(
    target: Path, full: bool = False, named: frozenset[Path] = frozenset()
) -> tuple[dict[str, Any], Any, float | None]:
    """Run the full check pipeline; returns `(payload, ruleset_map, file_score)`.

    A file `target` narrows discovery to its project root and the validated set
    to that single file, mirroring the CLI single-path mode. Unless `full` is set the
    payload is bounded to a top-N-per-file envelope so a large repo stays under the
    harness per-tool-result token cap. `ruleset_map` is `None` on a structured
    error/needs-install payload (the caller checks `payload` for that). `file_score` is
    the single file's own display score (`None` for a directory target or an unscored
    file) — the same value `remedy_brief` reports for that file.
    """
    scan_root, single_file = _resolve_scan_target(target)
    discovery = _discover_files(scan_root, single_file=single_file, named=named)
    if isinstance(discovery, dict):
        return discovery, None, None
    model_error = model_not_ready_error()
    if model_error is not None:
        return model_error, None, None
    filter_agents, effective_agent, instruction_files, file_type_by_path, excluded, exclusions = discovery
    return _lint_discovered(
        scan_root,
        effective_agent,
        instruction_files,
        filter_agents,
        file_type_by_path=file_type_by_path,
        full=full,
        single_file=single_file,
        left_out=LeftOut(excluded, exclusions),
    )


def _lint_discovered(
    scan_root: Path,
    effective_agent: str,
    instruction_files: list[Any],
    filter_agents: list[Any],
    *,
    file_type_by_path: dict[str, str] | None = None,
    full: bool = False,
    single_file: Path | None = None,
    left_out: LeftOut = NOTHING_LEFT_OUT,
) -> tuple[dict[str, Any], Any, float | None]:
    """Run M-probes + content/client checks over discovered files; returns `(payload,
    ruleset_map, file_score)`.

    Regime + surface health key against `scan_root` (the validated path), not the
    server cwd — otherwise regime drops out and surface scores misroute for MCP.

    Level determination, merge, and post-merge suppression/mutation run through the shared
    `core/pipeline/assemble` spine, so this surface picks up the capability-level coverage
    the CLI check flow already has. `filter_agents` (the resolved, exclude-filtered agent
    set) drives the level policy, matching the CLI flow. `single_file` (when set) scopes
    the mechanical M-probes the same way `ails check <file>` does — project-aggregate
    checks skipped — and is also when `file_score` is computed. A server funnel rejection
    is carried onto the payload as a top-level `funnel` object; a mapper failure (ruleset_map
    came back `None`) is carried the same way as a top-level `mapper_error` string, so a
    caller (`remedy_brief`'s `brief_unavailable`) can name the real cause instead of a bare
    "produced no map". Unless `full` is set the formatted payload is bounded to a
    top-N-per-file envelope (aggregate stats + surface_health stay whole).
    """

    ruleset_map, mapper_error = _build_map(scan_root, instruction_files, filter_agents)
    result, funnel_error = _check_and_assemble(
        scan_root,
        instruction_files,
        effective_agent,
        filter_agents,
        ruleset_map,
        left_out=left_out,
        scoped=single_file is not None,
    )
    payload = json_formatter.format_combined_result(
        result, ruleset_map=ruleset_map, project_root=scan_root, file_type_by_path=file_type_by_path
    )
    payload = with_host_hooks(_attach_funnel(payload, funnel_error), result)
    if mapper_error is not None:
        payload["mapper_error"] = mapper_error
    payload = payload if full else mcp_formatter.bound_validate_payload(payload)
    return payload, ruleset_map, _display_score(result, single_file, scan_root) if single_file is not None else None


def with_host_hooks(payload: dict[str, Any], result: Any) -> dict[str, Any]:
    """`payload` plus the `host_hooks` entries of `result`, for the MCP `validate` reply only:
    `ails check -f json` never lists the machine's own hooks."""
    return {**payload, **host_hooks_field(result.hooks)}


def _mcp_agent_file_pairs(
    scan_root: Path, instruction_files: list[Any], filter_agents: list[Any], effective_agent: str
) -> list[tuple[str, list[Any]]]:
    """MCP's thin wrapper over the shared `core.pipeline.mapping.agent_file_pairs` split --
    explicit-agent-ness for MCP `validate` can only come from the project's `default_agent`
    (no per-call `--agent`-style override the way the CLI has one)."""

    explicit = bool(get_project_config(scan_root).default_agent)
    return agent_file_pairs(
        instruction_files, filter_agents, scan_root, explicit=explicit, effective_agent=effective_agent
    )


def _check_and_assemble(
    scan_root: Path,
    instruction_files: list[Any],
    effective_agent: str,
    filter_agents: list[Any],
    ruleset_map: Any,
    *,
    left_out: LeftOut = NOTHING_LEFT_OUT,
    scoped: bool = False,
) -> tuple[Any, Any]:
    """Run the local checks, then `_assemble_mcp_result`; the request is resolved under the agents whose rules ran."""
    pairs = _mcp_agent_file_pairs(scan_root, instruction_files, filter_agents, effective_agent)
    with not_evaluated_scope() as unfinished:
        local = _checks_over_pairs(scan_root, pairs, ruleset_map, scoped, left_out.exclusions)

    result, funnel_error = _assemble_mcp_result(
        scan_root,
        effective_agent,
        filter_agents,
        ruleset_map,
        local,
        rule_agents=tuple(dict.fromkeys(agent_id for agent_id, _ in pairs)),
        not_evaluated=tuple(unfinished),
        exclusions=left_out.exclusions,
    )
    return with_exclusions(result, left_out.record), funnel_error


def _checks_over_pairs(
    scan_root: Path,
    pairs: list[tuple[str, list[Any]]],
    ruleset_map: Any,
    scoped: bool,
    exclusions: RunExclusions | None = None,
) -> tuple[list[Any], list[Any], list[Any]]:
    """Run M-probes + content/client checks over the `(agent, its files)` pairs, returning
    `(m_findings, content_findings, client_findings)`.

    `scoped` mirrors the CLI's `state.scope.is_targeted` — True for a single-file `validate`
    target, so project-aggregate mechanical checks (e.g. total-bytes / file-count bounds)
    are skipped exactly like `ails check <file>` skips them.

    The pairs come from the SAME `agent_file_pairs` split the CLI check flow uses (via
    `_mcp_agent_file_pairs`): a native file runs its owner's rules, an unowned file runs the
    core rules only, so `validate` reports identical `(rule, file, line)` triples to
    `ails check` for the same tree.
    """

    skills = skill_membership(ruleset_map)
    m_findings = run_m_probes_over_pairs(scan_root, pairs, scoped=scoped, skills=skills, exclusions=exclusions)
    content_findings: list[Any] = []
    for agent_id, agent_files in pairs:
        if ruleset_map:
            content_findings.extend(
                run_content_quality_checks(ruleset_map, scan_root, agent_files, agent=agent_id, exclusions=exclusions)
            )
    client_findings = run_client_checks(ruleset_map) if ruleset_map else []
    return m_findings, content_findings, client_findings


def _build_assemble_inputs(
    scan_root: Path,
    effective_agent: str,
    filter_agents: list[Any],
    ruleset_map: Any,
    local: tuple[list[Any], list[Any], list[Any]],
    *,
    rule_agents: tuple[str, ...] = (),
    not_evaluated: tuple[tuple[str, str], ...] = (),
) -> Any:
    """The shared `AssembleInputs` for `_assemble_mcp_result`, built from the local M-probe /
    content / client finding lists."""

    m_findings, content_findings, client_findings = local
    return AssembleInputs(
        m_findings=m_findings,
        content_findings=content_findings,
        client_findings=client_findings,
        ruleset_map=ruleset_map,
        scan_root=scan_root,
        filter_agents=filter_agents,
        effective_agent=effective_agent,
        lint_result=None,
        alias_fn=rule_aliases,
        rule_agents=rule_agents,
        not_evaluated=not_evaluated,
    )


def _server_lint_result(inputs: Any) -> tuple[Any, Any, tuple[Any, ...]]:
    """Run `_server_lint` and split its response into `(lint_result, funnel_error, notices)` — `(None,
    None, ())` when nothing was mapped (offline / no ruleset)."""
    response = _server_lint(inputs)
    if response is None:
        return None, None, ()
    return response.result, response.funnel_error, visible_notices(response.notices)


def _assemble_mcp_result(
    scan_root: Path,
    effective_agent: str,
    filter_agents: list[Any],
    ruleset_map: Any,
    local: tuple[list[Any], list[Any], list[Any]],
    *,
    rule_agents: tuple[str, ...] = (),
    not_evaluated: tuple[tuple[str, str], ...] = (),
    exclusions: RunExclusions | None = None,
) -> tuple[Any, Any]:
    """Server-lint the local findings, then run the shared assemble spine. Returns `(result, funnel_error)`."""

    inputs = _build_assemble_inputs(
        scan_root,
        effective_agent,
        filter_agents,
        ruleset_map,
        local,
        rule_agents=rule_agents,
        not_evaluated=not_evaluated,
    )
    lint_result, funnel_error, notices = _server_lint_result(inputs)
    return assemble_result(replace(inputs, lint_result=lint_result, notices=notices), exclusions), funnel_error


def _server_lint(inputs: Any) -> Any:
    """Send the reported local findings to the server and return the `LintResponse`.

    `.result` is None when offline. Returning the whole response (not just `.result`) lets the
    caller also read `.funnel_error` — a server-side rejection (rate limit, payload/atom cap,
    project limit) that must not read like a network outage. None when nothing was mapped.
    """

    if not inputs.ruleset_map:
        return None
    from reporails_cli.core.platform.adapters.api_client import (  # pylint: disable=import-outside-toplevel  # startup: the HTTP client loads on a server request
        AilsClient,
    )

    local, structural_required = lint_request_local(inputs)
    return AilsClient().lint(inputs.ruleset_map, local, structural_required, root=inputs.scan_root)


def is_retryable_reply(payload: dict[str, Any]) -> bool:
    """True when the reply's server failure is a temporary one (`funnel.retryable`)."""
    funnel = payload.get("funnel")
    return isinstance(funnel, dict) and funnel.get("retryable") is True


def _attach_funnel(payload: dict[str, Any], funnel_error: Any) -> dict[str, Any]:
    """Carry a server funnel rejection onto the payload as a top-level `funnel` object.

    Without this, `_server_lint` dropping `response.funnel_error` made a rate-limit / payload
    cap / atom cap / project-limit rejection indistinguishable from an offline server — both
    left `offline: true` and no explanation. The CLI text path shows the same information via
    `_render_funnel_cta` (`formatters.text.funnel_cta::format_cta`); this mirrors it for MCP consumers.

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


def unpaid_signed_in_reply(payload: dict[str, Any]) -> bool:
    """True when a signed-in user's reply carries a non-paid tier (reported, or named by a funnel
    rejection). Anonymous replies and paid replies are False."""

    if not has_api_key():
        return False
    funnel = payload.get("funnel")
    return tiers_unpaid(payload.get("tier"), funnel.get("tier") if isinstance(funnel, dict) else None)


def _rules_missing_payload() -> dict[str, Any]:
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


def run_pipeline_for_path(
    path: str, full: bool = False, named: frozenset[Path] = frozenset()
) -> tuple[dict[str, Any], Any, float | None]:
    """Run the pipeline for `path` (directory or file); returns `(payload, ruleset_map,
    file_score)`. `ruleset_map` and `file_score` are `None` on a structured error/needs-install
    payload — the caller checks `"error"` / `"needs_install"` in the payload, as `validate_tool`
    does. For a directory `path`, `named` holds files the caller named, which are checked whatever is
    excluded; the Excluded record still lists every pattern the user set. For a file `path` only that
    file is named and `named` is ignored.
    """
    if not is_initialized():
        return _rules_missing_payload(), None, None
    target = Path(path).resolve()
    if not target.exists():
        return {"error": f"Path not found: {target}"}, None, None
    # When `path` is an existing file, the pipeline narrows discovery to the
    # file's project root and the validated set to that single file.
    try:
        return _run_pipeline(target, full=full, named=named)
    except (FileNotFoundError, ValueError, RuntimeError) as e:
        return {"error": str(e)}, None, None


def validate_tool(path: str = ".", full: bool = False) -> dict[str, Any]:
    """Validate AI instruction files at `path` (directory OR single file).

    The slash-command body consumes the response per its Check loop — opens
    with one paragraph naming the worst surface + dominant category, then
    spawns the fix-walk sub-agent. Returns a structured `needs_install`
    response (not a bare error) when framework rules are absent, so the
    slash-command body can surface an actionable next step.

    By default the response is bounded to a top-N-per-file envelope (aggregate
    `stats` / `surface_health` / `level` stay whole) so a large repo stays under the
    harness per-tool-result token cap; pass `full=true` for the complete finding set.
    """
    payload, _ruleset_map, _score = run_pipeline_for_path(path, full)
    return payload
