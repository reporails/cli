"""MCP server for reporails — exposes validation tools to MCP clients.

Registers `validate` / `preflight` / `explain` on the mcp 2.x high-level
`MCPServer`. `validate` and `preflight` return a pre-built `CallToolResult`
(see `_result`) carrying the wire payload as `structured_content` plus a compact
text mirror; `explain` returns text with `structured_output=False`. Returning a
pre-built result rather than a typed return leaves `output_schema` unset, so the
SDK derives no output schema from an internal model — only the explicit wire
payload is exposed and no non-wire field can reach the schema.
"""

# ─────────────────────────────────────────────────────────────────────
# CRITICAL: the import blocker MUST run before any import that could
# transitively pull a heavy ML backend. The MCP server is long-lived and
# serves many tool calls; skipping that import makes the first validate/score
# calls fast. See `_torch_blocker` docstring for details.
from reporails_cli.core.platform.runtime import _torch_blocker

_torch_blocker.install()
# ─────────────────────────────────────────────────────────────────────

import asyncio  # noqa: E402
import json  # noqa: E402
import threading  # noqa: E402
from dataclasses import dataclass, field  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402

from mcp.types import CallToolResult, TextContent, ToolAnnotations  # noqa: E402

from reporails_cli.formatters.mcp import bound_validate_payload, with_rule_labels  # noqa: E402
from reporails_cli.formatters.mcp_view import has_text_view, render_text_view, unseen_notices  # noqa: E402
from reporails_cli.interfaces.mcp import snapshots  # noqa: E402
from reporails_cli.interfaces.mcp.feedback import file_feedback  # noqa: E402
from reporails_cli.interfaces.mcp.idle_release import lifespan, touch_activity  # noqa: E402
from reporails_cli.interfaces.mcp.remedy_brief import build_remedy_brief  # noqa: E402
from reporails_cli.interfaces.mcp.remedy_brief_paging import page_reply  # noqa: E402
from reporails_cli.interfaces.mcp.rule_tools import explain_tool, preflight_tool  # noqa: E402
from reporails_cli.interfaces.mcp.scan_fingerprint import (  # noqa: E402
    combine_scan_inputs,
    compute_scan_fingerprint,
    dependency_files,
)
from reporails_cli.interfaces.mcp.tools import (  # noqa: E402
    _resolve_scan_target,
    is_retryable_reply,
    model_not_ready_error,
    run_pipeline_for_path,
    unpaid_signed_in_reply,
)
from reporails_cli.interfaces.mcp.validate_targets import (  # noqa: E402
    keep_target_locations,
    resolve_validate_targets,
)

# Circuit breaker: content-aware loop detection.
_MAX_CALLS = 10
_MAX_UNCHANGED = 2


@dataclass
class _CircuitState:
    call_count: int = 0
    last_mtime_hash: str = ""
    consecutive_unchanged: int = 0
    # The full (unbounded) payload from the last run against `last_mtime_hash`. A `full=true`
    # follow-up to a bounded call (the response's own hint tells the caller to make exactly
    # this call) is served from here instead of re-running the pipeline, and does not count
    # as an unchanged repeat — only a re-run after a content change counts.
    full_payload: dict[str, Any] | None = None
    # The last fresh reply came to a signed-in user on a non-paid tier: it is never reused, since
    # the user may have upgraded since (the sign-in on disk still names the old tier).
    unpaid_reply: bool = False
    # The scan root the last validate resolved `path` against — what `remedy_brief` resolves
    # a location's (project-relative / `~/…`) file paths back to absolute against.
    scan_root: Path | None = None
    # The ruleset map + file score from the last fresh pipeline run against `last_mtime_hash` —
    # a cached (unchanged-content) reply's preservation check reuses these instead of
    # re-running the pipeline a second time just to get them again.
    last_ruleset_map: Any = None
    last_score: float | None = None
    # The unpaged `remedy_brief` build for this path's workflow, keyed by a location's `order`
    # — built once (`build_remedy_brief`) the first time a location is requested, then served
    # to every later `part` request for that same location with no pipeline re-run and no
    # snapshot re-commit. A new `validate` for this path clears the whole cache (below), since
    # it may have changed the file set the workflow's locations name.
    remedy_brief_cache: dict[int, Any] = field(default_factory=dict)
    # The notices a text view already showed for this path: each shows once per run.
    shown_notices: set[str] = field(default_factory=set)


_validate_states: dict[str, _CircuitState] = {}
# Held while a location's brief is built, so two requests for one location build it once.
_brief_build_lock = threading.Lock()


def _target_tokens(targets: list[str] | None) -> tuple[str, ...]:
    """The distinct non-empty target tokens, sorted — one spelling per set of targets."""
    return tuple(sorted({t.strip() for t in targets or () if t and t.strip()}))


def _state_key(path: str, tokens: tuple[str, ...]) -> str:
    """The circuit-breaker / workflow key: the resolved path, plus the targets when any — a
    targeted `validate` and a whole-project one keep separate counters and workflows."""
    key = str(Path(path).resolve())
    return f"{key}|targets={','.join(tokens)}" if tokens else key


# ─────────────────────────────────────────────────────────────────────
# Tool bodies — return plain dicts (validate/preflight) or text (explain).
# ─────────────────────────────────────────────────────────────────────


def _serve_remedy_brief(
    path: str, location: int, targets: list[str] | None = None, part: int = 1, has_guide: bool = False
) -> dict[str, Any]:
    """`remedy_brief(path, location, targets, part, has_guide)`'s body: a caller that does not
    carry the rewrite guide (`has_guide` false) is refused with `plugin_update_required` before
    anything else — no state read, no build, no snapshot, no breaker counter touched. Reads the last `validate(path,
    targets)`'s stored workflow and scan root, and builds the location's rewrite brief.
    `part` (1-based) selects one numbered part of a brief too large for one reply; a brief
    that fits in one part ignores it. Never runs `validate`'s own pipeline for `path`. A
    served brief (no error) resets the path's `call_count` — the agent is still working this
    rewrite loop, not re-validating without progress — so a multi-round pass survives
    past `_MAX_CALLS`; `consecutive_unchanged` (the actual no-progress guard) is untouched.

    A location's brief is built (`build_remedy_brief` — the file pipeline plus the snapshot
    commit) at most once per `validate`: the first `part` request for a location builds it and
    caches it on `state.remedy_brief_cache`; every later `part` request for that SAME location,
    however many, is served straight from the cached build (`page_reply` alone) — no pipeline
    re-run, no server call, no snapshot re-commit. A new `validate` for this path clears the
    cache (`_run_validate`), so requesting part 1 again after it rebuilds.

    An unpaid or offline caller's `validate` never carries a `workflow` key at all (a
    DIFFERENT cause from never having called `validate`): `workflow_requires_pro` names that
    real cause, never "call validate first" — which would send the agent straight back into
    `validate`'s own circuit breaker, with no way to learn the brief is what it actually lacks.
    """
    if not has_guide:
        return {
            "error": "plugin_update_required",
            "message": (
                "The rewrite brief no longer carries the guide to writing an ideal instruction; "
                "your agent has to carry it. Update the reporails plugin to 0.6.2 or later, then run heal again."
            ),
        }
    state = _validate_states.get(_state_key(path, _target_tokens(targets)))
    if state is None or not state.full_payload:
        return {
            "error": "no_workflow",
            "message": "Call validate for this path (and these targets) first; remedy_brief reads its workflow.",
        }
    if "workflow" not in state.full_payload:
        return {
            "error": "workflow_requires_pro",
            "message": (
                "The rewrite brief is a Pro feature. This path's last validate carried no rewrite "
                "workflow to brief from — calling validate again will not produce one."
            ),
        }
    workflow = state.full_payload.get("workflow")
    if not isinstance(workflow, dict):
        return {
            "error": "no_workflow",
            "message": "Call validate for this path (and these targets) first; remedy_brief reads its workflow.",
        }
    locations = workflow.get("locations") or []
    loc = next((entry for entry in locations if isinstance(entry, dict) and entry.get("order") == location), None)
    if loc is None:
        return {
            "error": "location_not_found",
            "message": f"The workflow has no location {location}; it has {len(locations)}.",
        }
    scan_root = state.scan_root or Path(path).resolve()
    with _brief_build_lock:
        built = state.remedy_brief_cache.get(location)
        if built is None:
            built = build_remedy_brief(loc, scan_root)
            if isinstance(built, dict):
                return built
            state.remedy_brief_cache[location] = built
    full, files_out, location_out = built
    reply = page_reply(full, files_out, location_out, part)
    if "error" not in reply:
        state.call_count = 0
    return reply


def _with_feedback(payload: dict[str, Any], target: Path, scan_root: Path) -> dict[str, Any]:
    """Add the `feedback` block to `payload` when `target` is a file `remedy_brief`
    snapshotted — same gate as `_with_preservation`, so the two blocks always ride together on
    a snapshotted file's reply."""
    if "error" in payload or "needs_install" in payload:
        return payload
    if not target.is_file() or not snapshots.has_snapshot(target):
        return payload
    return {**payload, "feedback": file_feedback(payload, target, scan_root)}


def _with_preservation(
    payload: dict[str, Any], target: Path, ruleset_map: Any, score: float | None, scan_root: Path | None
) -> dict[str, Any]:
    """Add the `preservation` block to `payload` when `target` is a file `remedy_brief`
    snapshotted. Carried on both the bounded and full replies — the caller bounds afterward.

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
    block = snapshots.check_rewrite(snap, target, ruleset_map, new_text, score, scan_root)
    block["introduced"] = snapshots.introduced_count(target, payload)
    return {**payload, "preservation": block}


async def _fresh_validate_payload(
    path: str, tokens: tuple[str, ...], scan_root: Path, state: _CircuitState
) -> dict[str, Any] | tuple[dict[str, Any], Any, float | None]:
    """Run the pipeline fresh (never served from `state.full_payload`) — resolve `tokens` to a
    location selection first when targeted, narrow the payload's `workflow.locations` to it
    (`keep_target_locations`), and memoize the map/score on `state` for the next same-content
    `validate` / preservation pass. Returns `(payload, ruleset_map, score)`; a target-resolution
    failure returns its own error payload instead (the caller returns it unchanged)."""
    selection: tuple[set[Path], set[Path]] | None = None
    if tokens:
        resolved = await asyncio.to_thread(resolve_validate_targets, tokens, scan_root)
        if isinstance(resolved, dict):
            return resolved
        selection = resolved
    # Blocking pipeline work (mapping, m-probes, server lint) runs off the event loop so a
    # slow map/lint never blocks other concurrent tool calls.
    payload, ruleset_map, score = await asyncio.to_thread(run_pipeline_for_path, path, True)
    if selection is not None and "files" in payload:
        payload = keep_target_locations(payload, *selection, scan_root, tokens)
    if "files" in payload:
        state.full_payload = payload
        state.unpaid_reply = unpaid_signed_in_reply(payload)
        state.scan_root = scan_root
        state.last_ruleset_map = ruleset_map
        state.last_score = score
    return payload, ruleset_map, score


async def _run_validate(path: str, full: bool, targets: list[str] | None = None) -> dict[str, Any]:
    """Compute the `validate` payload with the content-aware circuit breaker.

    With `targets`, the whole project is diagnosed as without them and the reply's
    `workflow.locations` keep only the locations holding a targeted file, re-numbered from 1
    (`keep_target_locations`); the counters and the stored workflow are kept per
    `(path, targets)`.

    Two layers of safety:
      1. Path-existence checks emit structured errors the slash command body can
         branch on (no bare strings).
      2. The circuit breaker (`_MAX_CALLS` total, `_MAX_UNCHANGED` consecutive
         no-op validates per path) catches a model that re-validates without
         applying fixes. The mtime-tracker resets on any file edit. A `full=true`
         call for unchanged content is served from the memoized full payload rather
         than counted as another unchanged repeat, since it is the bounded
         response's own suggested next call, not a sign of no progress.

    The circuit-breaker state read-modify-write runs inline on the event loop —
    no `await` between the `_validate_states` read and its write — so concurrent
    same-path calls serialize (a retryable reply edits that live state, never a copy); only the
    blocking pipeline (`run_pipeline_for_path`) is offloaded to a worker thread. The
    pipeline always runs `full=True` internally (the bounding step is the last
    thing it does) and the bounded view is derived here via `bound_validate_payload`,
    so a cached full payload serves either shape without a second pipeline run.
    Returns a structured-success dict for every expected condition (needs_install /
    path_not_found / circuit_breaker); an unexpected exception propagates for the
    SDK to surface as an execution error.
    """
    target = Path(path).resolve()

    # A model that is not ready yet is not a validate attempt: answer before the
    # circuit-breaker counters move, so retries during a first download never trip it.
    model_error = await asyncio.to_thread(model_not_ready_error)
    if model_error is not None:
        return model_error

    # The mtime hash walks the same scan root the pipeline itself discovers from — a FILE
    # target's root is its enclosing project (`_resolve_scan_target`), never the bare file
    # path, which discovery reads as an (empty) directory. Without this a
    # file-scoped validate's hash is always the empty string, `unchanged` is always False, and
    # a same-content repeat validate never hits the cached-reply path at all.
    scan_root = _resolve_scan_target(target)[0]

    tokens = _target_tokens(targets)
    path_key = _state_key(path, tokens)
    # The input walk is blocking file IO: run it off the event loop, before the state read, so
    # the read-modify-write below stays free of any `await`.
    prior = _validate_states.get(path_key)
    prior_map = prior.last_ruleset_map if prior is not None else None
    prior_reply = prior.full_payload if prior is not None else None
    base_hash, mtime_hash = await asyncio.to_thread(compute_scan_fingerprint, scan_root, prior_map, prior_reply, target)
    state = _validate_states.get(path_key, _CircuitState())
    # A new `validate` call for this path — whatever it decides below — invalidates any
    # `remedy_brief` build already cached for it: the workflow this validate stores (or the
    # tier-gated absence of one) may not be the one that cache was built from, and a changed
    # file set means the locations it named may no longer even resolve. `part=1` requested
    # after this rebuilds; parts of an untouched location build once again.
    state.remedy_brief_cache.clear()
    unchanged = bool(state.last_mtime_hash) and mtime_hash == state.last_mtime_hash
    if not unchanged:
        state.full_payload = None
        state.consecutive_unchanged = 0
    elif not full:
        state.consecutive_unchanged += 1
        if state.unpaid_reply:
            state.full_payload = None
    state.last_mtime_hash = mtime_hash
    state.call_count += 1
    _validate_states[path_key] = state

    if state.call_count > _MAX_CALLS or state.consecutive_unchanged >= _MAX_UNCHANGED:
        return {
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

    if not target.exists():
        return {"error": "path_not_found", "message": f"Path not found: {target}"}

    if unchanged and state.full_payload is not None:
        payload = state.full_payload
        # Reuse the map/score the last fresh run stored, instead of re-running the
        # pipeline a second time (with its own server diagnose) just for the preservation
        # check on a reply that is otherwise served entirely from cache.
        ruleset_map, score = state.last_ruleset_map, state.last_score
    else:
        result = await _fresh_validate_payload(path, tokens, scan_root, state)
        if isinstance(result, dict):
            return result
        payload, ruleset_map, score = result
        if is_retryable_reply(payload):
            state.full_payload, state.last_mtime_hash = None, ""
            state.consecutive_unchanged -= unchanged and not full
            return payload if full else bound_validate_payload(payload)
        # The run may have mapped other files than the last one did: store the fingerprint of
        # the list the next call will read, so the two compare like with like.
        state.last_mtime_hash = await asyncio.to_thread(
            lambda: combine_scan_inputs(
                base_hash, dependency_files(state.last_ruleset_map, target, scan_root, state.full_payload)
            )
        )

    # `_with_preservation` is CPU/IO work (a fenced-block scan over the file's text, a
    # possible read) — run it off the event loop too, so a preservation check never blocks a
    # concurrent tool call the way running it inline here used to.
    payload = await asyncio.to_thread(_with_preservation, payload, target, ruleset_map, score, scan_root)
    # `_with_feedback` reads only `payload` + `target` — no pipeline re-run, no IO — but stays
    # off the event loop too, so it never carries a stray blocking op later without review.
    payload = await asyncio.to_thread(_with_feedback, payload, target, scan_root)
    return with_rule_labels(payload) if full else bound_validate_payload(payload)


# ─────────────────────────────────────────────────────────────────────
# Server + tool registration (mcp 2.x high-level).
# ─────────────────────────────────────────────────────────────────────

# `MCPServer`'s own `version` defaults to `""` when not passed, so `initialize`'s
# `serverInfo.version` was always empty — a caller has no way to tell which server build it
# is talking to. `StrictArgsMCPServer` also closes a related gap: an unknown tool argument.
from reporails_cli import __version__ as _ails_version  # noqa: E402
from reporails_cli.interfaces.mcp.strict_tool_args import StrictArgsMCPServer  # noqa: E402

server = StrictArgsMCPServer("ails", version=_ails_version, lifespan=lifespan)

_READ_ONLY = ToolAnnotations(read_only_hint=True)


def _result(payload: dict[str, Any]) -> CallToolResult:
    """Wrap a payload as a compact structured result.

    Returns `structuredContent` (machine-readable, ending the consumer string-parse)
    plus a COMPACT text mirror for back-compat. Returning a pre-built result skips the
    SDK's pretty-printed auto-serialization, whose indented duplicate of the payload
    dominated the reply — the token
    economy the bounded envelope exists to protect.
    """
    return CallToolResult(
        content=[TextContent(type="text", text=json.dumps(payload, separators=(",", ":")))],
        structured_content=payload,
    )


def _text_result(text: str) -> CallToolResult:
    """A reply whose only channel is its text: a client that shows the structured block in place
    of the text (or drops a structured-only result) still shows the model this view."""
    return CallToolResult(content=[TextContent(type="text", text=text)])


@server.tool(
    name="validate",
    description=(
        "Validate AI instruction files at `path` (directory or single file)."
        " Returns JSON with findings, per-finding fix text, a `quality` score,"
        " tier, per-surface category breakdown, and cross-file analysis."
        " On a Pro account the default reply is a short text view instead: its lines name the"
        " reply's fields (`workflow.locations`, `workflow.listed`, `surface_health`, `notices`,"
        " `preservation`, `feedback`, ...) and `full=true` returns the JSON."
        " The default response is bounded (top findings per file plus whole"
        " `stats` / `surface_health`). On a paid tier the response carries a"
        " `workflow` — the ordered locations to rewrite, each without its findings — and"
        " the per-file finding lists are withheld (each file keeps its `count`)."
        " Call `remedy_brief(path, location)` for a location's rewrite brief, one kind at a time,"
        " or `full=true` for every finding. `targets` narrows the locations, the per-file"
        " findings, and the cross-file entries and pair counts to those holding the named"
        " files, read the way `ails check` reads its targets — `skills`, `skills:<name>`,"
        " `agents:<name>`, `@main`,"
        " a path (the whole project is still diagnosed and its score and stats stay"
        " whole-project; pass the same `targets` to `remedy_brief`); a targeted view carries its"
        " locations' findings and relations in this reply when they fit, and otherwise"
        " `truncated.hint` names `remedy_brief`, which serves them. After"
        " rewriting a briefed location's files, call"
        " validate again with `path` set to each rewritten file: the reply then carries a"
        " `preservation` block saying whether the rewrite kept everything the file had and how many findings it"
        " `introduced`, and a"
        " `feedback` list of the file's remaining findings, with any problem the rewrite newly"
        " introduced listed first."
        " `notices`, when present, are messages for the user about their account (for example a"
        " failed payment): show each one to the user."
        " Use when user asks to check, validate, or improve instruction files."
    ),
    annotations=_READ_ONLY,
)
async def validate(path: str = ".", full: bool = False, targets: list[str] | None = None) -> CallToolResult:
    """Validate instruction files; see the tool description for the response shape."""
    touch_activity()
    payload = await _run_validate(path, bool(full), targets)
    if not has_text_view(payload, full=bool(full)):
        return _result(payload)
    state = _validate_states.setdefault(_state_key(path, _target_tokens(targets)), _CircuitState())
    return _text_result(render_text_view(unseen_notices(payload, state.shown_notices)))


@server.tool(
    name="remedy_brief",
    description=(
        "Get the full rewrite brief for one location of the last `validate(path)`'s paid"
        " `workflow` — `path` is the path last passed to `validate`, `location` is a"
        " location's `order` from that reply, `targets` the targets that `validate` call"
        " passed (none for a whole-project reply). Returns each of the location's files with its"
        " current score, every instruction and heading in it, the location's findings and"
        " relations (with remedy text), the"
        " rules that govern this kind of file, and the preservation contract the rewrite must"
        " keep. A brief too large for one reply carries `part` / `total_parts` and a `next_part`"
        " note — call again with the same path, location and targets, and that `part` number,"
        " for the rest; every part's `files[]`, `findings`, `relations` and `procedure.mechanical_fixes`"
        " together carry the whole brief, and each part is at most about 16,000 characters unless"
        " one item (a single instruction or fixed field) is larger on its own. Call this before"
        " rewriting a location, one location at a time, one kind at a time. Set `has_guide` true"
        " when your agent carries the rewrite guide (the reporails plugin 0.6.2 and later does);"
        " without it the call returns `plugin_update_required` and no brief."
    ),
    annotations=_READ_ONLY,
)
async def remedy_brief(
    path: str, location: int, targets: list[str] | None = None, part: int = 1, has_guide: bool = False
) -> CallToolResult:
    """Return the rewrite brief for one workflow location; see the tool description."""
    touch_activity()
    return _result(
        await asyncio.to_thread(_serve_remedy_brief, path, int(location), targets, int(part), bool(has_guide))
    )


@server.tool(
    name="preflight",
    description=(
        "Return the workflow-ordered rules that govern authoring a file of the given"
        " `capability` — its file type as the agent config names it (`main`, `rules`,"
        " `skills`, `agents`, …; `skill`, `agent` and `rule` are read the same). Use BEFORE drafting"
        " a new SKILL.md / agent / rule so the draft follows the rules from the"
        " start instead of patching findings after `validate`."
        " Returns JSON with rules sorted by category in workflow order plus"
        " Pass / Fail examples."
    ),
    annotations=_READ_ONLY,
)
async def preflight(capability: str, agent: str = "") -> CallToolResult:
    """Return workflow-ordered rules for authoring a file of `capability`."""
    touch_activity()
    return _result(preflight_tool(capability, agent))


@server.tool(
    name="explain",
    description=(
        "Get details about a specific rule by ID."
        " Returns rule title, category, type, description, checks."
        " Use full coordinate IDs (e.g., CORE:S:0005, CLAUDE:S:0005)."
    ),
    annotations=_READ_ONLY,
    structured_output=False,
)
async def explain(rule_id: str) -> str:
    """Explain one rule as readable text (a JSON error string for an unknown rule).

    Text-only by design: `explain` is human-readable, so it carries no structured
    output mirror. The unknown-rule error is serialized to a JSON string so a
    caller still reads one shape.
    """
    touch_activity()
    result = explain_tool(rule_id)
    return result if isinstance(result, str) else json.dumps(result)


# ─────────────────────────────────────────────────────────────────────
# Back-compat module shims — the callable surface tests + callers share.
# ─────────────────────────────────────────────────────────────────────


async def list_tools() -> list[Any]:
    """List the registered tools (`validate`, `preflight`, `explain`)."""
    return await server.list_tools()


async def call_tool(name: str, arguments: dict[str, Any]) -> list[Any]:
    """Invoke a tool and return its content blocks (the text/structured result).

    An unknown tool name is a protocol error the high-level server raises; the shim
    maps it to a structured error block so an internal caller reads one shape. An unknown
    argument name is rejected the same way (`StrictArgsMCPServer.call_tool`), before the
    tool body ever runs.
    """
    import json

    from mcp.server.mcpserver.exceptions import ToolError

    try:
        result = await server.call_tool(name, arguments or {})
    except ToolError as exc:
        return [TextContent(type="text", text=json.dumps({"error": str(exc)}))]
    if not isinstance(result, CallToolResult):
        # Our read-only tools never request elicitation input (InputRequiredResult).
        return [TextContent(type="text", text=json.dumps({"error": "unexpected input-required result"}))]
    content = list(result.content)
    if not content:
        # A structured-only result: surface its JSON as a text block so callers
        # that read `content[0].text` still see the payload.
        content = [TextContent(type="text", text=json.dumps(result.structured_content or {}))]
    return content


def _prewarm_models() -> None:
    """Fetch the model set in the background so the first `validate` rarely waits on it."""
    import contextlib

    from reporails_cli.bundled import ensure_models_available
    from reporails_cli.core.mapper.model_fetch import ModelFetchError

    # On failure `validate` retries and reports the error to the caller.
    with contextlib.suppress(ModelFetchError):
        ensure_models_available()


def main() -> None:
    """Entry point for the MCP server (stdio transport)."""
    import threading

    threading.Thread(target=_prewarm_models, name="model-prewarm", daemon=True).start()
    server.run("stdio")


if __name__ == "__main__":
    main()
