"""The ``ails check`` command flow as phases over a shared ``CheckState``.

``check()`` in ``main.py`` builds a ``CheckState`` from the CLI options and runs
``run_check_flow`` over it. Each phase mutates the state in place (assigning
``state.<group>.x`` rather than returning tuples), so the pipeline's
intermediate values live on one object instead of exploding the command's
local-variable count. The state is grouped into per-phase sub-objects
(``inputs`` / ``targets`` / ``scope`` / ``pipeline`` / ``render``) so no single
container carries every field, and phases assign through the sub-object directly
rather than aliasing it into a local. Leaf helpers (dispatch, heal,
capability-path resolution) stay in ``check_orchestration.py`` /
``check_support.py`` / ``check_notices.py``.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from contextlib import nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.mapper.skills import skill_membership
from reporails_cli.core.pipeline.mapping import discover_scope
from reporails_cli.interfaces.cli.check_notices import (
    _agent_is_pinned,
    _emit_empty_run,
    _emit_heal_auth_required,
    _emit_heal_scope_refusal,
    _notify_heal_scope_skips,
)
from reporails_cli.interfaces.cli.check_orchestration import (
    _dispatch_output,
    _emit_stage_timing,
    _file_under_target,
    _narrow_to_path_targets,
    _quiet_mapper_logs,
    _resolve_capability_paths,
    _resolved_within_target,
    _run_heal_pass,
    _scan_root,
    _should_exit_strict,
    _token_agent,
    logger,
)
from reporails_cli.interfaces.cli.check_support import (
    _ensure_model_or_exit,
    _generic_scan_file_types,
    _heal_authed,
)
from reporails_cli.interfaces.cli.helpers import (
    _default_format,
    _show_agent_auto_detect_hint,
    _validate_agent,
    _warn_unresolved_skills,
    console,
)


@dataclass
class CheckInputs:
    """CLI options as passed to ``ails check`` — filled by the builder in ``main.py``."""

    targets: list[str] | None
    format_opt: str
    agent: str
    exclude_dirs: list[str] | None
    exclude_files: list[str] | None
    ascii_mode: bool
    strict: bool
    verbose: bool
    heal: bool
    dry_run: bool
    cwd: bool
    project_root: Path


@dataclass
class CheckTargets:
    """Resolved target scope — capability specs, path targets, scan root, output format."""

    capability_specs: list[tuple[str, str]] = field(default_factory=list)
    path_targets: set[Path] = field(default_factory=set)
    single_path: Path | None = None
    single_file: Path | None = None
    # A lone directory target that lives INSIDE the project and is NOT a project root
    # of its own — the run stays anchored at the project root and is scoped to this
    # subtree. `None` for every other target shape. See `_scan_root`.
    subtree: Path | None = None
    # Mirrors `subtree is not None` — the run is scope-to-subtree rather than
    # anchored at the target.
    subtree_scoped: bool = False
    target: Path = field(default_factory=Path)
    output_format: str = ""


@dataclass
class CheckScope:
    """Agent detection, instruction-file discovery, and scope narrowing."""

    detected: list[Any] = field(default_factory=list)
    effective_agent: str = ""
    assumed: bool = False
    mixed: bool = False
    filtered: list[Any] = field(default_factory=list)
    excl: Any = ()
    excl_files: Any = ()
    instruction_files: list[Path] = field(default_factory=list)
    upfront_paths: set[Path] = field(default_factory=set)
    is_targeted: bool = False
    file_type_by_path: dict[str, str] = field(default_factory=dict)
    generic_scanning: bool = False


@dataclass
class CheckPipeline:
    """Pipeline outputs — mapping, probes, content/client checks, server lint."""

    stage_timer: Any = None
    start_time: float = 0.0
    ruleset_map: Any = None
    m_findings: list[Any] = field(default_factory=list)
    content_findings: list[Any] = field(default_factory=list)
    client_findings: list[Any] = field(default_factory=list)
    rule_agents: tuple[str, ...] = ()
    lint_result: Any = None
    funnel_error: Any = None
    notices: tuple[Any, ...] = ()


@dataclass
class CheckRender:
    """Assembled result and the display-path projection rendered to the user."""

    result: Any = None
    display_result: Any = None
    display_map: Any = None
    capability_paths: set[Path] = field(default_factory=set)
    elapsed_ms: float = 0.0
    heal_authed: bool = False


@dataclass
class CheckState:
    """Per-phase sub-objects threaded through the ``ails check`` flow."""

    inputs: CheckInputs
    targets: CheckTargets = field(default_factory=CheckTargets)
    scope: CheckScope = field(default_factory=CheckScope)
    pipeline: CheckPipeline = field(default_factory=CheckPipeline)
    render: CheckRender = field(default_factory=CheckRender)


def _flow_targets(state: CheckState) -> None:
    """Classify target tokens, pick the scan root + output format, enforce heal scope-safety."""
    if state.inputs.targets:
        from reporails_cli.core.classify.capability_paths import classify_target_token

        sniffed: dict[Path, str] = {}
        for token in state.inputs.targets:
            sniff_agent = _token_agent(token, state.inputs.agent, state.inputs.project_root, sniffed)
            kind, payload = classify_target_token(token, sniff_agent, state.inputs.project_root)
            if kind == "capability" and isinstance(payload, tuple):
                state.targets.capability_specs.append(payload)
            elif isinstance(payload, Path):
                if not payload.exists():
                    from reporails_cli.core.classify.capability_paths import canonicalize_capability

                    suggestion = ""
                    if (
                        sniff_agent
                        and canonicalize_capability(token, sniff_agent, state.inputs.project_root) is not None
                    ):
                        suggestion = (
                            f"\n[dim]'{token}' is a known capability — did you mean `ails check {token}`?[/dim]"
                        )
                    console.print(f"[red]Error:[/red] Path not found: {payload}{suggestion}")
                    raise typer.Exit(2)
                state.targets.path_targets.add(payload)

    state.targets.single_path = (
        next(iter(state.targets.path_targets))
        if (state.targets.path_targets and not state.targets.capability_specs and len(state.targets.path_targets) == 1)
        else None
    )
    state.targets.single_file = (
        state.targets.single_path
        if (state.targets.single_path is not None and state.targets.single_path.is_file())
        else None
    )
    state.targets.subtree, state.targets.target = _scan_root(
        state.targets.single_path, state.targets.single_file, state.inputs.project_root
    )
    state.targets.subtree_scoped = state.targets.subtree is not None
    if state.targets.subtree is not None and not state.targets.path_targets and not state.targets.capability_specs:
        # No target named, run from inside an agent configuration folder: the folder is the scope.
        state.targets.path_targets.add(state.targets.subtree)
    state.targets.output_format = state.inputs.format_opt or _default_format()

    root_targeted = any(t == state.inputs.project_root for t in state.targets.path_targets)
    no_narrowing = not state.targets.path_targets and not state.targets.capability_specs
    whole_project_heal = state.targets.target == state.inputs.project_root and (no_narrowing or root_targeted)
    if state.inputs.heal and not state.inputs.dry_run and not state.inputs.cwd and whole_project_heal:
        _emit_heal_scope_refusal(state.targets.output_format)
        raise typer.Exit(2)


def _resolve_scope_at_target(state: CheckState) -> None:
    """Detect agents at the current scan root and discover the scannable files under it.

    The scope includes each agent's config surfaces (hooks, permissions, MCP
    declarations, plugin manifests) alongside its instruction and rule files, so a
    plain whole-project run checks them the same way an explicit `ails check hooks`
    already does — a config file left out of the default scan never gets its rules
    run against it at all.
    """
    from reporails_cli.core.platform.config.config import get_project_config

    config = get_project_config(state.targets.target)
    state.scope.generic_scanning = bool(config.generic_scanning)
    agent_arg = state.inputs.agent or config.default_agent
    state.scope.excl = state.inputs.exclude_dirs if state.inputs.exclude_dirs is not None else config.exclude_dirs
    state.scope.excl_files = (
        state.inputs.exclude_files if state.inputs.exclude_files is not None else config.exclude_files
    )
    if agent_arg:
        _validate_agent(agent_arg, console)
    found = discover_scope(state.targets.target, agent_arg, state.scope.excl, state.scope.excl_files)
    state.scope.detected = found.detected
    state.scope.effective_agent, state.scope.assumed, state.scope.mixed = (
        found.effective_agent,
        found.assumed,
        found.mixed,
    )
    state.scope.filtered = found.filtered
    state.scope.instruction_files = found.files
    if state.targets.single_file is not None:
        state.scope.instruction_files = [safe_resolve(state.targets.single_file)]
    elif state.targets.target != state.inputs.project_root:
        state.scope.instruction_files = [
            f for f in state.scope.instruction_files if _file_under_target(f, state.targets.target)
        ]


def _flow_scope(state: CheckState) -> bool:
    """Detect agents, discover instruction files, narrow to scope. False = nothing in scope."""
    _resolve_scope_at_target(state)
    if not state.scope.instruction_files:
        _emit_empty_run(state)
        return False

    # A scope-to-subtree run keeps the project scan root, so its narrowing runs here
    # with the capability/multi-path narrowing rather than through the re-root branch.
    if (state.targets.single_path is None or state.targets.subtree_scoped) and not _narrow_upfront(state):
        return False

    return _apply_generic_scan(state)


def _narrow_upfront(state: CheckState) -> bool:
    """Build the capability/path upfront filter and narrow instruction_files. False = no matches."""
    cap_paths: set[Path] = set()
    if state.targets.capability_specs and state.scope.mixed and not state.inputs.agent:
        names = sorted({d.agent_type.id for d in state.scope.filtered})
        console.print(
            f"[red]Error:[/red] multiple agents detected ({', '.join(names)}); a capability "
            f"target needs one agent. Re-run with [bold]--agent <name>[/bold] "
            f"(e.g. `ails check {state.targets.capability_specs[0][0]} --agent {names[0]}`)."
        )
        raise typer.Exit(2)
    if state.targets.capability_specs:
        cap_paths, unresolved_skills = _resolve_capability_paths(
            state.targets.capability_specs, state.scope.effective_agent, state.inputs.project_root, state.scope.excl
        )
        state.scope.upfront_paths |= cap_paths
        _warn_unresolved_skills(unresolved_skills, state.inputs.project_root)
    if state.targets.path_targets:
        state.scope.upfront_paths |= set(
            _narrow_to_path_targets(state.scope.instruction_files, state.targets.path_targets)
        )
    if (state.targets.capability_specs or state.targets.path_targets) and not state.scope.upfront_paths:
        _emit_empty_run(state)
        return False
    if state.scope.upfront_paths:
        state.scope.instruction_files = [f for f in state.scope.instruction_files if f in state.scope.upfront_paths]
        # Capability targets are authoritative — keep resolved targets broad discovery dropped.
        discovered = {safe_resolve(f) for f in state.scope.instruction_files}
        state.scope.instruction_files += [p for p in cap_paths if safe_resolve(p) not in discovered]
        if not state.scope.instruction_files:
            _emit_empty_run(state)
            return False
    return True


def _apply_generic_scan(state: CheckState) -> bool:
    """Fold @-import-reached files into the scored set and compute is_targeted. Always True."""
    import_extra, state.scope.file_type_by_path = _generic_scan_file_types(
        state.targets.target, state.scope.instruction_files, state.scope.effective_agent, state.scope.generic_scanning
    )
    if import_extra and state.scope.excl_files:
        from reporails_cli.core.platform.utils.utils import matches_any_glob

        import_extra = [
            f for f in import_extra if not matches_any_glob(f, state.scope.excl_files, state.targets.target)
        ]
    if import_extra:
        state.scope.instruction_files = list(state.scope.instruction_files) + import_extra
    state.scope.is_targeted = (
        state.targets.target != state.inputs.project_root
        or bool(state.scope.upfront_paths)
        or state.targets.single_file is not None
    )
    return True


def _agent_file_pairs(state: CheckState) -> list[tuple[str, list[Path]]]:
    """The ``(agent_id, its own scoped files)`` pairs M-probes / content checks run over --
    the CLI's thin wrapper over the shared ``core.pipeline.mapping.agent_file_pairs`` MCP
    ``validate`` also calls, so both surfaces score identical ``(rule, file, line)`` triples
    for the same tree."""
    from reporails_cli.core.pipeline.mapping import agent_file_pairs

    explicit = _agent_is_pinned(state)
    return agent_file_pairs(
        state.scope.instruction_files,
        state.scope.filtered,
        state.targets.target,
        explicit=explicit,
        effective_agent=state.scope.effective_agent,
    )


def _flow_pipeline(state: CheckState) -> None:
    """Map instruction files, run M-probes + content/client checks, then the server lint."""
    from reporails_cli.core.lint.rule_runner import run_m_probes_over_pairs
    from reporails_cli.core.platform.observability.stage_timer import get_stage_timer

    _quiet_mapper_logs()
    state.pipeline.start_time = time.perf_counter()
    import os

    state.pipeline.stage_timer = get_stage_timer()
    state.pipeline.stage_timer.configure(enabled=bool(os.environ.get("AILS_STAGE_TIMING")))

    show_progress = sys.stdout.isatty() and state.targets.output_format not in ("json", "github")
    progress: Callable[[str], None] = (
        (lambda msg: print(msg, file=sys.stderr, flush=True))
        if state.inputs.verbose and not show_progress
        else (lambda _: None)
    )
    spinner = console.status("[bold]Starting...[/bold]") if show_progress else nullcontext()

    with spinner:
        from reporails_cli.core.pipeline.mapping import map_instruction_files

        def map_progress(msg: str) -> None:
            if show_progress:
                spinner.update(f"[bold]{msg}[/bold]")  # type: ignore[union-attr]
            progress(msg)

        try:
            if show_progress:
                spinner.update("[bold]Mapping...[/bold]")  # type: ignore[union-attr]
            progress("Mapping instruction files...")
            state.pipeline.ruleset_map = map_instruction_files(
                state.targets.target,
                state.scope.instruction_files,
                progress=map_progress,
                filtered_agents=state.scope.filtered,
            )
        except (ImportError, RuntimeError) as exc:
            logger.warning("Mapper unavailable: %s. Content checks skipped.", exc)
            if state.inputs.verbose:
                console.print(f"[dim]Mapper unavailable: {exc}. Content checks skipped.[/dim]")
        state.pipeline.stage_timer.mark("map")

        if show_progress:
            spinner.update("[bold]Checking rules...[/bold]")  # type: ignore[union-attr]
        progress("Checking rules...")
        pairs = _agent_file_pairs(state)
        state.pipeline.rule_agents = tuple(dict.fromkeys(agent_id for agent_id, _ in pairs))
        skills = skill_membership(state.pipeline.ruleset_map)
        state.pipeline.m_findings = run_m_probes_over_pairs(
            state.targets.target, pairs, scoped=state.scope.is_targeted, skills=skills
        )
        state.pipeline.stage_timer.mark("m_probe")

        if state.pipeline.ruleset_map is not None:
            if show_progress:
                spinner.update("[bold]Running content checks...[/bold]")  # type: ignore[union-attr]
            progress("Running content checks...")
            _run_content_checks(state)
        state.pipeline.stage_timer.mark("content")

        _flow_server_lint(state, show_progress, spinner)


def _run_content_checks(state: CheckState) -> None:
    """Run the content-quality + client checks over the built ruleset map.

    Content-quality checks run once per agent in ``_agent_file_pairs`` (a single pass for
    a resolved agent, one pass per file each distinctive agent owns when ``mixed`` — a
    union run), against the SAME whole-project ``ruleset_map`` each time so cross-file
    checks still see every atom; only which file's rules get matched narrows per pass.
    Client checks are agent-agnostic and run once over the whole map.
    """
    from reporails_cli.core.lint.client_checks import run_client_checks
    from reporails_cli.core.lint.rule_runner import run_content_quality_checks

    state.pipeline.content_findings = [
        finding
        for agent_id, files in _agent_file_pairs(state)
        for finding in run_content_quality_checks(
            state.pipeline.ruleset_map, state.targets.target, files, agent=agent_id
        )
    ]
    state.pipeline.client_findings = run_client_checks(state.pipeline.ruleset_map)


def _flow_server_lint(state: CheckState, show_progress: bool, spinner: Any) -> None:
    """Send local findings to the server and unpack the lint response onto the pipeline state."""
    from reporails_cli.core.pipeline.assemble import lint_request_local
    from reporails_cli.core.platform.adapters.api_client import AilsClient

    if show_progress:
        spinner.update("[bold]Diagnosing...[/bold]")
    response = None
    if state.pipeline.ruleset_map is not None:
        local, structural_required = lint_request_local(_assemble_inputs(state))
        response = AilsClient().lint(state.pipeline.ruleset_map, local, structural_required, root=state.targets.target)
    state.pipeline.lint_result = response.result if response else None
    state.pipeline.funnel_error = response.funnel_error if response else None
    state.pipeline.notices = response.notices if response else ()
    state.pipeline.stage_timer.mark("server")


def _assemble_inputs(state: CheckState, lint_result: Any = None) -> Any:
    """The shared assemble spine's inputs from the check state (`lint_result` None before the lint)."""
    from reporails_cli.core.pipeline.assemble import AssembleInputs
    from reporails_cli.formatters.text.display_constants import rule_aliases

    return AssembleInputs(
        m_findings=state.pipeline.m_findings,
        content_findings=state.pipeline.content_findings,
        client_findings=state.pipeline.client_findings,
        ruleset_map=state.pipeline.ruleset_map,
        scan_root=state.targets.target,
        filter_agents=state.scope.filtered,
        effective_agent=state.scope.effective_agent,
        lint_result=lint_result,
        alias_fn=rule_aliases,
        rule_agents=state.pipeline.rule_agents,
        notices=state.pipeline.notices,
    )


def _flow_assemble(state: CheckState) -> None:
    """Memory validation, capability level, merge, suppression, and display-path filtering.

    The memory / level / merge / suppress / surface-mutation / credential-duplicate tail is the surface-agnostic
    assemble spine shared with the MCP `validate` tool (`core/pipeline/assemble.py`); the
    display-path filtering below stays CLI-only.
    """
    from reporails_cli.core.pipeline.assemble import assemble_result
    from reporails_cli.formatters.text.display import filter_result_to_paths, filter_ruleset_map_to_paths

    state.render.result = assemble_result(_assemble_inputs(state, state.pipeline.lint_result))
    # `assemble_result` unpacks the lint result (report/hints/cross_file_coordinates/tier)
    # and attaches the composable remediation `workflow` itself; the path filter below
    # preserves it via `dataclasses.replace`.
    state.render.elapsed_ms = (time.perf_counter() - state.pipeline.start_time) * 1000

    state.render.capability_paths = state.scope.upfront_paths
    if state.targets.single_file is not None:
        state.render.capability_paths = {safe_resolve(state.targets.single_file)}
    if state.render.capability_paths:
        state.render.display_result = filter_result_to_paths(
            state.render.result, state.render.capability_paths, state.targets.target
        )
        state.render.display_map = filter_ruleset_map_to_paths(
            state.pipeline.ruleset_map, state.render.capability_paths, state.targets.target
        )
    else:
        state.render.display_result = state.render.result
        state.render.display_map = state.pipeline.ruleset_map


def _flow_render(state: CheckState) -> None:
    """Dispatch the diagnosis output (unless an authed JSON heal replaces it) + timing + hint."""
    if state.inputs.heal:
        state.render.heal_authed = _heal_authed(state.pipeline.funnel_error)

    if not (state.render.heal_authed and state.targets.output_format == "json"):
        _dispatch_output(
            state.targets.output_format,
            state.render.display_result,
            state.render.display_map,
            state.render.elapsed_ms,
            state.render.capability_paths,
            state.targets.target,
            state.inputs.ascii_mode,
            state.inputs.verbose,
            state.pipeline.funnel_error,
            state.scope.file_type_by_path,
        )
    state.pipeline.stage_timer.mark("render")
    _emit_stage_timing(state.pipeline.stage_timer, state.targets.output_format)
    _show_agent_auto_detect_hint(
        state.scope.effective_agent,
        state.targets.output_format,
        state.scope.assumed,
        state.scope.mixed,
        state.scope.detected,
    )


def _flow_heal(state: CheckState) -> None:
    """Apply (or gate) the heal pass after the diagnosis is rendered."""
    if not state.inputs.heal:
        return
    if not state.render.heal_authed:
        if getattr(state.pipeline.funnel_error, "still_reaching", False):
            return
        _emit_heal_auth_required(state.targets.output_format)
        return
    heal_scope = state.targets.single_path if state.targets.single_path is not None else state.targets.target
    candidate = (
        [f for f in state.scope.instruction_files if f in state.render.capability_paths]
        if state.render.capability_paths
        else state.scope.instruction_files
    )
    heal_files = [f for f in candidate if _resolved_within_target(f, heal_scope)]
    _notify_heal_scope_skips(len(candidate) - len(heal_files), state.targets.output_format)
    _run_heal_pass(
        state.targets.target,
        heal_files,
        state.pipeline.ruleset_map,
        state.scope.effective_agent,
        state.inputs.dry_run,
        state.targets.output_format,
    )


def run_check_flow(state: CheckState) -> None:
    """Run the ``ails check`` phases over `state`, raising ``typer.Exit`` on scoped-exit paths."""
    _flow_targets(state)
    if not _flow_scope(state):
        return
    # Fetch the model only once there are files to map: a mistyped path or an empty
    # scope exits above without downloading it.
    _ensure_model_or_exit()
    _flow_pipeline(state)
    _flow_assemble(state)
    _flow_render(state)
    _flow_heal(state)
    if _should_exit_strict(
        state.inputs.strict,
        state.render.capability_paths,
        state.targets.target,
        state.render.result,
        state.pipeline.funnel_error,
    ):
        raise typer.Exit(1)
