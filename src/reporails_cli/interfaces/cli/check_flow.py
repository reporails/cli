"""The ``ails check`` command flow as phases over a shared ``CheckState``.

``check()`` in ``check_command.py`` builds a ``CheckState`` from the CLI options and runs
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

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer

from reporails_cli.core.classify.capability_paths import canonicalize_capability, classify_target_token
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.pipeline.mapping import (
    apply_generic_scan,
    discover_scope,
)
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.interfaces.cli.check_notices import (
    _emit_empty_run,
    _emit_heal_scope_refusal,
    _emit_heal_withheld,
    _notify_heal_scope_skips,
)
from reporails_cli.interfaces.cli.check_orchestration import (
    HealScope,
    RenderContext,
    _dispatch_output,
    _emit_stage_timing,
    _file_under_target,
    _named_paths,
    _narrow_to_path_targets,
    _quiet_mapper_logs,
    _resolve_capability_paths,
    _resolved_within_target,
    _run_heal_pass,
    _scan_root,
    _should_exit_strict,
    _token_agent,
)
from reporails_cli.interfaces.cli.check_pipeline import _flow_assemble, _flow_pipeline
from reporails_cli.interfaces.cli.check_support import (
    _ensure_model_or_exit,
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
    """CLI options as passed to ``ails check`` — filled by the builder in ``check_command.py``."""

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
    exclusions: Any = None
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
    not_evaluated: tuple[tuple[str, str], ...] = ()
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
    # The `(folders, file globs)` the run left out because the user set them, recorded where scope resolves.
    excluded: tuple[tuple[str, ...], tuple[str, ...]] = ((), ())
    elapsed_ms: float = 0.0
    heal_authed: bool = False
    # Announcements are left out of this run's notices (`--no-promo`).
    no_promo: bool = False


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
        sniffed: dict[Path, str] = {}
        for token in state.inputs.targets:
            sniff_agent = _token_agent(token, state.inputs.agent, state.inputs.project_root, sniffed)
            kind, payload = classify_target_token(token, sniff_agent, state.inputs.project_root)
            if kind == "capability" and isinstance(payload, tuple):
                state.targets.capability_specs.append(payload)
            elif isinstance(payload, Path):
                if not payload.exists():
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


def _resolve_scope_at_target(state: CheckState, capability_paths: frozenset[Path] = frozenset()) -> None:
    """Detect agents at the current scan root and discover the scannable files under it.

    The scope includes each agent's config surfaces (hooks, permissions, MCP
    declarations, plugin manifests) alongside its instruction and rule files, so a
    plain whole-project run checks them the same way an explicit `ails check hooks`
    already does — a config file left out of the default scan never gets its rules
    run against it at all.
    """

    config = get_project_config(state.targets.target)
    state.scope.generic_scanning = bool(config.generic_scanning)
    agent_arg = state.inputs.agent or config.default_agent
    if agent_arg:
        _validate_agent(agent_arg, console)
    # A single file is checked whatever is excluded, so its pass lists nothing and records nothing.
    flags, named = (state.inputs.exclude_dirs, state.inputs.exclude_files), _named_paths(state, capability_paths)
    scan = not state.targets.single_file
    found = discover_scope(state.targets.target, agent_arg, *flags, scan_files=scan, named=named, narrowed=bool(named))
    state.render.excluded, state.scope.exclusions = found.excluded, found.exclusions
    state.scope.detected, state.scope.filtered = found.detected, found.filtered
    state.scope.effective_agent, state.scope.assumed, state.scope.mixed = (
        found.effective_agent,
        found.assumed,
        found.mixed,
    )
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
    # A scope-to-subtree run keeps the project scan root, so its narrowing runs here
    # with the capability/multi-path narrowing rather than through the re-root branch.
    narrows = state.targets.single_path is None or state.targets.subtree_scoped
    named_targets = bool(state.targets.capability_specs or state.targets.path_targets)
    if not state.scope.instruction_files and not (narrows and named_targets):
        _emit_empty_run(state)
        return False
    if narrows and not _narrow_upfront(state):
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
            state.targets.capability_specs,
            state.scope.effective_agent,
            state.inputs.project_root,
            state.scope.exclusions,
        )
        state.scope.upfront_paths |= cap_paths
        _warn_unresolved_skills(unresolved_skills, state.inputs.project_root)
    if cap_paths:
        _resolve_scope_at_target(state, frozenset(cap_paths))
    if state.targets.path_targets:
        state.scope.upfront_paths |= set(
            _narrow_to_path_targets(state.scope.instruction_files, state.targets.path_targets)
        )
    if (state.targets.capability_specs or state.targets.path_targets) and not state.scope.upfront_paths:
        _emit_empty_run(state)
        return False
    if state.scope.upfront_paths:
        state.scope.instruction_files = [f for f in state.scope.instruction_files if f in state.scope.upfront_paths]
        # A capability target is checked even when no agent's file list holds it (a referenced file).
        discovered = {safe_resolve(f) for f in state.scope.instruction_files}
        state.scope.instruction_files += [p for p in cap_paths if safe_resolve(p) not in discovered]
        if not state.scope.instruction_files:
            _emit_empty_run(state)
            return False
    return True


def _apply_generic_scan(state: CheckState) -> bool:
    """Fold @-import-reached files into the scored set and compute is_targeted. Always True."""
    import_extra, state.scope.file_type_by_path = apply_generic_scan(
        state.targets.target,
        state.scope.instruction_files,
        state.scope.effective_agent,
        state.scope.generic_scanning,
        state.scope.exclusions,
    )
    if import_extra:
        state.scope.instruction_files = list(state.scope.instruction_files) + import_extra
    state.scope.is_targeted = (
        state.targets.target != state.inputs.project_root
        or bool(state.scope.upfront_paths)
        or state.targets.single_file is not None
    )
    return True


def _flow_render(state: CheckState) -> None:
    """Dispatch the diagnosis output (unless an authed JSON heal replaces it) + timing + hint."""
    if state.inputs.heal:
        state.render.heal_authed = _heal_authed(state.pipeline.funnel_error) and _heal_workflow(state) is not None

    if not (state.render.heal_authed and state.targets.output_format == "json"):
        _dispatch_output(
            state.targets.output_format,
            state.render.display_result,
            state.render.display_map,
            state.render.elapsed_ms,
            funnel_error=state.pipeline.funnel_error,
            context=RenderContext(
                project_root=state.targets.target,
                capability_paths=state.render.capability_paths,
                file_type_by_path=state.scope.file_type_by_path,
                ascii_mode=state.inputs.ascii_mode,
                verbose=state.inputs.verbose,
            ),
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


def _heal_workflow(state: CheckState) -> Any:
    """The remediation workflow the report was drawn from (after suppressions); None when the reply carries none."""
    return state.render.result.reply.workflow


def _flow_heal(state: CheckState) -> None:
    """Apply (or gate) the heal pass after the diagnosis is rendered."""
    if not state.inputs.heal:
        return
    if not state.render.heal_authed:
        if getattr(state.pipeline.funnel_error, "still_reaching", False):
            return
        _emit_heal_withheld(
            state.targets.output_format,
            funnel_error=state.pipeline.funnel_error,
            tier=getattr(state.render.result.reply, "tier", None),
            server_replied=state.pipeline.lint_result is not None,
        )
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
        HealScope(heal_files, state.scope.effective_agent, state.scope.exclusions),
        state.pipeline.ruleset_map,
        state.inputs.dry_run,
        state.targets.output_format,
        notices=state.render.result.reply.notices,
        workflow=_heal_workflow(state),
    )


def run_check_flow(state: CheckState) -> None:
    """Run the ``ails check`` phases over `state`, raising ``typer.Exit`` on scoped-exit paths."""
    _flow_targets(state)
    if not _flow_scope(state):
        return
    # Fetch the model only once there are files to map: a mistyped path or an empty
    # scope exits above without downloading it.
    _ensure_model_or_exit()
    with _quiet_mapper_logs():
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
