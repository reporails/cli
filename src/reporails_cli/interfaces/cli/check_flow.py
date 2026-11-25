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
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from reporails_cli.core.discovery.exclusions import no_exclusions
from reporails_cli.core.discovery.file_aliases import get_file_aliases
from reporails_cli.core.discovery.walk import file_under_target, is_markdown_file, safe_resolve
from reporails_cli.core.heal.apply import heal_scope_files, heal_scope_outside
from reporails_cli.core.pipeline.mapping import (
    apply_generic_scan,
    discover_scope,
    is_listed_file,
)
from reporails_cli.core.pipeline.named_targets import read_targets, unchecked_capability, unchecked_paths
from reporails_cli.core.pipeline.server_gate import server_gate
from reporails_cli.core.platform.adapters.http_get import http_get
from reporails_cli.core.platform.adapters.key_check import handshake
from reporails_cli.core.platform.config.bootstrap import running_in_ci
from reporails_cli.core.platform.config.run_context import RunContext
from reporails_cli.core.platform.dto.heal import HealRegression
from reporails_cli.core.platform.dto.platform import CombinedResult
from reporails_cli.core.platform.dto.targets import TargetReport, UnevaluatedTarget
from reporails_cli.core.platform.observability.stage_timer import Stopwatch, get_stage_timer
from reporails_cli.core.platform.runtime.merger import normalize_finding_path
from reporails_cli.interfaces.cli.check_notices import (
    _emit_empty_run,
    _emit_heal_scope_refusal,
    _emit_heal_withheld,
    _emit_server_refusal,
    _emit_target_report,
    _emit_unlisted_file,
    _notify_heal_scope_skips,
)
from reporails_cli.interfaces.cli.check_orchestration import (
    HealScope,
    RenderContext,
    _dispatch_output,
    _emit_stage_timing,
    _named_paths,
    _narrow_to_path_targets,
    _quiet_mapper_logs,
    _resolve_capability_paths,
    _run_heal_pass,
    _should_exit_strict,
    project_files,
    scan_scope,
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

if TYPE_CHECKING:
    from reporails_cli.core.mapper.models import Models
    from reporails_cli.core.platform.dto.classify import UnresolvedSkill
    from reporails_cli.core.platform.dto.diagnostics import FunnelError, LintResult, Notice, RemediationWorkflow
    from reporails_cli.core.platform.dto.discovery import DetectedAgent, RunExclusions
    from reporails_cli.core.platform.dto.models import LocalFinding
    from reporails_cli.core.platform.dto.ruleset import RulesetMap
    from reporails_cli.core.platform.observability.stage_timer import StageTimer


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
    # The word each capability spec was written as, in the same order.
    capability_words: list[str] = field(default_factory=list)
    path_targets: set[Path] = field(default_factory=set)
    # The folder targets written as a path inside the project.
    spelled_inside: set[Path] = field(default_factory=set)
    single_path: Path | None = None
    single_file: Path | None = None
    # A lone directory target that lives INSIDE the project and is NOT a project root
    # of its own — the run stays anchored at the project root and is scoped to this
    # subtree. `None` for every other target shape. See `scan_scope`.
    subtree: Path | None = None
    # Mirrors `subtree is not None` — the run is scope-to-subtree rather than
    # anchored at the target.
    subtree_scoped: bool = False
    target: Path = field(default_factory=Path)
    output_format: str = ""
    # The targets no file of the run came from, and the notices on how the run read its targets.
    unevaluated: list[UnevaluatedTarget] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)


@dataclass
class CheckScope:
    """Agent detection, instruction-file discovery, and scope narrowing."""

    detected: list[DetectedAgent] = field(default_factory=list)
    effective_agent: str = ""
    assumed: bool = False
    mixed: bool = False
    filtered: list[DetectedAgent] = field(default_factory=list)
    exclusions: RunExclusions = field(default_factory=lambda: no_exclusions(Path()))
    instruction_files: list[Path] = field(default_factory=list)
    upfront_paths: set[Path] = field(default_factory=set)
    is_targeted: bool = False
    file_type_by_path: dict[str, str] = field(default_factory=dict)
    # The named markdown files no agent loads: checked through their `referenced` class, never mapped.
    unloaded: list[Path] = field(default_factory=list)
    # The files an `@` import in the files in scope brings into the run: shown beside the named files.
    imported: list[Path] = field(default_factory=list)


@dataclass
class CheckPipeline:
    """Pipeline outputs — mapping, probes, content/client checks, server lint."""

    stage_timer: StageTimer = field(default_factory=get_stage_timer)
    stopwatch: Stopwatch = field(default_factory=Stopwatch)
    ruleset_map: RulesetMap | None = None
    m_findings: list[LocalFinding] = field(default_factory=list)
    content_findings: list[LocalFinding] = field(default_factory=list)
    client_findings: list[LocalFinding] = field(default_factory=list)
    rule_agents: tuple[str, ...] = ()
    not_evaluated: tuple[tuple[str, str], ...] = ()
    lint_result: LintResult | None = None
    funnel_error: FunnelError | None = None
    notices: tuple[Notice, ...] = ()


@dataclass
class CheckRender:
    """Assembled result and the display-path projection rendered to the user."""

    result: CombinedResult = field(default_factory=CombinedResult)
    display_result: CombinedResult = field(default_factory=CombinedResult)
    display_map: RulesetMap | None = None
    # The healed files the shown result has slipping since the heal.
    heal_regressions: tuple[HealRegression, ...] = ()
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
    run: RunContext
    models: Models
    targets: CheckTargets = field(default_factory=CheckTargets)
    scope: CheckScope = field(default_factory=CheckScope)
    pipeline: CheckPipeline = field(default_factory=CheckPipeline)
    render: CheckRender = field(default_factory=CheckRender)


def _flow_targets(state: CheckState) -> None:
    """Classify target tokens, pick the scan root + output format, enforce heal scope-safety."""
    if state.inputs.targets:
        reading = read_targets(state.run, state.inputs.targets, state.inputs.agent, state.inputs.project_root)
        if reading.missing:
            missing = reading.missing[0]
            suggestion = (
                f"\n[dim]'{missing.token}' is a known capability — did you mean `ails check {missing.token}`?[/dim]"
                if missing.capability_hint
                else ""
            )
            console.print(f"[red]Error:[/red] Path not found: {missing.path}{suggestion}")
            raise typer.Exit(2)
        state.targets.capability_specs.extend(reading.capability_specs)
        state.targets.capability_words.extend(reading.capability_words)
        state.targets.path_targets |= reading.path_targets
        state.targets.spelled_inside |= reading.spelled_inside
        state.targets.unevaluated.extend(reading.unevaluated)
        state.targets.notices.extend(reading.notices)

    state.targets.single_path = (
        next(iter(state.targets.path_targets))
        if (state.targets.path_targets and not state.targets.capability_specs and len(state.targets.path_targets) == 1)
        else None
    )
    state.targets.subtree, state.targets.target, state.targets.single_file = scan_scope(
        state.targets.single_path, state.inputs.project_root
    )
    state.targets.subtree_scoped = state.targets.subtree is not None
    if state.targets.subtree is not None and not state.targets.path_targets and not state.targets.capability_specs:
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

    config = state.run.project_config(state.targets.target)
    agent_arg = state.inputs.agent or config.default_agent
    if agent_arg:
        _validate_agent(agent_arg, console)
    # A single file is checked whatever is excluded, so its pass lists nothing and records nothing.
    flags, (named, narrowed) = (
        (state.inputs.exclude_dirs, state.inputs.exclude_files),
        _named_paths(state, capability_paths),
    )
    scan = not state.targets.single_file
    found = discover_scope(
        state.run, state.targets.target, agent_arg, *flags, scan_files=scan, named=named, narrowed=narrowed
    )
    state.render.excluded, state.scope.exclusions = found.excluded, found.exclusions
    state.scope.detected, state.scope.filtered = found.detected, found.filtered
    state.scope.effective_agent, state.scope.assumed, state.scope.mixed = (
        found.effective_agent,
        found.assumed,
        found.mixed,
    )
    state.scope.instruction_files = found.files
    if state.targets.single_file is not None:
        state.scope.instruction_files = [state.targets.single_file]
    elif state.targets.target != state.inputs.project_root:
        state.scope.instruction_files = [
            f for f in state.scope.instruction_files if file_under_target(f, state.targets.target)
        ]


def _flow_scope(state: CheckState) -> bool:
    """Detect agents, discover instruction files, narrow to scope. False = nothing in scope."""
    _resolve_scope_at_target(state)
    _list_unchecked_paths(state)
    # A scope-to-subtree run keeps the project scan root, so its narrowing runs here
    # with the capability/multi-path narrowing rather than through the re-root branch.
    narrows = state.targets.single_path is None or state.targets.subtree_scoped
    named_targets = bool(state.targets.capability_specs or state.targets.path_targets)
    if state.targets.unevaluated and not named_targets:
        _emit_empty_run(state)
        return False
    if not state.scope.instruction_files and not (narrows and named_targets):
        _emit_empty_run(state)
        return False
    if narrows and not _narrow_upfront(state):
        return False
    _emit_target_report(state)

    return _apply_generic_scan(state)


def _list_unchecked_paths(state: CheckState) -> None:
    """List each named file or folder no file is checked for, and say a named file no agent loads is checked anyway."""
    single = state.targets.single_file
    if (
        single is not None
        and not is_markdown_file(single)
        and not is_listed_file(state.run, single, state.targets.target)
    ):
        state.scope.instruction_files = []
    state.targets.unevaluated.extend(
        unchecked_paths(
            state.run,
            state.targets.path_targets,
            state.scope.instruction_files,
            exclusions=state.scope.exclusions,
            project_root=state.inputs.project_root,
            scan_target=state.targets.target,
        )
    )


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
        unresolved_skills: list[UnresolvedSkill] = []
        for spec, word in zip(state.targets.capability_specs, state.targets.capability_words, strict=True):
            paths, unresolved = _resolve_capability_paths(
                state.run,
                [spec],
                state.scope.effective_agent,
                state.inputs.project_root,
                state.scope.exclusions,
            )
            cap_paths |= paths
            unresolved_skills += unresolved
            entry = unchecked_capability(word, paths, unresolved)
            if entry is not None:
                state.targets.unevaluated.append(entry)
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
    state.scope.imported, state.scope.file_type_by_path = _classify_generic(state)
    if state.scope.imported:
        state.scope.instruction_files = list(state.scope.instruction_files) + state.scope.imported
    for path in state.scope.instruction_files:
        if safe_resolve(path) in state.scope.exclusions.named and is_markdown_file(path):
            key = normalize_finding_path(str(path), state.targets.target)
            if key not in state.scope.file_type_by_path and not is_listed_file(state.run, path, state.targets.target):
                state.scope.file_type_by_path[key] = "referenced"
                state.scope.unloaded.append(path)
    _announce_unlisted(state)
    state.scope.is_targeted = (
        state.targets.target != state.inputs.project_root
        or bool(state.scope.upfront_paths)
        or state.targets.single_file is not None
    )
    return True


def _classify_generic(state: CheckState) -> tuple[list[Path], dict[str, str]]:
    """The `(import_extra, file_type_by_path)` of the files in scope.

    A run that names files is classified from the whole project's files, so a named file an `@` import
    reaches keeps the class and loading its importer gives it. The files the named files import join
    the run; only those and the named files keep their class.
    """
    files = state.scope.instruction_files
    generic_scanning = bool(state.run.project_config(state.targets.target).generic_scanning)
    import_extra, file_types = _generic_scan(state, files, generic_scanning=generic_scanning)
    if not (generic_scanning and state.scope.exclusions.named):
        return import_extra, file_types
    held = set(files)
    _, file_types = _generic_scan(
        state, [*files, *(f for f in project_files(state) if f not in held)], generic_scanning=True
    )
    keep = {normalize_finding_path(str(f), state.targets.target) for f in (*files, *import_extra)}
    return import_extra, {key: kind for key, kind in file_types.items() if key in keep}


def _generic_scan(state: CheckState, seeds: list[Path], *, generic_scanning: bool) -> tuple[list[Path], dict[str, str]]:
    """`apply_generic_scan` over `seeds` in the run's target, agent and exclusions."""
    return apply_generic_scan(
        state.run,
        state.targets.target,
        seeds,
        state.scope.effective_agent,
        generic_scanning=generic_scanning,
        exclusions=state.scope.exclusions,
    )


def _announce_unlisted(state: CheckState) -> None:
    """Say a named markdown file no agent lists is checked anyway, unless an import brings it in as a loaded file."""
    file = state.targets.single_file
    if file is None or not is_markdown_file(file) or is_listed_file(state.run, file, state.targets.target):
        return
    key = normalize_finding_path(str(file), state.targets.target)
    if state.scope.file_type_by_path.get(key) == "generic":
        return
    _emit_unlisted_file(
        file, state.targets.target, state.inputs.project_root, state.targets.output_format, state.scope.effective_agent
    )


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
                heal_regressions=state.render.heal_regressions,
                aliases=get_file_aliases(state.run, state.targets.target),
                targets=TargetReport(tuple(state.targets.unevaluated), tuple(state.targets.notices)),
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


def _heal_workflow(state: CheckState) -> RemediationWorkflow | None:
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
    single = state.targets.single_path
    heal_scope = single if single is not None else state.targets.target
    candidate = (
        [f for f in state.scope.instruction_files if f in state.render.capability_paths]
        if state.render.capability_paths
        else state.scope.instruction_files
    )
    heal_files = heal_scope_files(candidate, heal_scope, state.targets.target)
    _notify_heal_scope_skips(
        len(heal_scope_outside(candidate, heal_scope, state.targets.target)), state.targets.output_format
    )
    _run_heal_pass(
        state.targets.target,
        HealScope(heal_files, state.scope.effective_agent, state.scope.exclusions, state.models),
        state.pipeline.ruleset_map,
        state.inputs.dry_run,
        state.targets.output_format,
        run=state.run,
        notices=state.render.result.reply.notices,
        workflow=_heal_workflow(state),
    )


def _exit_on_unknown_capability(state: CheckState) -> None:
    """End the run with exit 2 when a named capability is one the agent lacks, as a path that does not exist does."""
    if any(entry.reason == "unknown_capability" for entry in state.targets.unevaluated):
        raise typer.Exit(2)


def run_check_flow(state: CheckState) -> None:
    """Run the ``ails check`` phases over `state`, raising ``typer.Exit`` on scoped-exit paths.

    The server is asked after the targets are read and before any file is discovered:
    a refusal ends the run with exit 1.
    """
    _flow_targets(state)
    refusal = server_gate("ci" if running_in_ci() else "cli", partial(handshake, tier=state.run.tier(), fetch=http_get))
    if refusal is not None:
        _emit_server_refusal(state.targets.output_format, refusal)
        raise typer.Exit(1)
    if not _flow_scope(state):
        _exit_on_unknown_capability(state)
        return
    # Fetch the model only once there are files to map: a mistyped path or an empty
    # scope exits above without downloading it.
    _ensure_model_or_exit()
    with _quiet_mapper_logs():
        _flow_pipeline(state)
        _flow_assemble(state)
        _flow_render(state)
        _flow_heal(state)
    _exit_on_unknown_capability(state)
    if _should_exit_strict(
        state.inputs.strict,
        state.render.capability_paths,
        state.targets.target,
        state.render.result,
        state.pipeline.funnel_error,
    ):
        raise typer.Exit(1)
