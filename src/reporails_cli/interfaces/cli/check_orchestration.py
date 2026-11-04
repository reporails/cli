"""Orchestration helpers for the ``ails check`` command.

Capability-target error reporting (over the core resolver),
output dispatch, the heal pass, strict-exit policy, and the in-process mapper
fallback — the machinery ``check()`` drives. Split out of ``check_command.py`` so the
command body reads as a flow over named helpers rather than one long function.
"""

from __future__ import annotations

import json
import logging
import sys
from contextlib import AbstractContextManager
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

import typer

from reporails_cli.core.classify.capability_paths import TargetError, looks_like_windows_path, sniff_agent
from reporails_cli.core.classify.focus_expansion import resolve_capability_spec
from reporails_cli.core.discovery.walk import file_under_target, safe_resolve
from reporails_cli.core.heal.apply import resolved_within, suppressed_by_path
from reporails_cli.core.pipeline.check_one import resolve_scan_target
from reporails_cli.core.platform.adapters.notices_seen import due_notices
from reporails_cli.core.platform.dto.classify import UnresolvedSkill
from reporails_cli.core.platform.dto.diagnostics import AUTH_REJECTED_ERRORS, FunnelError
from reporails_cli.core.platform.dto.discovery import RunExclusions
from reporails_cli.core.platform.dto.platform import CombinedResult
from reporails_cli.core.platform.observability.log_levels import quiet_loggers
from reporails_cli.core.platform.observability.stage_timer import Stopwatch, get_stage_timer
from reporails_cli.core.platform.runtime.merger import normalize_finding_path
from reporails_cli.formatters import github as github_formatter
from reporails_cli.formatters import json as json_formatter
from reporails_cli.formatters.text.display import print_text_result
from reporails_cli.interfaces.cli.heal import (
    _apply_keyed_fixes,
    _collect_section_suggestions,
    _output_heal_results,
)
from reporails_cli.interfaces.cli.helpers import console
from reporails_cli.interfaces.cli.output_formats import CHECK_FORMATS

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.diagnostics import Notice, RemediationWorkflow
    from reporails_cli.core.platform.dto.ruleset import RulesetMap
    from reporails_cli.core.platform.observability.stage_timer import StageTimer
    from reporails_cli.interfaces.cli.check_flow import CheckState

logger = logging.getLogger(__name__)


def _resolve_capability_paths_one(
    capability: str,
    capability_name: str,
    effective_agent: str,
    project_root: Path,
    exclusions: RunExclusions | None = None,
) -> tuple[set[Path], list[UnresolvedSkill]]:
    """Resolve one (capability, name) spec to its file set + unresolved-skill list; a spec that
    names no file prints why and exits 2."""

    try:
        return resolve_capability_spec(capability, capability_name, effective_agent, project_root, exclusions)
    except TargetError as err:
        if err.reason == "undeclared":
            console.print(
                f"[red]Error:[/red] capability [bold]{capability}[/bold] is not declared "
                f"for agent [bold]{effective_agent}[/bold]. "
                f"Available: {', '.join(err.available) or '(none)'}"
            )
            raise typer.Exit(2) from err
        console.print(
            f"[red]Error:[/red] no {capability} named [bold]{capability_name}[/bold] "
            f"for agent [bold]{effective_agent}[/bold] under {project_root}."
        )
        if err.available:
            console.print(
                f"[dim]Found {len(err.available)} {capability}(s) — run `ails check @{capability}` to list.[/dim]"
            )
        raise typer.Exit(2) from err


def _resolve_capability_paths(
    specs: list[tuple[str, str]],
    effective_agent: str,
    project_root: Path,
    exclusions: RunExclusions | None = None,
) -> tuple[set[Path], list[UnresolvedSkill]]:
    """Union of every (capability, name) spec resolved against the agent's vocabulary."""
    paths: set[Path] = set()
    unresolved: list[UnresolvedSkill] = []
    for capability, capability_name in specs:
        one_paths, one_unresolved = _resolve_capability_paths_one(
            capability, capability_name, effective_agent, project_root, exclusions
        )
        paths |= one_paths
        unresolved.extend(one_unresolved)
    return paths, unresolved


def _named_paths(state: CheckState, capability_paths: frozenset[Path]) -> tuple[frozenset[Path], bool]:
    """The files the run names, and whether the run covers nothing but those files.

    Named: capability paths, path targets that are files, and the single file. The run is narrowed to them
    only when every target is a named file: a folder target or a capability listing (a bare capability
    such as `skills`) keeps the run wide.
    """
    single = state.targets.single_file
    named = frozenset(
        capability_paths | {t for t in state.targets.path_targets if t.is_file()} | ({single} if single else set())
    )
    only_files = all(name for _, name in state.targets.capability_specs) and all(
        t.is_file() for t in state.targets.path_targets
    )
    return named, bool(named) and only_files


def _resolved_within_target(f: Path, target: Path) -> bool:
    """True when the file's real (symlink-resolved) location is within the heal target."""

    return resolved_within(f, target)


def scan_scope(single_path: Path | None, project_root: Path) -> tuple[Path | None, Path, Path | None]:
    """The `(subtree, scan_root, single_file)` of a lone path target, read as `.` when there is no target:
    the scan root and file the shared target rule picks, and the folder target narrower than the root
    (None for a file or the whole project)."""
    target = project_root if single_path is None else single_path
    scan_root, single_file = resolve_scan_target(target, project_root)
    narrower = target.is_dir() and target != scan_root and target.is_relative_to(scan_root)
    return (target if narrower else None), scan_root, single_file


def _existing_target_root(token: str, project_root: Path) -> Path | None:
    """The scan root of a target token that names an existing file or folder, else None.

    A capability form (`@skills`, `skills:backlog`) and a word that names nothing on disk
    return None: those are read against the current folder's project.
    """

    raw = token[len("file:") :] if token.startswith("file:") else token
    if raw.startswith("@") or (":" in raw and not looks_like_windows_path(raw)):
        return None
    try:
        path = safe_resolve(Path(raw))
        if not path.exists():
            return None
        return resolve_scan_target(path, project_root)[0]
    except OSError:
        return None


def _token_agent(token: str, agent: str, project_root: Path, sniffed: dict[Path, str]) -> str:
    """The agent whose vocabulary reads `token`: sniffed under the project of an existing path
    target, under the current folder's project for anything else (`sniffed` caches per root)."""

    root = _existing_target_root(token, project_root) or project_root
    if root not in sniffed:
        sniffed[root] = sniff_agent(agent, root)
    return sniffed[root]


def _narrow_to_path_targets(instruction_files: list[Path], path_targets: set[Path]) -> list[Path]:
    """Keep only instruction files that are equal to or beneath one of `path_targets`."""
    return [f for f in instruction_files if any(file_under_target(f, tgt) for tgt in path_targets)]


def _relativize_paths(paths: set[Path], project_root: Path) -> set[str]:
    return {p.relative_to(project_root).as_posix() if p.is_relative_to(project_root) else p.as_posix() for p in paths}


def _validate_output_format(output_format: str | None) -> None:
    """Reject an unknown `--format` with a usage error naming the formats that exist."""
    if output_format and output_format not in CHECK_FORMATS:
        console.print(f"[red]Error:[/red] Unknown format: {output_format}")
        console.print(f"Valid formats: {', '.join(CHECK_FORMATS)}")
        raise typer.Exit(2)


class RenderContext(NamedTuple):
    """Where a result renders from and how: the scan root, the files in scope, and the text flags."""

    project_root: Path
    capability_paths: set[Path]
    file_type_by_path: dict[str, str] | None = None
    ascii_mode: bool = False
    verbose: bool = False


def _emit_json(
    result: CombinedResult, ruleset_map: RulesetMap | None, elapsed_ms: float, context: RenderContext
) -> None:
    """Print the result as one JSON object, with the run's elapsed time and any named paths."""
    data = json_formatter.format_combined_result(
        result,
        ruleset_map=ruleset_map,
        project_root=context.project_root,
        file_type_by_path=context.file_type_by_path,
    )
    data["elapsed_ms"] = round(elapsed_ms, 1)
    timer = get_stage_timer()
    if timer.enabled:
        data["timing"] = [*timer.as_dict()]
    if context.capability_paths:
        data["capability_paths"] = [*sorted(_relativize_paths(context.capability_paths, context.project_root))]
    print(json.dumps(data, indent=2))


def _dispatch_output(
    output_format: str,
    display_result: CombinedResult,
    ruleset_map: RulesetMap | None,
    elapsed_ms: float,
    *,
    funnel_error: FunnelError | None,
    context: RenderContext,
) -> None:
    """Route formatted output to JSON / GitHub / text.

    Every format consumes `funnel_error` by attaching it onto the `CombinedResult` as
    `server_error` before formatting — a server rejection, timeout, or network failure
    otherwise reads identically to a designed-offline run (`offline: true` with no reason).
    Text also renders `funnel_error` directly via its CTA path (`_render_funnel_cta`).
    """
    result_for_output = display_result
    if isinstance(funnel_error, FunnelError):
        result_for_output = replace(display_result, reply=replace(display_result.reply, server_error=funnel_error))

    if output_format == "json":
        _emit_json(result_for_output, ruleset_map, elapsed_ms, context)
        return
    if output_format == "github":
        print(
            github_formatter.format_combined_annotations(
                result_for_output,
                ruleset_map=ruleset_map,
                project_root=context.project_root,
                file_type_by_path=context.file_type_by_path,
                elapsed_ms=elapsed_ms,
            )
        )
        return
    # Only the notices due today are shown; JSON above carries them all.
    print_text_result(
        replace(
            result_for_output,
            reply=replace(result_for_output.reply, notices=due_notices(result_for_output.reply.notices)),
        ),
        elapsed_ms,
        context.ascii_mode,
        context.verbose,
        ruleset_map=ruleset_map,
        funnel_error=funnel_error,
        project_root=context.project_root,
        file_type_by_path=context.file_type_by_path,
    )


def _emit_stage_timing(stage_timer: StageTimer, output_format: str) -> None:
    """Print the per-stage timing table (dev-only, gated by `AILS_STAGE_TIMING`).

    Only renders when the timer was enabled via the env var; the internal stage
    names never reach the default text / JSON output.
    """
    if output_format == "json" or not stage_timer.enabled or not stage_timer.records:
        return
    console.print("\n  [dim]── Stage timing (wall-clock) ──[/dim]")
    for line in stage_timer.render_lines():
        console.print(f"  [dim]{line}[/dim]")


class HealScope(NamedTuple):
    """The files a heal pass may touch, the agent they are checked under, and what the run left out."""

    instruction_files: list[Path]
    effective_agent: str
    exclusions: RunExclusions | None = None


def _run_heal_pass(
    target: Path,
    scope: HealScope,
    ruleset_map: RulesetMap | None,
    dry_run: bool,
    output_format: str,
    *,
    notices: tuple[Notice, ...] = (),
    workflow: RemediationWorkflow | None = None,
) -> None:
    """Fix each finding at its own place and collect section suggestions using the already-built map.

    `workflow` is the paid remediation workflow; the fixes are the ones it lists.
    """
    show = sys.stdout.isatty() and output_format != "json"
    stopwatch = Stopwatch()
    with get_stage_timer().stage("heal"):
        # A line the author annotated with an `ails-disable-line` directive is reviewed —
        # heal must not mechanically rewrite it. Key the suppressed lines by resolved path
        # so they match the atom files regardless of path form.
        suppressed = suppressed_by_path(scope.instruction_files, target)
        # The mechanical pass writes only within the scoped `instruction_files` set — it
        # cannot rewrite a mapped file outside scope. Section suggestions never write.
        keyed = _apply_keyed_fixes(
            ruleset_map,
            target,
            workflow,
            dry_run=dry_run,
            show_progress=show,
            console=console,
            allowed_files=scope.instruction_files,
            suppressed=suppressed,
        )
        suggested = _collect_section_suggestions(
            target,
            scope.instruction_files,
            ruleset_map,
            scope.effective_agent,
            show_progress=show,
            console=console,
            exclusions=scope.exclusions,
        )
    heal_ms = round(stopwatch.ms, 1)
    _output_heal_results(
        keyed.fixes,
        suggested,
        dry_run=dry_run,
        elapsed_ms=heal_ms,
        output_format=output_format,
        console=console,
        notices=notices,
        keyed=keyed,
    )


# A key the server rejected, quoted back to the caller as `FunnelError.error`.
# `--strict` treats either as a hard failure regardless of local findings: a CI job
# passing a revoked or malformed key must not read as a clean run just because
# the tree it happened to check carries no findings of its own.


def _should_exit_strict(
    strict: bool,
    capability_paths: set[Path],
    project_root: Path,
    result: CombinedResult,
    funnel_error: FunnelError | None = None,
) -> bool:
    if not strict:
        return False

    if isinstance(funnel_error, FunnelError) and funnel_error.error in AUTH_REJECTED_ERRORS:
        return True
    if capability_paths:
        # Key the scope set with the SAME normalization the display filter uses
        # (`normalize_finding_path`), not `_relativize_paths`. The two diverge for
        # user-scope paths (`~/.claude/...`), so a strict run on such a target could
        # exit 0 while the display showed errors for it.

        rel_keys = {normalize_finding_path(str(p), project_root) for p in capability_paths}
        return any(f.file in rel_keys for f in result.findings)
    return bool(result.findings)


def _quiet_mapper_logs() -> AbstractContextManager[None]:
    """Keep the mapper's info-level logs off stderr for the duration of a check."""

    return quiet_loggers(("reporails_cli.core.mapper",))
