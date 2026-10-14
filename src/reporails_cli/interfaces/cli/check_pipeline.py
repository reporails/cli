"""Pipeline and assemble phases of the ``ails check`` flow.

Map the instruction files, run the M-probes and content/client checks, send the findings to
the server, and assemble the merged result. Each phase mutates the ``CheckState`` it is given.
"""

from __future__ import annotations

import sys
import time
from collections.abc import Callable
from contextlib import nullcontext
from pathlib import Path
from typing import TYPE_CHECKING, Any

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.lint.client_checks import run_client_checks
from reporails_cli.core.lint.regex.not_evaluated import not_evaluated_scope
from reporails_cli.core.lint.rule_runner import run_content_quality_checks, run_m_probes_over_pairs
from reporails_cli.core.mapper.skills import skill_membership
from reporails_cli.core.pipeline.assemble import (
    AssembleInputs,
    assemble_result,
    lint_request_local,
    with_exclusions,
)
from reporails_cli.core.pipeline.mapping import agent_file_pairs, map_instruction_files
from reporails_cli.core.platform.adapters.api_client import AilsClient
from reporails_cli.core.platform.adapters.notices_seen import visible_notices
from reporails_cli.core.platform.config.bootstrap import env_flag
from reporails_cli.core.platform.observability.stage_timer import get_stage_timer
from reporails_cli.formatters.text.path_filter import filter_result_to_paths, filter_ruleset_map_to_paths
from reporails_cli.interfaces.cli.check_notices import _agent_is_pinned
from reporails_cli.interfaces.cli.check_orchestration import logger
from reporails_cli.interfaces.cli.helpers import console

if TYPE_CHECKING:
    from reporails_cli.interfaces.cli.check_flow import CheckState


def _agent_file_pairs(state: CheckState) -> list[tuple[str, list[Path]]]:
    """The ``(agent_id, its own scoped files)`` pairs M-probes / content checks run over --
    the CLI's thin wrapper over the shared ``core.pipeline.mapping.agent_file_pairs`` MCP
    ``validate`` also calls, so both surfaces score identical ``(rule, file, line)`` triples
    for the same tree."""

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

    state.pipeline.start_time = time.perf_counter()

    state.pipeline.stage_timer = get_stage_timer()
    state.pipeline.stage_timer.configure(enabled=env_flag("AILS_STAGE_TIMING"))

    show_progress = sys.stdout.isatty() and state.targets.output_format not in ("json", "github")
    progress: Callable[[str], None] = (
        (lambda msg: print(msg, file=sys.stderr, flush=True))
        if state.inputs.verbose and not show_progress
        else (lambda _: None)
    )
    spinner = console.status("[bold]Starting...[/bold]") if show_progress else nullcontext()

    with spinner:

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
        with not_evaluated_scope() as unfinished:
            state.pipeline.m_findings = run_m_probes_over_pairs(
                state.targets.target,
                pairs,
                scoped=state.scope.is_targeted,
                skills=skills,
                exclusions=state.scope.exclusions,
            )
        state.pipeline.not_evaluated = tuple(unfinished)
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

    state.pipeline.content_findings = [
        finding
        for agent_id, files in _agent_file_pairs(state)
        for finding in run_content_quality_checks(
            state.pipeline.ruleset_map, state.targets.target, files, agent=agent_id, exclusions=state.scope.exclusions
        )
    ]
    state.pipeline.client_findings = run_client_checks(state.pipeline.ruleset_map)


def _flow_server_lint(state: CheckState, show_progress: bool, spinner: Any) -> None:
    """Send local findings to the server and unpack the lint response onto the pipeline state."""

    if show_progress:
        spinner.update("[bold]Diagnosing...[/bold]")
    response = None
    if state.pipeline.ruleset_map is not None:
        local, structural_required = lint_request_local(_assemble_inputs(state))
        response = AilsClient().lint(state.pipeline.ruleset_map, local, structural_required, root=state.targets.target)
    state.pipeline.lint_result = response.result if response else None
    state.pipeline.funnel_error = response.funnel_error if response else None
    state.pipeline.notices = visible_notices(response.notices if response else (), no_promo=state.render.no_promo)
    state.pipeline.stage_timer.mark("server")


def _assemble_inputs(state: CheckState, lint_result: Any = None) -> Any:
    """The shared assemble spine's inputs from the check state (`lint_result` None before the lint)."""

    return AssembleInputs(
        m_findings=state.pipeline.m_findings,
        content_findings=state.pipeline.content_findings,
        client_findings=state.pipeline.client_findings,
        ruleset_map=state.pipeline.ruleset_map,
        scan_root=state.targets.target,
        filter_agents=state.scope.filtered,
        effective_agent=state.scope.effective_agent,
        lint_result=lint_result,
        rule_agents=state.pipeline.rule_agents,
        notices=state.pipeline.notices,
        not_evaluated=state.pipeline.not_evaluated,
    )


def _flow_assemble(state: CheckState) -> None:
    """Memory validation, capability level, merge, suppression, and display-path filtering.

    The memory / level / merge / suppress / surface-mutation / credential-duplicate tail is the surface-agnostic
    assemble spine shared with the MCP `validate` tool (`core/pipeline/assemble.py`); the
    display-path filtering below stays CLI-only.
    """

    state.render.result = with_exclusions(
        assemble_result(_assemble_inputs(state, state.pipeline.lint_result), state.scope.exclusions),
        state.render.excluded,
    )
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
