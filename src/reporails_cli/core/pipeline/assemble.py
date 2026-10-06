"""The surface-agnostic post-lint assemble spine shared by the CLI and MCP surfaces.

Both the CLI ``ails check`` flow and the MCP ``validate`` tool run the same tail of
the pipeline once the server lint has returned: fold memory-index validation, compute
the capability level, merge local + server findings, then apply inline suppressions and
surface-scoped mutations. Carrying that tail in two places let the surfaces drift — the
MCP path skipped memory validation (drift surface 1) and never threaded the level (drift
surface 3). This module is the single implementation both surfaces call, so those two
surfaces are closed by construction.

Surface-specific concerns stay with the caller: the CLI keeps display-path filtering,
timing, render, and heal; the MCP shell keeps its own server-lint calling convention and
the response envelope. Only the surface-agnostic assemble tail lives here.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Imported at module scope so tests and callers can substitute the level policy;
# the heavier lint/merge/suppression machinery is imported lazily in the body to
# match the CLI flow's import discipline and avoid import-time cost on cold paths.
from reporails_cli.core.discovery.features import detect_features_filesystem
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.policy.levels import determine_level_from_gates

if TYPE_CHECKING:
    from reporails_cli.core.platform.dto.diagnostics import Diagnostic, LintResult, RulesetReport


@dataclass
class AssembleInputs:
    """Everything the surface-agnostic assemble tail needs from either surface.

    ``filter_agents`` is the agent list the level policy reads (the CLI passes its
    resolved ``filtered`` list; the MCP shell passes its discovered agents until the
    agent-filter drift surface is closed). ``lint_result`` is the surface's own
    server-lint result (or ``None`` when offline) -- this core unpacks its
    ``report``/``hints``/``cross_file_coordinates``/``tier``/``workflow`` itself, so both
    surfaces stop hand-unpacking the same four projections before calling in, and stop
    re-attaching ``workflow`` afterward. ``alias_fn`` is the rule-id → alias resolver the
    suppression passes key against; the caller supplies it (it lives in the formatters
    layer, which this core may not import). ``rule_agents`` names the agents whose rules
    ran (the empty name is the core rule set); left empty, the run is taken to be
    ``effective_agent`` alone.
    """

    m_findings: list[Any]
    content_findings: list[Any]
    client_findings: list[Any]
    ruleset_map: Any
    scan_root: Path
    filter_agents: list[Any] | None
    effective_agent: str
    lint_result: LintResult | None
    alias_fn: Callable[[str], set[str]]
    rule_agents: tuple[str, ...] = ()


def assemble_result(inp: AssembleInputs) -> Any:
    """Fold memory findings + level, merge local + server findings, suppress and mutate.

    Returns the merged ``CombinedResult`` after inline suppressions and surface-scoped
    mutations, with a secret reported by both credential rules on one line kept once, the
    composable remediation ``workflow`` attached (``None`` when the server withheld it), the
    workflow's grade stamped on each local finding it serves and the reply's grade stamped on
    each other local finding it names. A finding the reply does not grade, and every finding of
    an offline run, carries no grade. Memory validation runs whenever a ruleset map is present,
    and the computed level is always threaded onto the merged result.
    """
    from reporails_cli.core.lint.memory_checks import validate_memory_files
    from reporails_cli.core.lint.suppression import apply_suppressions
    from reporails_cli.core.platform.adapters.registry import convention_check_ids
    from reporails_cli.core.platform.runtime.merger import (
        collapse_same_secret,
        merge_results,
        stamp_conventions,
        stamp_local_tiers,
        stamp_served_tiers,
    )

    lint_result = inp.lint_result
    memory_findings: list[Any] = []
    if inp.ruleset_map is not None:
        memory_findings = validate_memory_files(inp.ruleset_map.files)

    level = determine_level_from_gates(detect_features_filesystem(inp.scan_root, agents=inp.filter_agents))

    all_client_findings = inp.content_findings + inp.client_findings + memory_findings
    report = lint_result.report if lint_result else None
    if report is not None and inp.ruleset_map is not None:
        report = name_imported_instructions(report, inp.ruleset_map, inp.scan_root)
    result = merge_results(
        inp.m_findings,
        all_client_findings,
        report,
        hints=lint_result.hints if lint_result else (),
        cross_file_coordinates=lint_result.cross_file_coordinates if lint_result else (),
        project_root=inp.scan_root,
        level=level,
        tier=lint_result.tier if lint_result else "",
    )
    result = _drop_dependent(result, inp)
    # The workflow goes on first, so the suppressions the author wrote apply to what it lists too.
    if lint_result is not None and lint_result.workflow is not None:
        result = replace(result, workflow=lint_result.workflow)
    imported = imported_places(inp.ruleset_map, inp.scan_root) if inp.ruleset_map is not None else None
    result = apply_suppressions(result, project_root=inp.scan_root, alias_fn=inp.alias_fn, imported=imported)
    result = _apply_surface_mutations(result, inp.scan_root, inp.effective_agent, inp.alias_fn)
    # After suppressions, so ignoring either credential rule on a line keeps the other's finding.
    result = stamp_served_tiers(collapse_same_secret(result), inp.scan_root)
    result = stamp_local_tiers(result, report.local_tiers if report is not None else (), inp.scan_root)
    return stamp_conventions(result, frozenset().union(*(convention_check_ids(a) for a in _rule_agents(inp))))


# How long a quoted instruction may run in a finding that names where it is written.
_QUOTE_MAX_CHARS = 80


def _imported_note(atom: Any, scan_root: Path) -> str:
    """` (from docs/style.md:7: "Keep the diff small.")` — where an imported instruction is written."""
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    where = normalize_finding_path((Path(atom.file_path).parent / atom.imported_from).as_posix(), scan_root)
    text = " ".join(atom.text.split())
    quote = text if len(text) <= _QUOTE_MAX_CHARS else text[: _QUOTE_MAX_CHARS - 1].rstrip() + "…"
    return f' (from {where}:{atom.imported_line}: "{quote}")'


def _imported_atoms(ruleset_map: Any, scan_root: Path) -> dict[tuple[str, int], Any]:
    """The instructions `@path` imports bring in, by their file and place in it."""
    from reporails_cli.core.mapper.parse import holds_position
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    return {
        (normalize_finding_path(a.file_path, scan_root), a.position_index): a
        for a in getattr(ruleset_map, "atoms", ())
        if a.imported_from and holds_position(a)
    }


def imported_places(ruleset_map: Any, scan_root: Path) -> dict[tuple[str, int], tuple[str, int]]:
    """Where each imported instruction is written: its importing file and place -> (imported file, line there)."""
    return {key: (a.imported_from, a.imported_line) for key, a in _imported_atoms(ruleset_map, scan_root).items()}


def name_imported_instructions(report: RulesetReport, ruleset_map: Any, scan_root: Path) -> RulesetReport:
    """A finding on an instruction an `@path` import brings in names where it is written.

    Such an instruction has no line of its own in the importing file, so the finding
    points at the `@path` line; its message gains the imported file, the line there and
    the instruction's words. Matched by the instruction's place in its file, so two
    imported instructions under one `@path` line each name their own line.
    """
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    imported = _imported_atoms(ruleset_map, scan_root)
    if not imported:
        return report

    def _named(d: Diagnostic) -> Diagnostic:
        atom = None if d.pi is None else imported.get((normalize_finding_path(d.file, scan_root), d.pi))
        return d if atom is None else replace(d, message=d.message + _imported_note(atom, scan_root))

    per_file = tuple(replace(fa, diagnostics=tuple(_named(d) for d in fa.diagnostics)) for fa in report.per_file)
    return replace(report, per_file=per_file)


def reported_local_findings(inp: AssembleInputs) -> tuple[Any, ...]:
    """The local findings as they will be reported, before any server lint.

    Memory-index validation is folded in, and the same inline suppressions, surface-scoped
    mutations and same-secret collapse the assembled result applies are applied here.
    """
    from reporails_cli.core.lint.memory_checks import validate_memory_files
    from reporails_cli.core.lint.suppression import apply_suppressions
    from reporails_cli.core.platform.runtime.merger import collapse_same_secret, merge_results

    memory_findings: list[Any] = []
    if inp.ruleset_map is not None:
        memory_findings = validate_memory_files(inp.ruleset_map.files)
    result = merge_results(
        inp.m_findings,
        inp.content_findings + inp.client_findings + memory_findings,
        None,
        project_root=inp.scan_root,
    )
    result = _drop_dependent(result, inp)
    result = apply_suppressions(result, project_root=inp.scan_root, alias_fn=inp.alias_fn)
    result = _apply_surface_mutations(result, inp.scan_root, inp.effective_agent, inp.alias_fn)
    return tuple(collapse_same_secret(result).findings)


def _local_finding_type_resolver(inp: AssembleInputs, registry: dict[str, Any]) -> Callable[[str], str]:
    """A `path -> type` lookup for `lint_request_local`'s local findings.

    The ruleset map's own records carry each path's type (a skill's supporting file included),
    so a mapped path keeps its record's type. A path the map does not carry takes its file
    type, and stays `skills` only when it sits at or below a recorded skill folder or is exactly a skill slot folder
    (a folder with no `SKILL.md`; its other files stay plain).
    """
    from reporails_cli.core.mapper.inspect import file_type_of
    from reporails_cli.core.mapper.skills import skill_membership, skill_slot_folders, skill_type

    ruleset_files = inp.ruleset_map.files if inp.ruleset_map is not None else ()
    skill_folders = {Path(f) for f in (skill_membership(inp.ruleset_map) or {}).values()}
    slot_folders = skill_slot_folders(inp.ruleset_map, inp.scan_root) if inp.ruleset_map is not None else set()
    type_by_path: dict[Path, str] = {safe_resolve(Path(f.path)): f.type for f in ruleset_files}

    def _typed(path: str) -> str:
        p = Path(path)
        mapped = type_by_path.get(safe_resolve(p))
        if mapped is not None:
            return str(mapped)
        if p in slot_folders:
            return "skills"
        return skill_type(file_type_of(p, inp.scan_root, registry), p, skill_folders)

    return _typed


def _rule_agents(inp: AssembleInputs) -> tuple[str, ...]:
    """The agents whose rules ran: the run's own agent list, or the effective agent alone."""
    return inp.rule_agents or (inp.effective_agent,)


def _drop_dependent(result: Any, inp: AssembleInputs) -> Any:
    """Drop the findings covered by a rule they depend on, judged on the findings as detected."""
    from reporails_cli.core.platform.adapters.registry import rule_dependencies, whole_run_check_ids
    from reporails_cli.core.platform.policy.dependencies import drop_dependent_findings
    from reporails_cli.core.platform.runtime.merger import drop_findings

    agents = _rule_agents(inp)
    dependencies: dict[str, frozenset[str]] = {}
    for agent in agents:
        for rule, deps in rule_dependencies(agent).items():
            dependencies[rule] = dependencies.get(rule, frozenset()) | deps
    kept = drop_dependent_findings(
        result.findings, dependencies, frozenset().union(*(whole_run_check_ids(a) for a in agents))
    )
    return drop_findings(result, kept)


def _structural_ids(inp: AssembleInputs) -> frozenset[str]:
    """The structural rule ids across every agent whose rules ran."""
    from reporails_cli.core.platform.adapters.registry import structural_rule_ids

    return frozenset().union(*(structural_rule_ids(a) for a in _rule_agents(inp)))


def lint_request_local(inp: AssembleInputs) -> tuple[list[Any], int]:
    """The local findings the diagnostics request carries, and the structural-rule total.

    One entry per reported local finding (see `reported_local_findings`). The rule-id sets are
    resolved under every agent whose rules ran, so a finding under an agent's own rule is sent,
    and an agent rule that supersedes a core structural rule counts under the id the finding
    carries.
    """
    from reporails_cli.core.lint.suppression import resolve_finding_path
    from reporails_cli.core.mapper.inspect import _load_registry
    from reporails_cli.core.platform.adapters.payload import local_entries
    from reporails_cli.core.platform.adapters.registry import file_level_check_ids, registry_rule_ids

    agents = _rule_agents(inp)
    structural_ids = _structural_ids(inp)
    registry = _load_registry()

    def _absolute(rel: str) -> str:
        path = resolve_finding_path(rel, inp.scan_root)
        return path.as_posix() if path is not None else rel

    entries = local_entries(
        reported_local_findings(inp),
        frozenset().union(*(file_level_check_ids(a) for a in agents)),
        frozenset().union(*(registry_rule_ids(a) for a in agents)),
        _absolute,
        _local_finding_type_resolver(inp, registry),
    )
    return entries, len(structural_ids)


def _apply_surface_mutations(
    result: Any, scan_root: Path, effective_agent: str, alias_fn: Callable[[str], set[str]]
) -> Any:
    """Drop findings on a surface whose rule declares ``surface_mutations`` non-applicable.

    Loads the active rule set (surface mutations live on core rules) and filters the merged
    result. A load failure is non-fatal — the unmutated result is returned unchanged.
    """
    from reporails_cli.core.lint.suppression import apply_surface_mutations
    from reporails_cli.core.platform.adapters.registry import load_rules

    try:
        rules = load_rules(project_root=scan_root, agent=effective_agent, scan_root=scan_root)
    except (OSError, ValueError):
        return result
    if rules:
        return apply_surface_mutations(result, rules, alias_fn=alias_fn, project_root=scan_root)
    return result
