"""Rule runner — iterate YAML rule definitions and dispatch checks.

Replaces the old engine.py pipeline with a simplified runner that
dispatches mechanical and deterministic checks, producing LocalFinding
instances directly.

Content-quality checks (type=content_query) run separately via
run_content_quality_checks() against the RulesetMap.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.lint.content_checker import run_content_checks
from reporails_cli.core.lint.mechanical.runner import run_mechanical_checks
from reporails_cli.core.lint.regex import run_checks
from reporails_cli.core.lint.regex.compiler import display_severity
from reporails_cli.core.mapper.skills import skill_entry_paths, skill_membership
from reporails_cli.core.platform.adapters.registry import load_rules
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.dto.models import Execution, LocalFinding, Rule, RuleType
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.policy.matching import match_files

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def _collect_mechanical_findings(
    rules: dict[str, Rule],
    project_dir: Path,
    classified: list[Any],
    *,
    scoped: bool = False,
    project_checks: str = "all",
    exclusions: RunExclusions | None = None,
) -> list[LocalFinding]:
    """Run mechanical checks and convert Violations to LocalFinding."""
    # A rule of any type may hold a mechanical check; the runner runs only those checks.
    mechanical_rules = {k: v for k, v in rules.items() if v.execution == Execution.LOCAL}
    findings: list[LocalFinding] = []
    for v in run_mechanical_checks(
        mechanical_rules, project_dir, classified, scoped=scoped, project_checks=project_checks, exclusions=exclusions
    ):
        file_path = v.location.rsplit(":", 1)[0] if ":" in v.location else v.location
        line = 0
        if ":" in v.location:
            with contextlib.suppress(ValueError):
                line = int(v.location.rsplit(":", 1)[1])
        findings.append(
            LocalFinding(
                file=file_path,
                line=line,
                severity=display_severity(v.severity.value),
                rule=v.rule_id,
                message=v.message,
                fix=v.fix,
                source="m_probe",
                check_id=v.check_id or "",
            )
        )
    return findings


def _has_deterministic_checks(rule: Rule) -> bool:
    """Return True if the rule contains at least one deterministic check."""
    return any(c.type == "deterministic" for c in rule.checks)


def _min_lines_overrides(project_dir: Path) -> dict[str, int]:
    """The per-rule `min_lines` thresholds the project's config sets."""
    try:
        thresholds = get_project_config(project_dir).rule_thresholds
    except (OSError, ValueError):
        return {}
    overrides: dict[str, int] = {}
    for rule_id, args in thresholds.items():
        min_lines = args.get("min_lines")
        if isinstance(min_lines, int):
            overrides[rule_id] = min_lines
    return overrides


def _deterministic_targets(rule: Rule, instruction_files: list[Path], classified: list[Any]) -> list[Path]:
    """The files a deterministic rule runs on: those its `match` criteria select, else every instruction file."""
    if rule.match:
        return [cf.path for cf in match_files(classified, rule.match)]
    return instruction_files


def _collect_deterministic_findings(
    rules: dict[str, Rule],
    project_dir: Path,
    instruction_files: list[Path],
    classified: list[Any],
) -> list[LocalFinding]:
    """Run deterministic checks against matched target files.

    Uses property-based matching (match_files) so rules targeting specific
    scopes, formats, or other properties get the correct file set.
    Rules of any type are included if they contain deterministic checks.
    """
    min_lines_overrides = _min_lines_overrides(project_dir)
    skill_entries = skill_entry_paths(classified)
    findings: list[LocalFinding] = []
    for rule in rules.values():
        if rule.type != RuleType.DETERMINISTIC and not _has_deterministic_checks(rule):
            continue
        if not rule.yml_path or not rule.yml_path.exists():
            continue
        target_files = _deterministic_targets(rule, instruction_files, classified)
        if not target_files:
            continue

        findings.extend(
            run_checks(
                [rule.yml_path],
                project_dir,
                instruction_files=target_files,
                min_lines_overrides=min_lines_overrides,
                fix_by_rule={rule.id: rule.fix} if rule.fix else None,
                skill_entries=skill_entries,
            )
        )
    return findings


def _extend_with_generic(
    instruction_files: list[Path],
    classified: list[Any],
    generic_scanning: bool,
) -> list[Path]:
    """Append link-walked generic-class files so rules without explicit `match` see them."""
    effective = list(instruction_files)
    if not generic_scanning:
        return effective
    known = set(effective)
    for cf in classified:
        if cf.path not in known and cf.file_type == "generic":
            effective.append(cf.path)
            known.add(cf.path)
    return effective


def _classify_agent_files(
    project_dir: Path,
    instruction_files: list[Path],
    agent: str,
    skills: Mapping[str, str] | None = None,
    exclusions: RunExclusions | None = None,
) -> tuple[list[Any], bool]:
    """Classify `instruction_files` with `agent`'s file types; also return whether generic scanning is on."""
    file_types = load_file_types(agent or "generic", project_root=project_dir)
    try:
        _config = get_project_config(project_dir)
        generic_scanning = _config.generic_scanning
    except (OSError, ValueError):
        generic_scanning = False
    classified = classify_files(
        project_dir,
        instruction_files,
        file_types,
        generic_scanning=generic_scanning,
        skills=skills,
        exclusions=exclusions,
    )
    return classified, generic_scanning


def run_m_probes(
    project_dir: Path,
    instruction_files: list[Path],
    *,
    agent: str = "",
    scoped: bool = False,
    project_checks: str = "all",
    skills: Mapping[str, str] | None = None,
    exclusions: RunExclusions | None = None,
) -> list[LocalFinding]:
    """Run M-probe checks (mechanical + deterministic) against instruction files.

    When `scoped` is True (targeted check — capability/path/file scope),
    project-aggregate mechanical checks are skipped so they cannot misfire
    against a narrowed subset. `project_checks` is ``"defer"`` for a per-agent pass
    whose project-wide core checks run later over every file, and ``"only"`` for that
    later pass (project-wide checks alone). `skills` maps each file in a skill to its
    skill folder; when given, only those files are typed `skills`.
    """
    scan_dir = project_dir if project_dir.is_dir() else project_dir.parent
    rules = load_rules(project_root=project_dir, scan_root=scan_dir, agent=agent)
    classified, generic_scanning = _classify_agent_files(project_dir, instruction_files, agent, skills, exclusions)
    effective_files = _extend_with_generic(instruction_files, classified, generic_scanning)

    findings: list[LocalFinding] = []
    findings.extend(
        _collect_mechanical_findings(
            rules, project_dir, classified, scoped=scoped, project_checks=project_checks, exclusions=exclusions
        )
    )
    if project_checks != "only":
        findings.extend(_collect_deterministic_findings(rules, project_dir, effective_files, classified))

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.line))
    return findings


def _replaced_core_rules(
    project_dir: Path, scan_dir: Path, agent_ids: list[str], core_rules: dict[str, Rule]
) -> dict[str, set[str]]:
    """For each core rule an agent's own rule supersedes, the agents whose rule replaces it."""
    replaced_by: dict[str, set[str]] = {}
    for agent_id in agent_ids:
        for rule in load_rules(project_root=project_dir, scan_root=scan_dir, agent=agent_id).values():
            if rule.supersedes in core_rules:
                replaced_by.setdefault(rule.supersedes, set()).add(agent_id)
    return replaced_by


def _files_by_first_agent(
    project_dir: Path,
    pairs: list[tuple[str, list[Path]]],
    skills: Mapping[str, str] | None,
    exclusions: RunExclusions | None,
) -> dict[Path, tuple[str, Any]]:
    """Each file the pairs name, classified by the first agent that lists it: path -> (agent, classified file)."""
    seen: dict[Path, tuple[str, Any]] = {}
    for agent_id, agent_files in pairs:
        for cf in _classify_agent_files(project_dir, agent_files, agent_id, skills, exclusions)[0]:
            seen.setdefault(cf.path, (agent_id, cf))
    return seen


def _project_wide_findings(
    project_dir: Path,
    pairs: list[tuple[str, list[Path]]],
    *,
    scoped: bool = False,
    skills: Mapping[str, str] | None = None,
    exclusions: RunExclusions | None = None,
) -> list[LocalFinding]:
    """The core rules' project-wide checks over every pair's files, each classified by its own agent.

    A core rule that an agent's own rule replaces does not judge that agent's files: the
    agent's pass already reports them under the agent's rule.
    """
    scan_dir = project_dir if project_dir.is_dir() else project_dir.parent
    rules = load_rules(project_root=project_dir, scan_root=scan_dir, agent="")
    seen = _files_by_first_agent(project_dir, pairs, skills, exclusions)
    replaced_by = _replaced_core_rules(project_dir, scan_dir, [agent_id for agent_id, _ in pairs if agent_id], rules)
    groups: dict[frozenset[str], dict[str, Rule]] = {}
    for rule_id, rule in rules.items():
        groups.setdefault(frozenset(replaced_by.get(rule_id, ())), {})[rule_id] = rule
    return [
        finding
        for skipped_agents, group in groups.items()
        for finding in _collect_mechanical_findings(
            group,
            project_dir,
            [cf for owner, cf in seen.values() if owner not in skipped_agents],
            scoped=scoped,
            project_checks="only",
            exclusions=exclusions,
        )
    ]


def run_m_probes_over_pairs(
    project_dir: Path,
    pairs: list[tuple[str, list[Path]]],
    *,
    scoped: bool = False,
    skills: Mapping[str, str] | None = None,
    exclusions: RunExclusions | None = None,
) -> list[LocalFinding]:
    """Run the M-probes once per ``(agent, its files)`` pair, with project-wide checks once.

    A check that judges the project as a whole (total size, file count) must see every
    in-scope file, so when several agents own files those core checks are held back from
    each agent's pass and run once over the union. Checks that judge one agent's own files,
    and agent-specific rules, stay in that agent's pass.
    """
    several = len(pairs) > 1
    mode = "defer" if several else "all"
    findings: list[LocalFinding] = []
    for agent_id, agent_files in pairs:
        findings.extend(
            run_m_probes(
                project_dir,
                agent_files,
                agent=agent_id,
                scoped=scoped,
                project_checks=mode,
                skills=skills,
                exclusions=exclusions,
            )
        )
    if several:
        findings.extend(_project_wide_findings(project_dir, pairs, scoped=scoped, skills=skills, exclusions=exclusions))
    return findings


def run_content_quality_checks(
    ruleset_map: object,
    project_dir: Path,
    instruction_files: list[Path] | None = None,
    agent: str = "",
    exclusions: RunExclusions | None = None,
) -> list[LocalFinding]:
    """Run content-quality checks (type=content_query) against RulesetMap atoms.

    Atom queries are dispatched against files matching each rule's `match`
    field, using classified file properties from the agent config.
    """
    if not isinstance(ruleset_map, RulesetMap):
        return []

    scan_dir = project_dir if project_dir.is_dir() else project_dir.parent
    rules = load_rules(project_root=project_dir, scan_root=scan_dir, agent=agent)

    # Classify files so content_checker can respect rule.match targeting
    classified: list[Any] = []
    if instruction_files:
        classified, _ = _classify_agent_files(
            project_dir, instruction_files, agent, skill_membership(ruleset_map), exclusions
        )

    return run_content_checks(ruleset_map, rules, classified)
