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
from pathlib import Path
from typing import Any

from reporails_cli.core.models import LocalFinding, Rule, RuleType

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def _collect_mechanical_findings(
    rules: dict[str, Rule],
    project_dir: Path,
    classified: list[Any],
) -> list[LocalFinding]:
    """Run mechanical checks and convert Violations to LocalFinding."""
    from reporails_cli.core.mechanical.runner import run_mechanical_checks
    from reporails_cli.core.models import Execution

    mechanical_rules = {
        k: v for k, v in rules.items() if v.type == RuleType.MECHANICAL and v.execution == Execution.LOCAL
    }
    findings: list[LocalFinding] = []
    for v in run_mechanical_checks(mechanical_rules, project_dir, classified):
        file_path = v.location.rsplit(":", 1)[0] if ":" in v.location else v.location
        line = 0
        if ":" in v.location:
            with contextlib.suppress(ValueError):
                line = int(v.location.rsplit(":", 1)[1])
        findings.append(
            LocalFinding(
                file=file_path,
                line=line,
                severity=v.severity.value,
                rule=v.rule_id,
                message=v.message,
                source="m_probe",
                check_id=v.check_id or "",
            )
        )
    return findings


def _group_rules_by_match_type(
    rules: dict[str, Rule],
) -> dict[str | None, dict[str, Rule]]:
    """Group deterministic rules by their match.type for targeted file scanning."""
    groups: dict[str | None, dict[str, Rule]] = {}
    for rid, r in rules.items():
        if r.type != RuleType.DETERMINISTIC:
            continue
        match_type = None
        if r.match and r.match.type:
            match_type = r.match.type if isinstance(r.match.type, str) else None
        groups.setdefault(match_type, {})[rid] = r
    return groups


def _collect_deterministic_findings(
    rules: dict[str, Rule],
    project_dir: Path,
    instruction_files: list[Path],
    classified: list[Any],
) -> list[LocalFinding]:
    """Run deterministic checks grouped by match type."""
    from reporails_cli.core.regex import get_checks_paths, run_checks

    files_by_type: dict[str, list[Path]] = {}
    for cf in classified:
        files_by_type.setdefault(cf.file_type, []).append(cf.path)

    findings: list[LocalFinding] = []
    for match_type, group_rules in _group_rules_by_match_type(rules).items():
        yml_paths = get_checks_paths(group_rules)
        if not yml_paths:
            continue
        target_files = instruction_files if match_type is None else files_by_type.get(match_type, [])
        if not target_files:
            continue
        findings.extend(run_checks(yml_paths, project_dir, instruction_files=target_files))
    return findings


def run_m_probes(
    project_dir: Path,
    instruction_files: list[Path],
    agent: str = "",
) -> list[LocalFinding]:
    """Run M-probe checks (mechanical + deterministic) against instruction files."""
    from reporails_cli.core.classification import classify_files, load_file_types
    from reporails_cli.core.registry import load_rules

    rules = load_rules(project_root=project_dir, scan_root=project_dir, agent=agent)
    file_types = load_file_types(agent or "generic")
    classified = classify_files(project_dir, instruction_files, file_types)

    findings: list[LocalFinding] = []
    findings.extend(_collect_mechanical_findings(rules, project_dir, classified))
    findings.extend(_collect_deterministic_findings(rules, project_dir, instruction_files, classified))

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.line))
    return findings


def run_content_quality_checks(
    ruleset_map: object,
    project_dir: Path,
    instruction_files: list[Path] | None = None,
    agent: str = "",
) -> list[LocalFinding]:
    """Run content-quality checks (type=content_query) against RulesetMap atoms.

    Atom queries are dispatched against files matching each rule's `match`
    field, using classified file properties from the agent config.
    """
    from reporails_cli.core.classification import classify_files, load_file_types
    from reporails_cli.core.content_checker import run_content_checks
    from reporails_cli.core.mapper.mapper import RulesetMap as _RulesetMap
    from reporails_cli.core.registry import load_rules

    if not isinstance(ruleset_map, _RulesetMap):
        return []

    rules = load_rules(project_root=project_dir, scan_root=project_dir, agent=agent)

    # Classify files so content_checker can respect rule.match targeting
    classified = []
    if instruction_files:
        file_types = load_file_types(agent or "generic")
        classified = classify_files(project_dir, instruction_files, file_types)

    return run_content_checks(ruleset_map, rules, classified)
