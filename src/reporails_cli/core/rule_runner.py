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

from reporails_cli.core.models import LocalFinding, Rule, RuleType

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def run_m_probes(
    project_dir: Path,
    instruction_files: list[Path],
    agent: str = "",
) -> list[LocalFinding]:
    """Run M-probe checks (mechanical + deterministic) against instruction files."""
    from reporails_cli.core.classification import classify_files, load_file_types
    from reporails_cli.core.mechanical.runner import run_mechanical_checks
    from reporails_cli.core.regex import get_checks_paths, run_checks
    from reporails_cli.core.registry import load_rules

    rules = load_rules(project_root=project_dir, scan_root=project_dir, agent=agent)

    # Classify files for mechanical check targeting
    file_types = load_file_types(agent or "generic")
    classified = classify_files(project_dir, instruction_files, file_types)

    findings: list[LocalFinding] = []

    # Run mechanical checks -> Violation objects -> convert to LocalFinding
    # Skip server-execution rules — they have no local checks
    from reporails_cli.core.models import Execution

    mechanical_rules = {
        k: v for k, v in rules.items() if v.type == RuleType.MECHANICAL and v.execution == Execution.LOCAL
    }
    mech_violations = run_mechanical_checks(mechanical_rules, project_dir, classified)
    for v in mech_violations:
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

    # Run deterministic checks — group by match.type so each rule only
    # targets files of the correct type (e.g., scoped_rule rules skip CLAUDE.md)
    det_rules = {rid: r for rid, r in rules.items() if r.type == RuleType.DETERMINISTIC}

    # Build file lists per match type from classified files
    files_by_type: dict[str, list[Path]] = {}
    for cf in classified:
        files_by_type.setdefault(cf.file_type, []).append(cf.path)

    # Group rules by their match.type (None = wildcard, targets all files)
    rules_by_target: dict[str | None, dict[str, Rule]] = {}
    for rid, r in det_rules.items():
        match_type = None
        if r.match and r.match.type:
            match_type = r.match.type if isinstance(r.match.type, str) else None
        rules_by_target.setdefault(match_type, {})[rid] = r

    for match_type, group_rules in rules_by_target.items():
        yml_paths = get_checks_paths(group_rules)
        if not yml_paths:
            continue

        target_files = instruction_files if match_type is None else files_by_type.get(match_type, [])

        if not target_files:
            continue

        det_findings = run_checks(
            yml_paths,
            project_dir,
            instruction_files=target_files,
        )
        findings.extend(det_findings)

    # Sort by severity then line number
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
