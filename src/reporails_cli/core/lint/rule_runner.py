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

from reporails_cli.core.platform.dto.models import LocalFinding, Rule, RuleType

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def _to_display_severity(raw: str) -> str:
    """Normalize a Severity enum value to the display vocabulary.

    `Rule.severity` and `Check.severity` carry the SARIF-adjacent
    `critical`/`high`/`medium`/`low`/`info` vocabulary; the merger and
    text formatters only count `error`/`warning`/`info`. Mirrors the
    translation already applied to deterministic regex findings in
    `core/lint/regex/compiler.py`.
    """
    if raw in ("error", "critical", "high"):
        return "error"
    if raw == "info":
        return "info"
    return "warning"


def _collect_mechanical_findings(
    rules: dict[str, Rule],
    project_dir: Path,
    classified: list[Any],
) -> list[LocalFinding]:
    """Run mechanical checks and convert Violations to LocalFinding."""
    from reporails_cli.core.lint.mechanical.runner import run_mechanical_checks
    from reporails_cli.core.platform.dto.models import Execution

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
                severity=_to_display_severity(v.severity.value),
                rule=v.rule_id,
                message=v.message,
                source="m_probe",
                check_id=v.check_id or "",
            )
        )
    return findings


def _has_deterministic_checks(rule: Rule) -> bool:
    """Return True if the rule contains at least one deterministic check."""
    return any(c.type == "deterministic" for c in rule.checks)


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
    from reporails_cli.core.classify import match_files
    from reporails_cli.core.lint.regex import run_checks
    from reporails_cli.core.platform.config.config import get_project_config

    try:
        project_config = get_project_config(project_dir)
        thresholds = project_config.rule_thresholds
    except (OSError, ValueError):
        thresholds = {}
    min_lines_overrides: dict[str, int] = {}
    for rule_id, args in thresholds.items():
        ml = args.get("min_lines")
        if isinstance(ml, int):
            min_lines_overrides[rule_id] = ml

    findings: list[LocalFinding] = []
    for rule in rules.values():
        if rule.type != RuleType.DETERMINISTIC and not _has_deterministic_checks(rule):
            continue
        if not rule.yml_path or not rule.yml_path.exists():
            continue

        # Resolve target files: match criteria → classified files, or all instruction files
        if rule.match:
            matched = match_files(classified, rule.match)
            target_files = [cf.path for cf in matched]
        else:
            target_files = instruction_files

        if not target_files:
            continue

        findings.extend(
            run_checks(
                [rule.yml_path],
                project_dir,
                instruction_files=target_files,
                min_lines_overrides=min_lines_overrides,
            )
        )
    return findings


def run_m_probes(
    project_dir: Path,
    instruction_files: list[Path],
    agent: str = "",
) -> list[LocalFinding]:
    """Run M-probe checks (mechanical + deterministic) against instruction files."""
    from reporails_cli.core.classify import classify_files, load_file_types
    from reporails_cli.core.platform.adapters.registry import load_rules
    from reporails_cli.core.platform.config.config import get_project_config

    rules = load_rules(project_root=project_dir, scan_root=project_dir, agent=agent)
    file_types = load_file_types(agent or "generic")
    try:
        generic_scanning = get_project_config(project_dir).generic_scanning
    except (OSError, ValueError):
        generic_scanning = False
    classified = classify_files(project_dir, instruction_files, file_types, generic_scanning=generic_scanning)
    # Extend instruction_files with link-walked generic-class files so
    # downstream rules without explicit `match` still see them.
    effective_files = list(instruction_files)
    if generic_scanning:
        known = set(effective_files)
        for cf in classified:
            if cf.path not in known and cf.file_type == "generic":
                effective_files.append(cf.path)
                known.add(cf.path)

    findings: list[LocalFinding] = []
    findings.extend(_collect_mechanical_findings(rules, project_dir, classified))
    findings.extend(_collect_deterministic_findings(rules, project_dir, effective_files, classified))

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
    from reporails_cli.core.classify import classify_files, load_file_types
    from reporails_cli.core.lint.content_checker import run_content_checks
    from reporails_cli.core.platform.adapters.registry import load_rules
    from reporails_cli.core.platform.config.config import get_project_config
    from reporails_cli.core.platform.dto.ruleset import RulesetMap as _RulesetMap

    if not isinstance(ruleset_map, _RulesetMap):
        return []

    rules = load_rules(project_root=project_dir, scan_root=project_dir, agent=agent)

    # Classify files so content_checker can respect rule.match targeting
    classified = []
    if instruction_files:
        file_types = load_file_types(agent or "generic")
        try:
            generic_scanning = get_project_config(project_dir).generic_scanning
        except (OSError, ValueError):
            generic_scanning = False
        classified = classify_files(project_dir, instruction_files, file_types, generic_scanning=generic_scanning)

    return run_content_checks(ruleset_map, rules, classified)
