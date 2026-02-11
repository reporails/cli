"""Engine helper functions and constants extracted from engine.py."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.bundled import get_capability_patterns_path
from reporails_cli.core.agents import get_all_instruction_files
from reporails_cli.core.cache import ProjectCache, content_hash
from reporails_cli.core.capability import detect_features_content, determine_capability_level
from reporails_cli.core.mechanical import run_mechanical_checks
from reporails_cli.core.models import (
    Category,
    CategoryStats,
    JudgmentRequest,
    Rule,
    RuleType,
    Severity,
    Violation,
)
from reporails_cli.core.opengrep import get_rule_yml_paths, run_opengrep
from reporails_cli.core.results import CapabilityResult, DetectedFeatures
from reporails_cli.core.sarif import parse_sarif
from reporails_cli.core.semantic import build_semantic_requests


def _find_project_root(target: Path) -> Path:
    """Walk up from target to find project root (backbone > .git > target)."""
    current = target if target.is_dir() else target.parent
    first_git = None
    while current != current.parent:
        if (current / ".git").exists() and first_git is None:
            first_git = current
        backbone = current / ".reporails" / "backbone.yml"
        if backbone.exists():
            try:
                text = backbone.read_text(encoding="utf-8")
                if "\nchildren:" in text or "\nrepos:" in text:
                    return current
            except OSError:
                pass
        current = current.parent
    return first_git or target


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# Category enum → single-letter display code
_CATEGORY_CODE: dict[Category, str] = {
    Category.STRUCTURE: "S",
    Category.CONTENT: "C",
    Category.EFFICIENCY: "E",
    Category.MAINTENANCE: "M",
    Category.GOVERNANCE: "G",
}

# Canonical display order
_CATEGORY_ORDER = ("S", "C", "E", "M", "G")

# Code → human name
_CATEGORY_NAMES = {
    "S": "Structure",
    "C": "Content",
    "E": "Efficiency",
    "M": "Maintenance",
    "G": "Governance",
}


def _compute_category_summary(
    applicable_rules: dict[str, Rule],
    unique_violations: list[Violation],
) -> tuple[CategoryStats, ...]:
    """Compute per-category stats from applicable rules and violations."""
    # Build rule_id → category code lookup from Rule.category enum
    rule_category: dict[str, str] = {}
    totals: dict[str, int] = {}
    for rule in applicable_rules.values():
        code = _CATEGORY_CODE.get(rule.category, "")
        if not code:
            continue
        rule_category[rule.id] = code
        totals[code] = totals.get(code, 0) + 1

    # Count failed rules and worst severity per category
    failed: dict[str, set[str]] = {}
    worst: dict[str, Severity] = {}
    for v in unique_violations:
        code = rule_category.get(v.rule_id, "")
        if not code:
            continue
        if code not in failed:
            failed[code] = set()
        failed[code].add(v.rule_id)
        if code not in worst or _SEVERITY_ORDER[v.severity] < _SEVERITY_ORDER[worst[code]]:
            worst[code] = v.severity

    stats = []
    for code in _CATEGORY_ORDER:
        total = totals.get(code, 0)
        fail_count = len(failed.get(code, set()))
        stats.append(
            CategoryStats(
                code=code,
                name=_CATEGORY_NAMES[code],
                total=total,
                passed=total - fail_count,
                failed=fail_count,
                worst_severity=worst[code].value if code in worst else None,
            )
        )
    return tuple(stats)


def _matches_negated(violation: Violation, negated_ids: set[str]) -> bool:
    """Check if a violation's check_id matches any negated check ID."""
    if not violation.check_id:
        return False
    return any(nid.startswith(violation.rule_id + ":") and nid.endswith(violation.check_id) for nid in negated_ids)


def _resolve_target_template(target: str, template_context: dict[str, str | list[str]]) -> str:
    """Resolve {{placeholder}} tokens in a target string."""
    if "{{" not in target or not template_context:
        return target
    for key, val in template_context.items():
        placeholder = "{{" + key + "}}"
        if placeholder in target:
            resolved = ", ".join(val) if isinstance(val, list) else str(val)
            target = target.replace(placeholder, resolved)
    return target


def _handle_negated_checks(
    deterministic: dict[str, Rule],
    det_violations: list[Violation],
    template_context: dict[str, str | list[str]],
) -> list[Violation]:
    """Invert match semantics for negated checks. Returns filtered+augmented list."""
    negated_check_ids: set[str] = {check.id for rule in deterministic.values() for check in rule.checks if check.negate}
    if not negated_check_ids:
        return det_violations

    # Track which negated check IDs had findings (= pass)
    negated_with_findings: set[str] = set()
    for v in det_violations:
        if _matches_negated(v, negated_check_ids):
            negated_with_findings |= {
                nid for nid in negated_check_ids if nid.startswith(v.rule_id + ":") and nid.endswith(v.check_id or "")
            }

    # Remove false violations from negated checks that found content
    det_violations = [v for v in det_violations if not _matches_negated(v, negated_check_ids)]

    # Add violations for negated checks with NO findings (content missing)
    for rule in deterministic.values():
        for check in rule.checks:
            if check.negate and check.id not in negated_with_findings:
                display_target = _resolve_target_template(rule.targets, template_context)
                det_violations.append(
                    Violation(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        location=f"{display_target}:0",
                        message="Expected content not found",
                        severity=check.severity,
                        check_id=check.id.split(":")[-1] if ":" in check.id else None,
                    )
                )

    return det_violations


def _detect_capabilities(
    project_root: Path,
    opengrep_path: Path,
    template_context: dict[str, str | list[str]],
    features: DetectedFeatures,
) -> tuple[CapabilityResult, list[Path] | None]:
    """Run PASS 1: capability detection and return (capability_result, extra_targets)."""
    extra_targets = features.resolved_symlinks or None

    # Project-scoped instruction files for capability detection
    project_instruction_files = get_all_instruction_files(project_root) or None
    if project_instruction_files and extra_targets:
        project_instruction_files = list(project_instruction_files) + list(extra_targets)

    capability_patterns = get_capability_patterns_path()
    capability_sarif: dict[str, object] = {}
    if capability_patterns.exists():
        capability_sarif = run_opengrep(
            [capability_patterns],
            project_root,
            opengrep_path,
            template_context,
            extra_targets=extra_targets,
            instruction_files=project_instruction_files,
        )

    content_features = detect_features_content(capability_sarif)
    capability = determine_capability_level(features, content_features)
    return capability, extra_targets


def _run_rule_validation(
    applicable_rules: dict[str, Rule],
    scan_root: Path,
    opengrep_path: Path,
    template_context: dict[str, str | list[str]],
    extra_targets: list[Path] | None,
    target_instruction_files: list[Path] | None,
    exclude_dirs: list[str] | None,
) -> tuple[list[Violation], list[JudgmentRequest]]:
    """Run PASS 2: mechanical checks + OpenGrep + negated checks + semantic requests."""
    violations: list[Violation] = run_mechanical_checks(
        applicable_rules,
        scan_root,
        template_context,
        instruction_files=target_instruction_files,
    )

    # Run OpenGrep on rules with .yml patterns (deterministic + semantic types)
    deterministic = {k: v for k, v in applicable_rules.items() if v.type == RuleType.DETERMINISTIC}
    semantic = {k: v for k, v in applicable_rules.items() if v.type == RuleType.SEMANTIC}
    opengrep_rules = {**deterministic, **semantic}
    rule_yml_paths = get_rule_yml_paths(opengrep_rules)
    rule_sarif: dict[str, object] = {}
    if rule_yml_paths:
        rule_sarif = run_opengrep(
            rule_yml_paths,
            scan_root,
            opengrep_path,
            template_context,
            extra_targets=extra_targets,
            instruction_files=target_instruction_files,
            exclude_dirs=exclude_dirs,
        )

    det_violations = parse_sarif(rule_sarif, deterministic)
    det_violations = _handle_negated_checks(deterministic, det_violations, template_context)
    violations.extend(det_violations)

    judgment_requests = build_semantic_requests(rule_sarif, semantic, scan_root)
    return violations, judgment_requests


def _filter_cached_judgments(
    judgment_requests: list[JudgmentRequest],
    violations: list[Violation],
    scan_root: Path,
    project_root: Path,
    use_cache: bool,
) -> tuple[list[JudgmentRequest], list[Violation]]:
    """Filter already-evaluated judgments from cache. Returns (remaining_requests, updated_violations)."""
    if not judgment_requests or not use_cache:
        return judgment_requests, violations

    cache = ProjectCache(project_root)
    filtered_requests: list[JudgmentRequest] = []
    for jr in judgment_requests:
        raw_path = jr.location.rsplit(":", 1)[0] if ":" in jr.location else jr.location
        try:
            rel_path = str(Path(raw_path).relative_to(scan_root))
        except ValueError:
            rel_path = raw_path
        try:
            file_hash = content_hash(scan_root / rel_path)
        except OSError:
            filtered_requests.append(jr)
            continue

        cached = cache.get_cached_judgment(rel_path, file_hash)
        if cached and jr.rule_id in cached:
            verdict = cached[jr.rule_id]
            if verdict.get("verdict") == jr.pass_value:
                continue  # Previously evaluated as pass — skip
            violations.append(
                Violation(
                    rule_id=jr.rule_id,
                    rule_title=jr.rule_title,
                    location=jr.location,
                    message=verdict.get("reason", f"Semantic rule {jr.rule_id} failed (cached)"),
                    severity=jr.severity,
                )
            )
        else:
            filtered_requests.append(jr)
    return filtered_requests, violations
