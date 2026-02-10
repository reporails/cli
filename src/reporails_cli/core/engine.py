"""Validation engine - orchestration only, no domain logic.

Coordinates other modules to run validation. Target: <200 lines.
"""

from __future__ import annotations

import contextlib
import time
from pathlib import Path

from reporails_cli.bundled import get_capability_patterns_path
from reporails_cli.core.agents import get_all_instruction_files
from reporails_cli.core.applicability import detect_features_filesystem, get_applicable_rules
from reporails_cli.core.bootstrap import (
    get_agent_vars,
    get_opengrep_bin,
    is_initialized,
)
from reporails_cli.core.cache import ProjectCache, content_hash, record_scan
from reporails_cli.core.capability import (
    detect_features_content,
    determine_capability_level,
)
from reporails_cli.core.init import run_init
from reporails_cli.core.mechanical import run_mechanical_checks
from reporails_cli.core.models import (
    Category,
    CategoryStats,
    PendingSemantic,
    Rule,
    RuleType,
    Severity,
    SkippedExperimental,
    ValidationResult,
    Violation,
)
from reporails_cli.core.opengrep import get_rule_yml_paths, run_opengrep
from reporails_cli.core.registry import get_experimental_rules, load_rules
from reporails_cli.core.sarif import dedupe_violations, parse_sarif
from reporails_cli.core.scorer import calculate_score, estimate_friction
from reporails_cli.core.semantic import build_semantic_requests


def _find_project_root(target: Path) -> Path:
    """Walk up from target to find the project root.

    Prefers a coordination backbone (.reporails/backbone.yml with children
    or repos keys) as the definitive root — this handles monorepos where
    child directories have their own .git. Falls back to nearest .git,
    then to target itself.
    """
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
    "S": "Structure", "C": "Content", "E": "Efficiency",
    "M": "Maintenance", "G": "Governance",
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
        stats.append(CategoryStats(
            code=code,
            name=_CATEGORY_NAMES[code],
            total=total,
            passed=total - fail_count,
            failed=fail_count,
            worst_severity=worst[code].value if code in worst else None,
        ))
    return tuple(stats)


def run_validation(
    target: Path,
    rules: dict[str, Rule] | None = None,
    opengrep_path: Path | None = None,
    rules_paths: list[Path] | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
    agent: str = "",
    include_experimental: bool = False,
    exclude_dirs: list[str] | None = None,
) -> ValidationResult:
    """Run full validation on target directory.

    Two-pass approach:
    1. Capability detection (small pattern set) → determines final level
    2. Rule validation (filtered by final level) → violations + score

    Args:
        target: Directory or file to validate
        rules: Pre-loaded rules (optional, loads from rules_paths if not provided)
        opengrep_path: Path to OpenGrep binary (optional, auto-detects)
        rules_paths: Directories containing rules (first = primary framework)
        use_cache: Whether to use cached results
        record_analytics: Whether to record scan analytics
        agent: Agent identifier for loading template vars (empty = no agent-specific vars)
        include_experimental: Include experimental-tier rules
        exclude_dirs: Directory names to exclude from scanning
    """
    start_time = time.perf_counter()
    scan_root = target.parent if target.is_file() else target
    project_root = _find_project_root(scan_root)

    # Auto-init if needed
    if not is_initialized():
        run_init()
    if opengrep_path is None:
        opengrep_path = get_opengrep_bin()

    # Get template vars from agent config for yml placeholder resolution
    template_context = get_agent_vars(agent) if agent else {}

    # Load rules if not provided
    if rules is None:
        rules = load_rules(rules_paths, include_experimental=include_experimental, project_root=project_root, agent=agent, scan_root=scan_root)

    # Track skipped experimental rules (for display when not included)
    skipped_experimental = None
    if not include_experimental:
        exp_rules = get_experimental_rules(rules_paths[0] if rules_paths else None)
        if exp_rules:
            skipped_experimental = SkippedExperimental(
                rule_count=len(exp_rules),
                rules=tuple(sorted(exp_rules.keys())),
            )

    # =========================================================================
    # PASS 1: Capability Detection (determines final level)
    # =========================================================================

    # Filesystem feature detection (fast)
    features = detect_features_filesystem(project_root)

    # Content feature detection via OpenGrep (capability patterns only)
    extra_targets = features.resolved_symlinks or None

    # Project-scoped instruction files for capability detection
    project_instruction_files = get_all_instruction_files(project_root) or None
    if project_instruction_files and extra_targets:
        # Merge resolved symlinks into instruction files (deduped in runner)
        project_instruction_files = list(project_instruction_files) + list(extra_targets)

    capability_patterns = get_capability_patterns_path()
    capability_sarif = {}
    if capability_patterns.exists():
        capability_sarif = run_opengrep(
            [capability_patterns], project_root, opengrep_path, template_context,
            extra_targets=extra_targets,
            instruction_files=project_instruction_files,
        )

    content_features = detect_features_content(capability_sarif)

    # Determine FINAL capability level (filesystem + content)
    capability = determine_capability_level(features, content_features)
    final_level = capability.level

    # =========================================================================
    # PASS 2: Rule Validation (filtered by final level)
    # =========================================================================

    # Filter rules by FINAL level — rule.level ≤ project_level
    applicable_rules = get_applicable_rules(rules, final_level)

    # Target-scoped instruction files for rule validation
    target_instruction_files = get_all_instruction_files(scan_root) or None
    if target_instruction_files and exclude_dirs:
        exclude_set = set(exclude_dirs)
        target_instruction_files = [
            f for f in target_instruction_files
            if not (exclude_set & set(f.relative_to(scan_root).parts))
        ]
    if target_instruction_files and extra_targets:
        target_instruction_files = list(target_instruction_files) + list(extra_targets)

    # Run mechanical checks from ALL rules (runner filters by check.type).
    # Rule.type is a dispatch ceiling, not a bucket: deterministic and semantic
    # rules can contain mechanical checks that run before their other gates.
    violations: list[Violation] = run_mechanical_checks(
        applicable_rules, scan_root, template_context,
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
            rule_yml_paths, scan_root, opengrep_path, template_context,
            extra_targets=extra_targets,
            instruction_files=target_instruction_files,
            exclude_dirs=exclude_dirs,
        )

    # Parse violations from deterministic rule SARIF
    det_violations = parse_sarif(rule_sarif, deterministic)

    # Handle negated deterministic checks:
    # - finding exists → PASS (content present, remove from violations)
    # - no finding → FAIL (content missing, add violation)
    negated_check_ids: set[str] = set()
    for rule in deterministic.values():
        for check in rule.checks:
            if check.negate:
                negated_check_ids.add(check.id)

    if negated_check_ids:
        # Track which negated check IDs had findings (= pass)
        # Scope match by rule_id to avoid cross-rule collisions (check:0001 is common)
        negated_with_findings: set[str] = set()
        for v in det_violations:
            if v.check_id:
                for nid in negated_check_ids:
                    if nid.startswith(v.rule_id + ":") and nid.endswith(v.check_id):
                        negated_with_findings.add(nid)

        # Remove false violations from negated checks that found content
        filtered: list[Violation] = []
        for v in det_violations:
            is_negated = False
            if v.check_id:
                for nid in negated_check_ids:
                    if nid.startswith(v.rule_id + ":") and nid.endswith(v.check_id):
                        is_negated = True
                        break
            if not is_negated:
                filtered.append(v)
        det_violations = filtered

        # Add violations for negated checks with NO findings (content missing)
        for rule in deterministic.values():
            for check in rule.checks:
                if check.negate and check.id not in negated_with_findings:
                    # Resolve template in targets for display (e.g. {{instruction_files}} → **/CLAUDE.md)
                    display_target = rule.targets
                    if "{{" in display_target and template_context:
                        for key, val in template_context.items():
                            placeholder = "{{" + key + "}}"
                            if placeholder in display_target:
                                resolved = ", ".join(val) if isinstance(val, list) else str(val)
                                display_target = display_target.replace(placeholder, resolved)
                    det_violations.append(Violation(
                        rule_id=rule.id,
                        rule_title=rule.title,
                        location=f"{display_target}:0",
                        message="Expected content not found",
                        severity=check.severity,
                        check_id=check.id.split(":")[-1] if ":" in check.id else None,
                    ))

    violations.extend(det_violations)

    # Build semantic requests from semantic rule SARIF
    judgment_requests = build_semantic_requests(rule_sarif, semantic, scan_root)

    # =========================================================================
    # Semantic Cache: filter already-evaluated judgments
    # =========================================================================

    if judgment_requests and use_cache:
        cache = ProjectCache(project_root)
        filtered_requests = []
        for jr in judgment_requests:
            raw_path = jr.location.rsplit(":", 1)[0] if ":" in jr.location else jr.location
            # Normalize to relative path for cache key consistency
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
                # Cached fail → convert to violation
                violations.append(Violation(
                    rule_id=jr.rule_id,
                    rule_title=jr.rule_title,
                    location=jr.location,
                    message=verdict.get("reason", f"Semantic rule {jr.rule_id} failed (cached)"),
                    severity=jr.severity,
                ))
            else:
                filtered_requests.append(jr)
        judgment_requests = filtered_requests

    # =========================================================================
    # Scoring (uses same rules that were filtered by final level)
    # =========================================================================

    unique_violations = dedupe_violations(violations)
    category_summary = _compute_category_summary(applicable_rules, unique_violations)
    score = calculate_score(len(applicable_rules), unique_violations)
    friction = estimate_friction(unique_violations)
    rules_failed = len({v.rule_id for v in unique_violations})

    # Record analytics
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    if record_analytics:
        with contextlib.suppress(OSError):
            record_scan(target, score, final_level.value, len(violations),
                        len(applicable_rules), elapsed_ms, features.instruction_file_count)

    # Build pending semantic summary
    pending_semantic = None
    if judgment_requests:
        unique_rules = sorted({jr.rule_id for jr in judgment_requests})
        unique_files = {jr.location.rsplit(":", 1)[0] for jr in judgment_requests}
        pending_semantic = PendingSemantic(
            rule_count=len(unique_rules),
            file_count=len(unique_files),
            rules=tuple(unique_rules),
        )

    return ValidationResult(
        score=score,
        level=final_level,
        violations=tuple(violations),
        judgment_requests=tuple(judgment_requests),
        rules_checked=len(applicable_rules),
        rules_passed=len(applicable_rules) - rules_failed,
        rules_failed=rules_failed,
        feature_summary=capability.feature_summary,
        has_orphan_features=capability.has_orphan_features,
        friction=friction,
        category_summary=category_summary,
        is_partial=bool(judgment_requests),  # Partial if semantic rules pending
        pending_semantic=pending_semantic,
        skipped_experimental=skipped_experimental,
    )


def run_validation_sync(
    target: Path,
    rules: dict[str, Rule] | None = None,
    opengrep_path: Path | None = None,
    rules_paths: list[Path] | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
    agent: str = "",
    include_experimental: bool = False,
    exclude_dirs: list[str] | None = None,
) -> ValidationResult:
    """Synchronous entry point for run_validation."""
    return run_validation(
        target, rules, opengrep_path, rules_paths, use_cache,
        record_analytics, agent, include_experimental, exclude_dirs,
    )
