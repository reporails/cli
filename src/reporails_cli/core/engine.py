"""Validation engine - orchestration only, no domain logic.

Coordinates other modules to run validation. Target: <200 lines.
"""

from __future__ import annotations

import contextlib
import time
from pathlib import Path

from reporails_cli.bundled import get_capability_patterns_path
from reporails_cli.core.applicability import detect_features_filesystem, get_applicable_rules
from reporails_cli.core.bootstrap import (
    get_agent_vars,
    get_opengrep_bin,
    get_package_level_rules,
    get_project_config,
    is_initialized,
)
from reporails_cli.core.cache import ProjectCache, content_hash, record_scan
from reporails_cli.core.capability import (
    detect_features_content,
    determine_capability_level,
)
from reporails_cli.core.discover import generate_backbone_placeholder, save_backbone
from reporails_cli.core.init import run_init
from reporails_cli.core.models import (
    PendingSemantic,
    Rule,
    RuleType,
    SkippedExperimental,
    ValidationResult,
    Violation,
)
from reporails_cli.core.opengrep import get_rule_yml_paths, run_opengrep
from reporails_cli.core.registry import get_experimental_rules, load_rules
from reporails_cli.core.sarif import dedupe_violations, parse_sarif
from reporails_cli.core.scorer import calculate_score, estimate_friction
from reporails_cli.core.semantic import build_semantic_requests


def run_validation(
    target: Path,
    rules: dict[str, Rule] | None = None,
    opengrep_path: Path | None = None,
    rules_dir: Path | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
    agent: str = "",
    include_experimental: bool = False,
) -> ValidationResult:
    """Run full validation on target directory.

    Two-pass approach:
    1. Capability detection (small pattern set) → determines final level
    2. Rule validation (filtered by final level) → violations + score

    Args:
        target: Directory or file to validate
        rules: Pre-loaded rules (optional, loads from rules_dir if not provided)
        opengrep_path: Path to OpenGrep binary (optional, auto-detects)
        rules_dir: Directory containing rules (optional)
        use_cache: Whether to use cached results
        record_analytics: Whether to record scan analytics
        agent: Agent identifier for loading template vars (empty = no agent-specific vars)
    """
    start_time = time.perf_counter()
    project_root = target.parent if target.is_file() else target

    # Auto-init if needed
    if not is_initialized():
        run_init()
    if opengrep_path is None:
        opengrep_path = get_opengrep_bin()

    # Auto-create backbone placeholder if missing
    backbone_path = project_root / ".reporails" / "backbone.yml"
    if not backbone_path.exists():
        save_backbone(project_root, generate_backbone_placeholder())

    # Get template vars from agent config for yml placeholder resolution
    template_context = get_agent_vars(agent) if agent else {}

    # Load rules if not provided
    if rules is None:
        rules = load_rules(rules_dir, include_experimental=include_experimental, project_root=project_root, agent=agent)

    # Track skipped experimental rules (for display when not included)
    skipped_experimental = None
    if not include_experimental:
        exp_rules = get_experimental_rules(rules_dir)
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
    capability_patterns = get_capability_patterns_path()
    capability_sarif = {}
    if capability_patterns.exists():
        capability_sarif = run_opengrep(
            [capability_patterns], target, opengrep_path, template_context
        )

    content_features = detect_features_content(capability_sarif)

    # Determine FINAL capability level (filesystem + content)
    capability = determine_capability_level(features, content_features)
    final_level = capability.level

    # =========================================================================
    # PASS 2: Rule Validation (filtered by final level)
    # =========================================================================

    # Load package level mappings for applicability filtering
    config = get_project_config(project_root) if project_root else None
    package_level_rules = (
        get_package_level_rules(project_root, config.packages)
        if config and config.packages
        else {}
    )

    # Filter rules by FINAL level - this ensures scoring matches displayed level
    applicable_rules = get_applicable_rules(rules, final_level, extra_level_rules=package_level_rules or None)

    # Run OpenGrep on applicable rules only
    rule_yml_paths = get_rule_yml_paths(applicable_rules)
    rule_sarif = {}
    if rule_yml_paths:
        rule_sarif = run_opengrep(
            rule_yml_paths, target, opengrep_path, template_context
        )

    # Split by type
    deterministic = {k: v for k, v in applicable_rules.items() if v.type == RuleType.DETERMINISTIC}
    semantic = {k: v for k, v in applicable_rules.items() if v.type == RuleType.SEMANTIC}

    # Parse violations from rule SARIF (only deterministic rules)
    violations = parse_sarif(rule_sarif, deterministic)

    # Build semantic requests from rule SARIF (only semantic rules)
    judgment_requests = build_semantic_requests(rule_sarif, semantic, project_root)

    # =========================================================================
    # Semantic Cache: filter already-evaluated judgments
    # =========================================================================

    if judgment_requests and use_cache:
        cache = ProjectCache(project_root)
        filtered_requests = []
        for jr in judgment_requests:
            file_path = jr.location.rsplit(":", 1)[0] if ":" in jr.location else jr.location
            try:
                file_hash = content_hash(project_root / file_path)
            except OSError:
                filtered_requests.append(jr)
                continue

            cached = cache.get_cached_judgment(file_path, file_hash)
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
        friction=friction,
        is_partial=bool(judgment_requests),  # Partial if semantic rules pending
        pending_semantic=pending_semantic,
        skipped_experimental=skipped_experimental,
    )


def run_validation_sync(
    target: Path,
    rules: dict[str, Rule] | None = None,
    opengrep_path: Path | None = None,
    rules_dir: Path | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
    agent: str = "",
    checks_dir: Path | None = None,  # Legacy alias
    include_experimental: bool = False,
) -> ValidationResult:
    """Legacy alias for run_validation (now sync)."""
    # Support legacy checks_dir parameter
    if checks_dir is not None and rules_dir is None:
        rules_dir = checks_dir
    return run_validation(
        target, rules, opengrep_path, rules_dir, use_cache,
        record_analytics, agent, include_experimental
    )
