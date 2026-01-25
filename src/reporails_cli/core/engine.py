"""Validation engine - orchestration only, no domain logic.

Coordinates other modules to run validation. Target: <100 lines.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from pathlib import Path

from reporails_cli.core.applicability import detect_features_filesystem, get_applicable_rules
from reporails_cli.core.bootstrap import get_agent_vars, get_opengrep_bin, is_initialized
from reporails_cli.core.cache import record_scan
from reporails_cli.core.capability import (
    detect_features_content,
    determine_capability_level,
    estimate_preliminary_level,
)
from reporails_cli.core.discover import generate_backbone_yaml, run_discovery, save_backbone
from reporails_cli.core.init import run_init
from reporails_cli.core.models import PendingSemantic, Rule, RuleType, ValidationResult
from reporails_cli.bundled import get_capability_patterns_path
from reporails_cli.core.opengrep import get_rule_yml_paths, run_opengrep
from reporails_cli.core.registry import load_rules
from reporails_cli.core.sarif import dedupe_violations, parse_sarif
from reporails_cli.core.scorer import calculate_score, estimate_friction
from reporails_cli.core.semantic import build_semantic_requests


async def run_validation(
    target: Path,
    rules: dict[str, Rule] | None = None,
    opengrep_path: Path | None = None,
    rules_dir: Path | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
    agent: str = "",
) -> ValidationResult:
    """Run full validation on target directory.

    Orchestrates: features → rules → OpenGrep → violations → score.

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

    # Auto-create backbone if missing
    backbone_path = project_root / ".reporails" / "backbone.yml"
    if not backbone_path.exists():
        save_backbone(project_root, generate_backbone_yaml(run_discovery(project_root)))

    # Phase 1: Filesystem feature detection
    features = detect_features_filesystem(project_root)

    # Get template vars from agent config for yml placeholder resolution
    template_context = get_agent_vars(agent) if agent else {}

    # Load rules if not provided
    if rules is None:
        rules = load_rules(rules_dir)

    # Estimate preliminary level from filesystem features (for early rule filtering)
    # This avoids running unnecessary rules - major performance optimization
    prelim_level = estimate_preliminary_level(features)
    prelim_applicable_rules = get_applicable_rules(rules, prelim_level)

    # Collect yml paths: capability patterns + only applicable rules
    all_yml_paths: list[Path] = []

    # Add capability detection patterns
    capability_patterns = get_capability_patterns_path()
    if capability_patterns.exists():
        all_yml_paths.append(capability_patterns)

    # Add only applicable rule yml paths (filtered by preliminary level)
    all_yml_paths.extend(get_rule_yml_paths(prelim_applicable_rules))

    # Run single consolidated OpenGrep invocation with filtered rules
    combined_sarif = await run_opengrep(
        all_yml_paths, target, opengrep_path, template_context
    ) if all_yml_paths else {"runs": []}

    # Phase 2: Content feature detection (from combined SARIF)
    content_features = detect_features_content(combined_sarif)

    # Determine final capability level (may be higher than preliminary)
    capability = determine_capability_level(features, content_features)

    # Use preliminary level for scoring (we only ran those rules)
    # Note: final level is displayed but scoring uses prelim rules
    applicable_rules = prelim_applicable_rules

    # Split by type
    deterministic = {k: v for k, v in applicable_rules.items() if v.type == RuleType.DETERMINISTIC}
    semantic = {k: v for k, v in applicable_rules.items() if v.type == RuleType.SEMANTIC}

    # Parse violations from combined SARIF (only deterministic rules)
    violations = parse_sarif(combined_sarif, deterministic)

    # Build semantic requests from combined SARIF (only semantic rules)
    judgment_requests = build_semantic_requests(combined_sarif, semantic, project_root)

    # Calculate score and friction
    unique_violations = dedupe_violations(violations)
    score = calculate_score(len(applicable_rules), unique_violations)
    friction = estimate_friction(unique_violations)
    rules_failed = len({v.rule_id for v in unique_violations})

    # Record analytics
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    if record_analytics:
        with contextlib.suppress(OSError):
            record_scan(target, score, capability.level.value, len(violations),
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
        level=capability.level,
        violations=tuple(violations),
        judgment_requests=tuple(judgment_requests),
        rules_checked=len(applicable_rules),
        rules_passed=len(applicable_rules) - rules_failed,
        rules_failed=rules_failed,
        feature_summary=capability.feature_summary,
        friction=friction,
        is_partial=bool(judgment_requests),  # Partial if semantic rules pending
        pending_semantic=pending_semantic,
        time_waste_estimate=friction.by_category,
        violation_points=sum(-2 for _ in unique_violations),  # Legacy
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
) -> ValidationResult:
    """Synchronous wrapper for run_validation."""
    # Support legacy checks_dir parameter
    if checks_dir is not None and rules_dir is None:
        rules_dir = checks_dir
    return asyncio.run(run_validation(target, rules, opengrep_path, rules_dir, use_cache, record_analytics, agent))
