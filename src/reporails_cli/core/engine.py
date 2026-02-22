"""Validation engine - orchestration only, no domain logic.

Coordinates other modules to run validation. Helpers in engine_helpers.py.
"""

from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import Callable
from pathlib import Path

from reporails_cli.core.agents import (
    clear_agent_cache,
    detect_agents,
    filter_agents_by_exclude_dirs,
    get_all_instruction_files,
    get_all_scannable_files,
)
from reporails_cli.core.applicability import detect_features_filesystem, get_applicable_rules
from reporails_cli.core.bootstrap import (
    get_agent_vars,
    is_initialized,
)
from reporails_cli.core.cache import record_scan
from reporails_cli.core.engine_helpers import (
    _compute_category_summary as _compute_category_summary,
)
from reporails_cli.core.engine_helpers import (
    _detect_capabilities as _detect_capabilities,
)
from reporails_cli.core.engine_helpers import (
    _filter_cached_judgments as _filter_cached_judgments,
)
from reporails_cli.core.engine_helpers import (
    _filter_dismissed_violations as _filter_dismissed_violations,
)
from reporails_cli.core.engine_helpers import (
    _find_project_root as _find_project_root,
)
from reporails_cli.core.engine_helpers import (
    _run_rule_validation as _run_rule_validation,
)
from reporails_cli.core.init import run_init
from reporails_cli.core.models import (
    PendingSemantic,
    Rule,
    SkippedExperimental,
    ValidationResult,
)
from reporails_cli.core.registry import clear_rule_cache, get_experimental_rules, load_rules
from reporails_cli.core.sarif import dedupe_violations
from reporails_cli.core.scorer import calculate_score, estimate_friction

ProgressCallback = Callable[[str, int, int], None]

logger = logging.getLogger(__name__)


def build_template_context(
    agent: str,
    instruction_files: list[Path],
    rules_paths: list[Path] | None = None,
) -> dict[str, str | list[str]]:
    """Build template context for rule placeholder resolution.

    With an agent: loads vars from agent config (e.g., claude → CLAUDE.md patterns).
    Without an agent: derives minimal vars from detected instruction files so
    core rules can resolve {{instruction_files}} and {{main_instruction_file}}.
    """
    if agent:
        vars = get_agent_vars(agent, rules_paths=rules_paths)
        if vars:
            return vars
        # Agent has no config.yml — fall through to file-based derivation
    # Derive from detected files so rules can resolve {{instruction_files}}
    rel_patterns = [f"**/{f.name}" for f in instruction_files]
    return {
        "instruction_files": rel_patterns,
        "main_instruction_file": rel_patterns[:1],
    }


def run_validation(  # pylint: disable=too-many-arguments,too-many-locals,too-many-statements
    target: Path,
    rules: dict[str, Rule] | None = None,
    rules_paths: list[Path] | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
    agent: str = "",
    include_experimental: bool = False,
    exclude_dirs: list[str] | None = None,
    on_progress: ProgressCallback | None = None,
) -> ValidationResult:
    """Run full validation: capability detection then rule validation."""
    start_time = time.perf_counter()
    _notify = on_progress or (lambda *_: None)
    _notify("Loading rules", 1, 3)
    scan_root = target.parent if target.is_file() else target
    project_root = _find_project_root(scan_root)

    # Clear file-discovery and rule caches when refresh requested
    if not use_cache:
        clear_agent_cache()
        clear_rule_cache()

    # Auto-init if needed (downloads rules framework)
    if not is_initialized():
        logger.info("Downloading rules framework...")
        run_init()

    # Detect agents once — reuse for all file lookups (avoids redundant recursive globs)
    # Use scan_root (not project_root) so only files inside the target are scanned
    all_agents = detect_agents(scan_root)

    # Resolve effective agent: explicit flag or generic default (agents.md convention)
    from reporails_cli.core.agents import filter_agents_by_id

    effective_agent = agent if agent else "generic"
    agents = filter_agents_by_id(all_agents, effective_agent)
    agents = filter_agents_by_exclude_dirs(agents, scan_root, exclude_dirs)

    instruction_files = get_all_instruction_files(scan_root, agents=agents)

    # Get template vars for yml placeholder resolution
    template_context = build_template_context(effective_agent, instruction_files, rules_paths)

    # Load rules if not provided
    if rules is None:
        rules = load_rules(
            rules_paths,
            include_experimental=include_experimental,
            project_root=project_root,
            agent=effective_agent,
            scan_root=scan_root,
        )

    # Track skipped experimental rules (for display when not included)
    skipped_experimental = None
    if not include_experimental:
        exp_rules = get_experimental_rules(rules_paths[0] if rules_paths else None)
        if exp_rules:
            skipped_experimental = SkippedExperimental(
                rule_count=len(exp_rules),
                rules=tuple(sorted(exp_rules.keys())),
            )

    _notify("Checking files", 2, 3)

    # PASS 1: Capability Detection (determines final level)
    features = detect_features_filesystem(scan_root, agents=agents)
    capability, extra_targets = _detect_capabilities(
        scan_root,
        template_context,
        features,
        instruction_files=instruction_files or None,
    )
    final_level = capability.level

    # Filter rules by FINAL level
    applicable_rules = get_applicable_rules(rules, final_level)

    # Target-scoped files for rule validation (includes config files for path-filtered rules)
    target_instruction_files = get_all_scannable_files(scan_root, agents=agents) or None
    if target_instruction_files and extra_targets:
        target_instruction_files = list(target_instruction_files) + list(extra_targets)

    # PASS 2: Rule Validation (mechanical + regex + semantic)
    violations, judgment_requests = _run_rule_validation(
        applicable_rules,
        scan_root,
        template_context,
        extra_targets,
        target_instruction_files,
        exclude_dirs,
    )

    # Semantic Cache: filter already-evaluated judgments
    judgment_requests, violations = _filter_cached_judgments(
        judgment_requests,
        violations,
        scan_root,
        project_root,
        use_cache,
    )

    # Dismissed violations: filter deterministic violations cached as 'pass'
    violations = _filter_dismissed_violations(violations, scan_root, project_root, use_cache)

    _notify("Scoring", 3, 3)

    # Scoring
    unique_violations = dedupe_violations(violations)
    category_summary = _compute_category_summary(applicable_rules, unique_violations)
    score = calculate_score(len(applicable_rules), unique_violations)
    friction = estimate_friction(unique_violations)
    rules_failed = len({v.rule_id for v in unique_violations})

    # Record analytics
    elapsed_ms = (time.perf_counter() - start_time) * 1000
    if record_analytics:
        with contextlib.suppress(OSError):
            record_scan(
                target,
                score,
                final_level.value,
                len(violations),
                len(applicable_rules),
                elapsed_ms,
                features.instruction_file_count,
            )

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
        violations=tuple(unique_violations),
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


def run_validation_sync(  # pylint: disable=too-many-arguments
    target: Path,
    rules: dict[str, Rule] | None = None,
    rules_paths: list[Path] | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
    agent: str = "",
    include_experimental: bool = False,
    exclude_dirs: list[str] | None = None,
    on_progress: ProgressCallback | None = None,
) -> ValidationResult:
    """Synchronous entry point for run_validation."""
    return run_validation(
        target,
        rules,
        rules_paths,
        use_cache,
        record_analytics,
        agent,
        include_experimental,
        exclude_dirs,
        on_progress,
    )
