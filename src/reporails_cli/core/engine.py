"""Validation engine - orchestration only, no domain logic."""

from __future__ import annotations

import asyncio
import contextlib
import json
import subprocess
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from reporails_cli.core.applicability import (
    detect_features,
    get_applicable_rules,
    get_feature_summary,
)
from reporails_cli.core.bootstrap import get_opengrep_bin, is_initialized
from reporails_cli.core.cache import ProjectCache, record_scan
from reporails_cli.core.discover import generate_backbone_yaml, run_discovery, save_backbone
from reporails_cli.core.init import run_init
from reporails_cli.core.models import (
    JudgmentRequest,
    Rule,
    RuleType,
    Severity,
    ValidationResult,
    Violation,
)
from reporails_cli.core.registry import get_rule_yml_paths, get_rules_by_type, load_rules
from reporails_cli.core.scorer import (
    calculate_score,
    determine_capability_level,
    estimate_time_waste,
    get_severity_points,
)


async def run_validation(
    target: Path,
    rules: dict[str, Rule] | None = None,
    opengrep_path: Path | None = None,
    checks_dir: Path | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
) -> ValidationResult:
    """
    Run full validation on target directory.

    Orchestrates: load rules -> run OpenGrep -> parse results -> score.

    Args:
        target: Directory containing CLAUDE.md
        rules: Pre-loaded rules (optional)
        opengrep_path: Path to OpenGrep binary (optional, auto-detects)
        checks_dir: Directory containing check rules (optional, defaults to ~/.reporails/checks/)
        use_cache: Use cached file map (default True)
        record_analytics: Record scan to global analytics (default True)

    Returns:
        ValidationResult with violations, score, judgment_requests
    """
    start_time = time.perf_counter()

    # Normalize target: use parent directory if target is a file
    project_root = target.parent if target.is_file() else target

    # Auto-create backbone if missing
    backbone_path = project_root / ".reporails" / "backbone.yml"
    if not backbone_path.exists():
        discovery_result = run_discovery(project_root)
        backbone_yaml = generate_backbone_yaml(discovery_result)
        save_backbone(project_root, backbone_yaml)

    # Detect project features first
    features = detect_features(project_root)
    feature_summary = get_feature_summary(features)

    # Get applicable rules based on features
    applicable_rule_ids = get_applicable_rules(features)

    # Load all rules if not provided
    if rules is None:
        rules = load_rules(checks_dir)

    # Filter to only applicable rules
    applicable_rules = {
        rule_id: rule for rule_id, rule in rules.items() if rule_id in applicable_rule_ids
    }

    # Auto-install OpenGrep if not available
    if opengrep_path is None:
        if not is_initialized():
            run_init()  # Auto-download opengrep + rules on first run
        opengrep_path = get_opengrep_bin()

    # Use ProjectCache for file discovery
    cache = ProjectCache(project_root)
    claude_files: list[Path] | None = None

    # If target is a specific file, only check that file
    target_is_file = target.is_file()

    if use_cache and not target_is_file:
        claude_files = cache.get_cached_files()

    if claude_files is None:
        # Scan filesystem and cache results
        claude_files = _discover_instruction_files(target)
        if not target_is_file:
            cache.save_file_map(claude_files)

    if not claude_files:
        msg = "No instruction files found. Create a CLAUDE.md to get started."
        raise FileNotFoundError(msg)

    # Separate applicable rules by type
    deterministic_rules = get_rules_by_type(applicable_rules, RuleType.DETERMINISTIC)
    heuristic_rules = get_rules_by_type(applicable_rules, RuleType.HEURISTIC)
    semantic_rules = get_rules_by_type(applicable_rules, RuleType.SEMANTIC)

    violations: list[Violation] = []
    judgment_requests: list[JudgmentRequest] = []

    # Run deterministic rules → direct violations
    deterministic_yml_paths = get_rule_yml_paths(deterministic_rules)
    if deterministic_yml_paths and opengrep_path.exists():
        sarif = await run_opengrep(deterministic_yml_paths, target, opengrep_path)
        violations.extend(parse_sarif(sarif, deterministic_rules))

    # Run heuristic rules → JudgmentRequest (two-stage filter)
    # Stage 1: OpenGrep pattern gate (fast, cheap)
    # Stage 2: LLM evaluates matched content
    heuristic_yml_paths = get_rule_yml_paths(heuristic_rules)
    if heuristic_yml_paths and opengrep_path.exists():
        sarif = await run_opengrep(heuristic_yml_paths, target, opengrep_path)
        judgment_requests.extend(parse_sarif_for_heuristics(sarif, heuristic_rules))

    # Prepare semantic judgment requests (no pattern gate - always LLM)
    for claude_file in claude_files:
        content = claude_file.read_text(encoding="utf-8")
        relative_path = str(claude_file.relative_to(project_root))
        judgment_requests.extend(prepare_semantic_requests(semantic_rules, content, relative_path))

    # Calculate scores
    rules_checked = len(applicable_rules)
    rules_failed = len({v.rule_id for v in violations})
    rules_passed = rules_checked - rules_failed

    score = calculate_score(rules_checked, violations)
    time_waste = estimate_time_waste(violations)
    violation_points = sum(v.points for v in violations)

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # Record analytics (quiet collection to global cache)
    if record_analytics:
        with contextlib.suppress(OSError):
            record_scan(
                target=target,
                score=score,
                level="",  # No longer tracking level
                violations_count=len(violations),
                rules_checked=rules_checked,
                elapsed_ms=elapsed_ms,
                instruction_files=len(claude_files),
            )

    # Determine capability level from features (not score)
    level = determine_capability_level(features)

    return ValidationResult(
        score=score,
        level=level,
        violations=tuple(violations),
        judgment_requests=tuple(judgment_requests),
        rules_checked=rules_checked,
        rules_passed=rules_passed,
        rules_failed=rules_failed,
        time_waste_estimate=time_waste,
        feature_summary=feature_summary,
        violation_points=violation_points,
    )


def run_validation_sync(
    target: Path,
    rules: dict[str, Rule] | None = None,
    opengrep_path: Path | None = None,
    checks_dir: Path | None = None,
    use_cache: bool = True,
    record_analytics: bool = True,
) -> ValidationResult:
    """
    Synchronous wrapper for run_validation.

    Args:
        target: Directory containing CLAUDE.md
        rules: Pre-loaded rules (optional)
        opengrep_path: Path to OpenGrep binary (optional, auto-detects)
        checks_dir: Directory containing check rules (optional)
        use_cache: Use cached file map (default True)
        record_analytics: Record scan to global analytics (default True)

    Returns:
        ValidationResult with violations, score, judgment_requests
    """
    return asyncio.run(
        run_validation(target, rules, opengrep_path, checks_dir, use_cache, record_analytics)
    )


def _discover_instruction_files(target: Path) -> list[Path]:
    """
    Discover all instruction files in target directory.

    repoRAILS = repo Recursive AI LintingS

    Args:
        target: Directory to search

    Returns:
        List of paths to CLAUDE.md files and .claude/ rule files
    """
    if target.is_file() and target.name == "CLAUDE.md":
        return [target]

    if not target.is_dir():
        return []

    files: list[Path] = []

    # Recursively find all CLAUDE.md files
    files.extend(target.rglob("CLAUDE.md"))

    # Also include .claude/rules/*.md at root level
    claude_dir = target / ".claude"
    if claude_dir.exists():
        files.extend(claude_dir.rglob("*.md"))

    return sorted(files)


async def run_opengrep(
    yml_paths: list[Path],
    target: Path,
    opengrep_path: Path,
) -> dict[str, Any]:
    """
    Execute OpenGrep with specified rules.

    Shells out to OpenGrep, returns parsed SARIF.

    Args:
        yml_paths: List of .yml rule files
        target: Directory to scan
        opengrep_path: Path to OpenGrep binary

    Returns:
        Parsed SARIF JSON output
    """
    if not yml_paths:
        return {"runs": []}

    # Create temp file for SARIF output
    with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        sarif_path = Path(f.name)

    try:
        # Build command
        cmd = [
            str(opengrep_path),
            "scan",
            "--sarif",
            "--no-git-ignore",  # Scan all files, not just git-tracked
            f"--output={sarif_path}",
        ]

        # Add rule files
        for yml_path in yml_paths:
            cmd.extend(["--config", str(yml_path)])

        # Add target
        cmd.append(str(target))

        # Run OpenGrep
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await process.communicate()

        # Parse SARIF output
        if sarif_path.exists():
            result: dict[str, Any] = json.loads(sarif_path.read_text(encoding="utf-8"))
            return result
        return {"runs": []}

    finally:
        # Clean up
        if sarif_path.exists():
            sarif_path.unlink()


def run_opengrep_sync(
    yml_paths: list[Path],
    target: Path,
    opengrep_path: Path,
) -> dict[str, Any]:
    """
    Synchronous version of run_opengrep.

    Args:
        yml_paths: List of .yml rule files
        target: Directory to scan
        opengrep_path: Path to OpenGrep binary

    Returns:
        Parsed SARIF JSON output
    """
    if not yml_paths:
        return {"runs": []}

    # Create temp file for SARIF output
    with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        sarif_path = Path(f.name)

    try:
        # Build command
        cmd = [
            str(opengrep_path),
            "scan",
            "--sarif",
            "--no-git-ignore",  # Scan all files, not just git-tracked
            f"--output={sarif_path}",
        ]

        # Add rule files
        for yml_path in yml_paths:
            cmd.extend(["--config", str(yml_path)])

        # Add target
        cmd.append(str(target))

        # Run OpenGrep
        subprocess.run(cmd, capture_output=True, check=False)

        # Parse SARIF output
        if sarif_path.exists():
            result: dict[str, Any] = json.loads(sarif_path.read_text(encoding="utf-8"))
            return result
        return {"runs": []}

    finally:
        # Clean up
        if sarif_path.exists():
            sarif_path.unlink()


def extract_short_rule_id(sarif_rule_id: str) -> str:
    """
    Extract short rule ID from OpenGrep SARIF ruleId.

    OpenGrep formats rule IDs as: checks.{category}.{id}-{slug}
    Example: checks.structure.S1-many-h2-headings -> S1

    Args:
        sarif_rule_id: Full ruleId from SARIF output

    Returns:
        Short rule ID (e.g., S1, C10, M7)
    """
    import re

    # Pattern: extract the ID part (letter + digits) from the last segment
    # e.g., "checks.structure.S1-many-h2-headings" -> "S1"
    match = re.search(r"\.([A-Z]\d+)-", sarif_rule_id)
    if match:
        return match.group(1)
    return sarif_rule_id


def parse_sarif(sarif: dict[str, Any], rules: dict[str, Rule]) -> list[Violation]:
    """
    Parse OpenGrep SARIF output into Violation objects.

    Pure function — no I/O. Skips INFO/note level findings.

    Args:
        sarif: Parsed SARIF JSON
        rules: Dict of rules for metadata lookup

    Returns:
        List of Violation objects
    """
    violations = []

    for run in sarif.get("runs", []):
        # Build map of rule levels from tool definitions
        rule_levels: dict[str, str] = {}
        tool = run.get("tool", {}).get("driver", {})
        for rule_def in tool.get("rules", []):
            rule_id = rule_def.get("id", "")
            level = rule_def.get("defaultConfiguration", {}).get("level", "warning")
            rule_levels[rule_id] = level

        for result in run.get("results", []):
            sarif_rule_id = result.get("ruleId", "")

            # Skip INFO/note level findings - they're informational, not violations
            rule_level = rule_levels.get(sarif_rule_id, "warning")
            if rule_level in ("note", "none"):
                continue

            short_rule_id = extract_short_rule_id(sarif_rule_id)
            message = result.get("message", {}).get("text", "")

            # Get location
            locations = result.get("locations", [])
            if locations:
                loc = locations[0].get("physicalLocation", {})
                artifact = loc.get("artifactLocation", {}).get("uri", "unknown")
                region = loc.get("region", {})
                line = region.get("startLine", 0)
                location = f"{artifact}:{line}"
            else:
                location = "unknown"

            # Get rule metadata using short ID
            rule = rules.get(short_rule_id)
            if rule:
                title = rule.title
                # Find matching antipattern severity or use medium
                severity = Severity.MEDIUM
                points = get_severity_points(severity)
                for ap in rule.antipatterns:
                    severity = ap.severity
                    points = ap.points
                    break
            else:
                title = sarif_rule_id
                severity = Severity.MEDIUM
                points = get_severity_points(severity)

            violations.append(
                Violation(
                    rule_id=short_rule_id,
                    rule_title=title,
                    location=location,
                    message=message,
                    severity=severity,
                    points=points,
                )
            )

    return violations


def parse_sarif_for_heuristics(sarif: dict[str, Any], rules: dict[str, Rule]) -> list[JudgmentRequest]:
    """
    Parse OpenGrep SARIF output into JudgmentRequests for heuristic rules.

    Two-stage filter: OpenGrep match gates LLM evaluation.
    Skips INFO/note level findings.

    Args:
        sarif: Parsed SARIF JSON from heuristic rule patterns
        rules: Dict of heuristic rules for metadata lookup

    Returns:
        List of JudgmentRequest objects for LLM confirmation
    """
    requests: list[JudgmentRequest] = []

    for run in sarif.get("runs", []):
        # Build map of rule levels from tool definitions
        rule_levels: dict[str, str] = {}
        tool = run.get("tool", {}).get("driver", {})
        for rule_def in tool.get("rules", []):
            rule_id = rule_def.get("id", "")
            level = rule_def.get("defaultConfiguration", {}).get("level", "warning")
            rule_levels[rule_id] = level

        for result in run.get("results", []):
            sarif_rule_id = result.get("ruleId", "")

            # Skip INFO/note level findings - they're informational, not candidates
            rule_level = rule_levels.get(sarif_rule_id, "warning")
            if rule_level in ("note", "none"):
                continue

            short_rule_id = extract_short_rule_id(sarif_rule_id)
            message = result.get("message", {}).get("text", "")

            # Get location and matched content
            locations = result.get("locations", [])
            if locations:
                loc = locations[0].get("physicalLocation", {})
                artifact = loc.get("artifactLocation", {}).get("uri", "unknown")
                region = loc.get("region", {})
                line = region.get("startLine", 0)
                location = f"{artifact}:{line}"
                # Get snippet if available
                snippet = region.get("snippet", {}).get("text", message)
            else:
                location = "unknown"
                snippet = message

            # Get rule metadata using short ID
            rule = rules.get(short_rule_id)
            if not rule:
                continue

            # Skip if rule doesn't have question/criteria (shouldn't happen for heuristics)
            if not rule.question:
                continue

            # Parse criteria - may be string or already dict
            criteria: dict[str, str]
            if isinstance(rule.criteria, dict):
                criteria = rule.criteria
            elif isinstance(rule.criteria, str):
                # Simple string criteria becomes single-entry dict
                criteria = {"pass_condition": rule.criteria}
            else:
                criteria = {"pass_condition": "Evaluate based on context"}

            # Get severity and points from first antipattern (or defaults)
            severity = Severity.MEDIUM
            points_if_fail = -10
            for ap in rule.antipatterns:
                severity = ap.severity
                points_if_fail = ap.points
                break

            request = JudgmentRequest(
                rule_id=short_rule_id,
                rule_title=rule.title,
                content=snippet,
                location=location,
                question=rule.question,
                criteria=criteria,
                examples={"good": [], "bad": []},  # Heuristics use criteria, not examples
                choices=["pass", "fail"],
                pass_value="pass",
                severity=severity,
                points_if_fail=points_if_fail,
            )
            requests.append(request)

    return requests


def prepare_semantic_requests(
    rules: dict[str, Rule],
    content: str,
    file_path: str,
) -> list[JudgmentRequest]:
    """
    Prepare JudgmentRequests for semantic rules.

    Pure function — extracts content, builds requests.

    Args:
        rules: Dict of semantic rules
        content: Content of CLAUDE.md file
        file_path: Path to the file (for location)

    Returns:
        List of JudgmentRequest objects
    """
    from reporails_cli.semantic.definitions import get_semantic_definition

    requests = []

    for rule_id, rule in rules.items():
        definition = get_semantic_definition(rule_id)
        if definition is None:
            continue

        # Create judgment request
        request = JudgmentRequest(
            rule_id=rule_id,
            rule_title=rule.title,
            content=content,
            location=file_path,
            question=definition["question"],
            criteria=definition["criteria"],
            examples=definition["examples"],
            choices=definition["choices"],
            pass_value=definition["pass_value"],
            severity=Severity(definition.get("severity", "medium")),
            points_if_fail=definition.get("points_if_fail", -10),
        )
        requests.append(request)

    return requests
