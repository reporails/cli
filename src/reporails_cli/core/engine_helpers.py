"""Engine helper functions and constants extracted from engine.py."""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.cache import ProjectCache, content_hash, structural_hash
from reporails_cli.core.models import (
    Category,
    CategoryStats,
    ClassifiedFile,
    JudgmentRequest,
    Rule,
    Severity,
    Violation,
)


def _find_project_root(target: Path) -> Path:
    """Walk up from target to find project root (nearest backbone > .git > target).

    Nearest backbone wins: if the target itself has a backbone.yml, that IS
    the project root — don't walk past it to a parent coordination root.
    """
    current = target if target.is_dir() else target.parent
    first_git = None
    while current != current.parent:
        if (current / ".git").exists() and first_git is None:
            first_git = current
        backbone = current / ".ails" / "backbone.yml"
        if backbone.exists():
            return current
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
    Category.COHERENCE: "C",
    Category.DIRECTION: "D",
    Category.EFFICIENCY: "E",
    Category.MAINTENANCE: "M",
    Category.GOVERNANCE: "G",
}

# Canonical display order
_CATEGORY_ORDER = ("S", "C", "D", "E", "M", "G")

# Code → human name
_CATEGORY_NAMES = {
    "S": "Structure",
    "C": "Coherence",
    "D": "Direction",
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


def _group_rules_by_target_files(
    rules: dict[str, Rule],
    classified_files: list[ClassifiedFile],
) -> dict[frozenset[Path], dict[str, Rule]]:
    """Group rules by resolved file targets for batched regex calls."""
    from reporails_cli.core.classification import match_files

    groups: dict[frozenset[Path], dict[str, Rule]] = {}
    for rule_id, rule in rules.items():
        if rule.match is not None:
            matched = match_files(classified_files, rule.match)
            file_set = frozenset(cf.path for cf in matched)
        else:
            file_set = frozenset(cf.path for cf in classified_files)
        groups.setdefault(file_set, {})[rule_id] = rule
    return groups


def _collect_body_only_paths(group_rules: dict[str, Rule]) -> set[Path] | None:
    """Collect yml_paths for rules whose match.format is exclusively 'freeform'.

    These rules target body content only — their regex checks should strip
    YAML frontmatter before matching (frontmatter is metadata, not content).

    Rules with format lists containing 'frontmatter' need to see the full file.
    """
    paths: set[Path] = set()
    for rule in group_rules.values():
        if rule.yml_path is None or not rule.yml_path.exists():
            continue
        if rule.match is not None and rule.match.format == "freeform":
            paths.add(rule.yml_path)
    return paths or None


def _filter_dismissed_violations(  # pylint: disable=too-many-locals
    violations: list[Violation],
    scan_root: Path,
    project_root: Path,
    use_cache: bool,
    rules_fp: str = "",
) -> list[Violation]:
    """Filter out dismissed violations (cached as 'pass' in judgment cache).

    Deterministic violations dismissed via ``ails heal`` are cached with
    verdict='pass'. This removes them so ``ails check`` also hides them.
    When ``use_cache=False`` (--refresh), all violations pass through.
    """
    if not violations or not use_cache:
        return violations

    cache = ProjectCache(project_root)
    cache_data = cache.load_judgment_cache(rules_fingerprint=rules_fp)
    all_judgments = cache_data.get("judgments", {})
    if not all_judgments:
        return violations

    filtered: list[Violation] = []
    for v in violations:
        raw_path = v.location.rsplit(":", 1)[0] if ":" in v.location else v.location
        try:
            rel_path = Path(raw_path).relative_to(scan_root).as_posix()
        except ValueError:
            rel_path = raw_path

        entry = all_judgments.get(rel_path)
        if not entry:
            filtered.append(v)
            continue

        try:
            full_file = scan_root / rel_path
            file_hash = content_hash(full_file)
            struct_hash = structural_hash(full_file)
        except (OSError, ValueError):
            filtered.append(v)
            continue

        # Match on content or structural hash
        if entry.get("content_hash") != file_hash and entry.get("structural_hash") != struct_hash:
            filtered.append(v)
            continue

        results = entry.get("results", {})
        if v.rule_id in results and results[v.rule_id].get("verdict") == "pass":
            continue  # Dismissed — skip
        filtered.append(v)
    return filtered


def _filter_cached_judgments(  # pylint: disable=too-many-locals
    judgment_requests: list[JudgmentRequest],
    violations: list[Violation],
    scan_root: Path,
    project_root: Path,
    use_cache: bool,
    rules_fp: str = "",
) -> tuple[list[JudgmentRequest], list[Violation]]:
    """Filter already-evaluated judgments from cache. Returns (remaining_requests, updated_violations)."""
    if not judgment_requests or not use_cache:
        return judgment_requests, violations

    cache = ProjectCache(project_root)
    cache_data = cache.load_judgment_cache(rules_fingerprint=rules_fp)
    all_judgments = cache_data.get("judgments", {})
    if not all_judgments:
        return judgment_requests, violations

    filtered_requests: list[JudgmentRequest] = []
    for jr in judgment_requests:
        raw_path = jr.location.rsplit(":", 1)[0] if ":" in jr.location else jr.location
        try:
            rel_path = Path(raw_path).relative_to(scan_root).as_posix()
        except ValueError:
            rel_path = raw_path
        try:
            full_file = scan_root / rel_path
            file_hash = content_hash(full_file)
            struct_hash = structural_hash(full_file)
        except (OSError, ValueError):
            filtered_requests.append(jr)
            continue

        entry = all_judgments.get(rel_path)
        if not entry:
            filtered_requests.append(jr)
            continue

        # Match on content or structural hash
        if entry.get("content_hash") != file_hash and entry.get("structural_hash") != struct_hash:
            filtered_requests.append(jr)
            continue

        results = entry.get("results", {})
        if jr.rule_id in results:
            verdict = results[jr.rule_id]
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
