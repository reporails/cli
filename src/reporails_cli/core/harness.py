# pylint: disable=too-many-lines
"""Rule harness engine — validates rules against their own test fixtures.

Discovers rules, loads agent config, runs mechanical + deterministic checks
against pass/fail fixtures. Produces per-rule pass/fail results.

Uses the same check engines as production validation (ails check):
- Mechanical: dispatch_single_check from core.mechanical.runner
- Deterministic: run_validation from core.regex.runner
- Semantic: always pass (no LLM in harness mode)
"""

from __future__ import annotations

import logging
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from reporails_cli.core.classification import classify_files, load_file_types
from reporails_cli.core.mechanical.checks import MECHANICAL_CHECKS, CheckResult
from reporails_cli.core.models import ClassifiedFile, FileTypeDeclaration
from reporails_cli.core.regex import run_validation as run_regex_validation
from reporails_cli.core.utils import parse_frontmatter

logger = logging.getLogger(__name__)

_FIXTURE_EXCLUDES = frozenset({".gitkeep", ".DS_Store"})


# ── Data models ─────────────────────────────────────────────────────


class HarnessStatus:
    """Rule-level harness outcomes."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_IMPLEMENTED = "not_implemented"
    NO_FIXTURES = "no_fixtures"
    SKIPPED = "skipped"


@dataclass
class CheckRun:
    """Result of one check against one fixture."""

    check_id: str
    check_type: str
    fixture: str  # "pass" or "fail"
    passed: bool
    message: str


@dataclass
class HarnessResult:
    """Per-rule harness outcome."""

    rule_id: str
    slug: str
    title: str
    status: str  # HarnessStatus value
    check_runs: list[CheckRun] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)


# ── Agent config ────────────────────────────────────────────────────


def load_agent_config(
    rules_root: Path,
    agent: str,
) -> tuple[list[FileTypeDeclaration], list[str]]:
    """Load agent config.yml and return (file_types, excludes).

    Args:
        rules_root: Rules repository root directory.
        agent: Agent name (e.g., "claude").

    Returns:
        Tuple of (file_type declarations, exclude_patterns).
    """
    config_path = rules_root / agent / "config.yml"
    if not config_path.exists():
        logger.warning("Agent config not found: %s", config_path)
        return [], []
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except (yaml.YAMLError, OSError) as exc:
        logger.warning("Failed to load agent config: %s", exc)
        return [], []

    file_types = load_file_types(agent, [rules_root])
    return file_types, data.get("excludes", [])


def _classify_fixture(
    fixture_root: Path,
    file_types: list[FileTypeDeclaration],
) -> list[ClassifiedFile]:
    """Classify files in a fixture directory against file type declarations."""
    files = [f for f in fixture_root.rglob("*") if f.is_file() and f.name not in _FIXTURE_EXCLUDES]
    return classify_files(fixture_root, files, file_types)


def _build_prefix_to_agent_map(rules_root: Path) -> dict[str, str]:
    """Build NAMESPACE_PREFIX → agent_name map from agent configs.

    Reads each {agent}/config.yml for the ``prefix`` field.
    Agent directories sit alongside core/ (flat layout).
    Returns mapping like ``{"CLAUDE": "claude", "CODEX": "codex"}``.
    """
    mapping: dict[str, str] = {}
    if not rules_root.is_dir():
        return mapping
    for agent_dir in sorted(rules_root.iterdir()):
        if not agent_dir.is_dir() or agent_dir.name == "core":
            continue
        config_path = agent_dir / "config.yml"
        if not config_path.exists():
            continue
        try:
            data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            prefix = data.get("prefix", "")
            if prefix:
                mapping[prefix] = agent_dir.name
        except (yaml.YAMLError, OSError):
            continue
    return mapping


# ── Rule discovery ──────────────────────────────────────────────────


@dataclass
class RuleInfo:  # pylint: disable=too-many-instance-attributes
    """Lightweight rule descriptor for harness discovery."""

    rule_id: str
    slug: str
    title: str
    category: str
    rule_type: str
    match: dict[str, str]
    checks: list[dict[str, Any]]
    rule_dir: Path
    checks_yml: Path

    @property
    def has_checks(self) -> bool:
        """Whether the rule has any check definitions."""
        return len(self.checks) > 0

    @property
    def has_pass_fixture(self) -> bool:
        """Whether the rule has a non-empty pass fixture directory."""
        d = self.rule_dir / "tests" / "pass"
        return d.is_dir() and any(d.iterdir())

    @property
    def has_fail_fixture(self) -> bool:
        """Whether the rule has a non-empty fail fixture directory."""
        d = self.rule_dir / "tests" / "fail"
        return d.is_dir() and any(d.iterdir())


def _rule_matches_exclude(rule_id: str, patterns: list[str]) -> bool:
    """Check if a rule ID matches any exclude pattern (exact or NAMESPACE:*)."""
    for pattern in patterns:
        if pattern == rule_id:
            return True
        if pattern.endswith(":*") and rule_id.startswith(pattern[:-1]):
            return True
    return False


def _scan_root(root: Path, agent: str | None = None) -> list[Path]:
    """Find rule directories under a single root.

    Layout: core/{slug}/ for core rules, {agent}/{slug}/ for agent rules.
    Agent directories sit alongside core/ and contain a config.yml.
    """
    dirs: list[Path] = []

    core_dir = root / "core"
    if core_dir.exists():
        dirs.extend(d for d in sorted(core_dir.iterdir()) if d.is_dir())

    # Agent dirs are siblings of core/ that contain a config.yml
    if root.is_dir():
        for candidate in sorted(root.iterdir()):
            if not candidate.is_dir() or candidate.name == "core":
                continue
            if not (candidate / "config.yml").exists():
                continue
            if agent and candidate.name != agent:
                continue
            dirs.extend(d for d in sorted(candidate.iterdir()) if d.is_dir() and d.name != "tests")

    return dirs


def discover_rules(  # pylint: disable=too-many-locals
    rules_root: Path,
    *,
    filter_path: str | None = None,
    filter_rule: str | None = None,
    package_roots: list[Path] | None = None,
    excludes: list[str] | None = None,
    agent: str | None = None,
) -> list[RuleInfo]:
    """Discover rules by walking core/ and agents/*/rules/ directories.

    Args:
        rules_root: Primary rules repository root.
        filter_path: Optional path prefix filter.
        filter_rule: Optional rule coordinate filter (e.g., "CORE:S:0001").
        package_roots: Additional package roots to scan.
        excludes: Rule ID patterns to exclude.
        agent: Agent name filter for agent-specific rules.
    """
    rules: list[RuleInfo] = []
    excludes = excludes or []

    all_roots = [rules_root] + (package_roots or [])
    search_pairs: list[tuple[Path, Path]] = []
    for root in all_roots:
        search_pairs.extend((root, slug_dir) for slug_dir in _scan_root(root, agent))

    for root, slug_dir in search_pairs:
        rule_md = slug_dir / "rule.md"
        checks_yml = slug_dir / "checks.yml"
        if not rule_md.exists():
            continue

        if filter_path:
            rel = str(slug_dir.relative_to(root))
            if not rel.startswith(filter_path.rstrip("/")):
                continue

        try:
            content = rule_md.read_text(encoding="utf-8")
        except OSError:
            continue

        meta = parse_frontmatter(content)
        if not meta:
            continue

        rule_id = meta.get("id", "")
        if filter_rule and rule_id != filter_rule:
            continue
        if _rule_matches_exclude(rule_id, excludes):
            continue

        checks = meta.get("checks", [])
        if not checks and checks_yml.exists():
            try:
                yml_data = yaml.safe_load(checks_yml.read_text(encoding="utf-8"))
                checks = yml_data.get("checks", []) if isinstance(yml_data, dict) else []
            except (OSError, yaml.YAMLError):
                checks = []

        rules.append(
            RuleInfo(
                rule_id=rule_id,
                slug=meta.get("slug", ""),
                title=meta.get("title", ""),
                category=meta.get("category", ""),
                rule_type=meta.get("type", ""),
                match=meta.get("match") or {},
                checks=checks,
                rule_dir=slug_dir,
                checks_yml=checks_yml,
            )
        )

    return rules


# ── Check execution ─────────────────────────────────────────────────


def _run_mechanical_check(
    check: dict[str, Any],
    fixture_root: Path,
    classified_files: list[ClassifiedFile],
) -> CheckResult:
    """Run a single mechanical check against a fixture directory."""
    check_name = check.get("check", "") or check.get("name", "")
    args = check.get("args", {}) or {}

    fn = MECHANICAL_CHECKS.get(check_name)
    if fn is None:
        logger.warning("Unknown mechanical check: %s", check_name)
        return CheckResult(passed=False, message=f"Unknown mechanical check: {check_name}")

    result = fn(fixture_root, args, classified_files)

    if check.get("expect", "present") == "absent":
        result = CheckResult(passed=not result.passed, message=result.message)

    return result  # type: ignore[no-any-return]


def _run_deterministic_check(  # pylint: disable=too-many-locals
    checks_yml: Path,
    check: dict[str, Any],
    fixture_root: Path,
) -> tuple[bool, int, str]:
    """Run a deterministic check via the CLI regex engine against fixtures.

    Returns:
        Tuple of (engine_ok, findings_count, message).
    """
    if not checks_yml.exists():
        return False, 0, f"checks.yml not found: {checks_yml}"

    try:
        yml_content = yaml.safe_load(checks_yml.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError) as exc:
        return False, 0, f"Failed to load checks.yml: {exc}"

    yml_rules = yml_content.get("checks") or []
    if not yml_rules:
        return False, 0, "checks.yml has no patterns (checks: [])"

    # Find the matching rule entry by check ID
    check_id = check.get("id", "")
    check_id_dotted = check_id.replace(":", ".")
    matching_rule = None
    for r in yml_rules:
        if r.get("id") == check_id_dotted:
            matching_rule = r
            break

    if matching_rule is None and len(yml_rules) == 1:
        matching_rule = yml_rules[0]

    if matching_rule is None:
        return False, 0, f"No pattern for check {check_id} in checks.yml"

    # Write a temp rule file and run the CLI regex engine
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as tmp:
        yaml.dump({"checks": [matching_rule]}, tmp)
        tmp_path = Path(tmp.name)

    try:
        # Discover all files in fixture for path filtering
        fixture_files = [f for f in fixture_root.rglob("*") if f.is_file() and f.name not in _FIXTURE_EXCLUDES]
        sarif = run_regex_validation(
            [tmp_path],
            fixture_root,
            instruction_files=fixture_files if fixture_files else None,
        )
        findings = 0
        for run in sarif.get("runs", []):
            findings += len(run.get("results", []))
        return True, findings, f"{findings} finding(s)"
    except Exception as exc:
        return False, 0, f"Regex engine error: {exc}"
    finally:
        tmp_path.unlink(missing_ok=True)


# ── Pass fixture scaffolding ─────────────────────────────────────────


def _glob_to_concrete(pattern: str) -> str:
    """Convert a glob pattern to a concrete file path for scaffolding.

    Examples:
        "**/*.md" → "scaffold.md"
        ".claude/skills/**" → ".claude/skills/scaffold"
        ".claude/rules/**/*.md" → ".claude/rules/scaffold.md"
    """
    # Strip leading ./
    clean = pattern.removeprefix("./")
    parts = clean.split("/")
    concrete: list[str] = []
    for part in parts:
        if part == "**":
            continue
        if "*" in part:
            # Replace glob with scaffold filename, preserving extension
            ext = ""
            if "." in part:
                ext = part[part.rindex(".") :]
                if "*" in ext:
                    ext = ".md"
            concrete.append(f"scaffold{ext}")
        else:
            concrete.append(part)
    return "/".join(concrete) if concrete else "scaffold.md"


_SCAFFOLDABLE_CHECKS: dict[str, str] = {
    "file_exists": "file",
    "glob_match": "file",
    "directory_exists": "dir",
    "glob_count": "glob_count",
    "file_count": "glob_count",
    "git_tracked": "git_marker",
    "file_tracked": "git_marker",
    "file_absent": "file_removal",
}


def _collect_scaffold_actions(
    checks: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    """Extract scaffoldable actions from mechanical checks."""
    actions: list[tuple[str, dict[str, Any]]] = []
    for check in checks:
        if check.get("type") != "mechanical":
            continue
        check_name = check.get("check", "") or check.get("name", "")
        action_type = _SCAFFOLDABLE_CHECKS.get(check_name)
        if action_type:
            actions.append((action_type, check.get("args", {}) or {}))
    return actions


def _apply_scaffold_action(
    action_type: str,
    args: dict[str, Any],
    tmp_dir: Path,
    file_types: list[FileTypeDeclaration],
) -> None:
    """Apply a single scaffold action to the temp directory."""
    if action_type == "file":
        _scaffold_file(args, tmp_dir, file_types)
    elif action_type == "dir":
        path = str(args.get("path", ""))
        target = tmp_dir / path
        if not target.is_dir():
            target.mkdir(parents=True, exist_ok=True)
    elif action_type == "glob_count":
        _scaffold_glob_count(args, tmp_dir)
    elif action_type == "file_removal":
        _scaffold_file_removal(args, tmp_dir)
    elif action_type == "git_marker":
        marker = tmp_dir / ".git_marker"
        if not marker.exists() and not (tmp_dir / ".git").exists():
            marker.touch()


def _scaffold_file(
    args: dict[str, Any],
    tmp_dir: Path,
    file_types: list[FileTypeDeclaration],
) -> None:
    """Scaffold a single file for file_exists/glob_match checks."""
    path_pattern = str(args.get("path", ""))
    if path_pattern:
        concrete = _glob_to_concrete(path_pattern)
    else:
        # Use first file type pattern as fallback
        if file_types:
            concrete = _glob_to_concrete(file_types[0].patterns[0] if file_types[0].patterns else "scaffold.md")
        else:
            return
    target = tmp_dir / concrete
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()


def _scaffold_glob_count(
    args: dict[str, Any],
    tmp_dir: Path,
) -> None:
    """Scaffold files for glob_count/file_count checks."""
    raw_pattern = str(args.get("pattern", "**/*"))
    min_count = int(args.get("min", 1))
    existing = list(tmp_dir.glob(raw_pattern))
    needed = max(0, min_count - len(existing))
    for i in range(needed):
        concrete = _glob_to_concrete(raw_pattern)
        base, ext = concrete.rsplit(".", 1) if "." in concrete else (concrete, "")
        name = f"{base}_{i}.{ext}" if ext else f"{base}_{i}"
        target = tmp_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.touch()


def _scaffold_fixture(
    fixture_root: Path,
    checks: list[dict[str, Any]],
    file_types: list[FileTypeDeclaration],
) -> Path | None:
    """Create a scaffolded copy of a pass fixture with M check dependencies.

    Reads mechanical checks and creates minimal structure so that
    checks like file_exists, directory_exists, glob_count, git_tracked
    can pass. Only applied to pass fixtures.

    Returns the scaffolded temp directory, or None if no scaffolding needed.
    """
    actions = _collect_scaffold_actions(checks)
    if not actions:
        return None

    tmp_dir = Path(tempfile.mkdtemp(prefix="harness_scaffold_"))
    shutil.copytree(fixture_root, tmp_dir, dirs_exist_ok=True)

    for action_type, args in actions:
        _apply_scaffold_action(action_type, args, tmp_dir, file_types)

    return tmp_dir


def _scaffold_file_removal(
    args: dict[str, Any],
    tmp_dir: Path,
) -> None:
    """Remove forbidden file from pass scaffold (for file_absent checks)."""
    import glob as globmod

    pattern = str(args.get("pattern", ""))
    if not pattern:
        return
    # Try as plain path first
    target = tmp_dir / pattern
    if target.exists():
        target.unlink()
        return
    # Try as glob
    for match in globmod.glob(str(tmp_dir / pattern), recursive=True):
        Path(match).unlink()


# ── Fail fixture scaffolding ─────────────────────────────────────────


_SCAFFOLDABLE_FAIL_CHECKS: dict[str, str] = {
    "filename_matches_pattern": "filename_mismatch",
    "glob_count": "glob_count_deficit",
    "file_count": "glob_count_deficit",
    "file_absent": "file_present",
}


def _collect_fail_scaffold_actions(
    checks: list[dict[str, Any]],
) -> list[tuple[str, dict[str, Any]]]:
    """Extract scaffoldable fail actions from mechanical checks."""
    actions: list[tuple[str, dict[str, Any]]] = []
    for check in checks:
        if check.get("type") != "mechanical":
            continue
        check_name = check.get("check", "") or check.get("name", "")
        action_type = _SCAFFOLDABLE_FAIL_CHECKS.get(check_name)
        if action_type:
            actions.append((action_type, check.get("args", {}) or {}))
    return actions


def _apply_fail_scaffold_action(
    action_type: str,
    args: dict[str, Any],
    tmp_dir: Path,
    file_types: list[FileTypeDeclaration],
) -> None:
    """Apply a single fail scaffold action to the temp directory."""
    if action_type == "filename_mismatch":
        _scaffold_filename_mismatch(args, tmp_dir, file_types)
    elif action_type == "glob_count_deficit":
        _scaffold_glob_count_deficit(args, tmp_dir)
    elif action_type == "file_present":
        _scaffold_file_present(args, tmp_dir)


def _get_target_patterns_from_args(
    args: dict[str, Any],
    file_types: list[FileTypeDeclaration],
) -> list[str]:
    """Get file patterns from args or file_types for scaffolding."""
    path_pattern = args.get("path", "")
    if path_pattern:
        return [str(path_pattern)]
    # Fall back to first file type's patterns
    if file_types:
        return list(file_types[0].patterns)
    return []


def _scaffold_filename_mismatch(
    args: dict[str, Any],
    tmp_dir: Path,
    file_types: list[FileTypeDeclaration],
) -> None:
    """Rename existing files so they fail filename_matches_pattern.

    Preserves the file extension so glob patterns still find the file,
    but uses a name that won't match the regex pattern.
    """
    import glob as globmod

    for fp in _get_target_patterns_from_args(args, file_types):
        resolved = str(tmp_dir / fp)
        for match_path in globmod.glob(resolved, recursive=True):
            match = Path(match_path)
            if match.is_file():
                dest = match.parent / f"_scaffold_invalid{match.suffix}"
                match.rename(dest)
                return  # One rename is sufficient to cause failure
    # No existing files to rename — create one with a bad name
    patterns = _get_target_patterns_from_args(args, file_types)
    concrete = _glob_to_concrete(patterns[0] if patterns else "**/*.md")
    base = Path(concrete)
    target = tmp_dir / base.parent / f"_scaffold_invalid{base.suffix or '.md'}"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.touch()


def _scaffold_glob_count_deficit(
    args: dict[str, Any],
    tmp_dir: Path,
) -> None:
    """Remove files to get count below min for glob_count/file_count checks."""
    raw_pattern = str(args.get("pattern", "**/*"))
    min_count = int(args.get("min", 1))
    existing = sorted(tmp_dir.glob(raw_pattern))
    existing_files = [f for f in existing if f.is_file()]
    # Remove files until count is below min
    target_count = max(0, min_count - 1)
    to_remove = len(existing_files) - target_count
    for f in existing_files[:to_remove]:
        f.unlink()


def _scaffold_file_present(
    args: dict[str, Any],
    tmp_dir: Path,
) -> None:
    """Create the forbidden file so file_absent fails."""
    pattern = str(args.get("pattern", ""))
    if not pattern:
        return
    # Create as plain path
    target = tmp_dir / pattern
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.touch()


def _scaffold_fail_fixture(
    fixture_root: Path,
    checks: list[dict[str, Any]],
    file_types: list[FileTypeDeclaration],
) -> Path | None:
    """Create a scaffolded copy of a fail fixture with M check dependencies.

    Mirrors _scaffold_fixture() for the fail side. First applies pass scaffolding
    (to ensure structural dependencies exist), then applies fail actions to break
    exactly the targeted check.

    Returns the scaffolded temp directory, or None if no scaffolding needed.
    """
    fail_actions = _collect_fail_scaffold_actions(checks)
    if not fail_actions:
        return None

    tmp_dir = Path(tempfile.mkdtemp(prefix="harness_fail_scaffold_"))
    shutil.copytree(fixture_root, tmp_dir, dirs_exist_ok=True)

    # First, apply pass scaffolding so structural deps exist
    pass_actions = _collect_scaffold_actions(checks)
    for action_type, args in pass_actions:
        _apply_scaffold_action(action_type, args, tmp_dir, file_types)

    # Then apply fail actions to break the targeted checks
    for action_type, args in fail_actions:
        _apply_fail_scaffold_action(action_type, args, tmp_dir, file_types)

    return tmp_dir


# ── Rule runner ─────────────────────────────────────────────────────


def _prepare_scaffolds(
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
) -> tuple[Path | None, Path | None, Path, Path]:
    """Prepare scaffolded fixtures for a rule.

    Returns (scaffolded_pass, scaffolded_fail, effective_pass_dir, effective_fail_dir).
    """
    pass_dir = rule.rule_dir / "tests" / "pass"
    fail_dir = rule.rule_dir / "tests" / "fail"

    scaffolded_pass: Path | None = None
    if rule.has_pass_fixture:
        scaffolded_pass = _scaffold_fixture(pass_dir, rule.checks, file_types)

    scaffolded_fail: Path | None = None
    if rule.has_fail_fixture:
        scaffolded_fail = _scaffold_fail_fixture(fail_dir, rule.checks, file_types)

    effective_pass = scaffolded_pass if scaffolded_pass else pass_dir
    effective_fail = scaffolded_fail if scaffolded_fail else fail_dir
    return scaffolded_pass, scaffolded_fail, effective_pass, effective_fail


def run_rule(
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
) -> HarnessResult:
    """Run all checks for a rule against its fixtures.

    Follows asymmetric pass/fail contract:
    - Pass fixture: ALL checks must pass (no violations).
    - Fail fixture: AT LEAST ONE check must detect a violation.
    - Semantic checks: always pass (skipped, no LLM).
    """
    result = HarnessResult(
        rule_id=rule.rule_id,
        slug=rule.slug,
        title=rule.title,
        status=HarnessStatus.PASSED,
    )

    if not rule.has_checks:
        result.status = HarnessStatus.NOT_IMPLEMENTED
        result.messages.append("checks: [] — not implemented")
        return result

    if not rule.has_pass_fixture and not rule.has_fail_fixture:
        result.status = HarnessStatus.NO_FIXTURES
        result.messages.append("No test fixtures (tests/pass/ or tests/fail/ empty)")
        return result

    fail_violation_found = False
    scaffolded_pass, scaffolded_fail, effective_pass_dir, effective_fail_dir = _prepare_scaffolds(rule, file_types)

    try:
        for check in rule.checks:
            check_id = check.get("id", "unknown")
            check_type = check.get("type", "unknown")
            expect = check.get("expect", "present")

            # === Pass fixture: ALL checks must pass ===
            if rule.has_pass_fixture:
                passed, run = _check_fixture(
                    check, check_id, check_type, expect, effective_pass_dir, rule, file_types, "pass"
                )
                result.check_runs.append(run)
                if not passed:
                    result.status = HarnessStatus.FAILED

            # === Fail fixture: at least ONE check must detect a violation ===
            if rule.has_fail_fixture:
                violation, run = _check_fixture_for_violation(
                    check, check_id, check_type, expect, effective_fail_dir, rule, file_types
                )
                result.check_runs.append(run)
                if violation:
                    fail_violation_found = True

        if rule.has_fail_fixture and not fail_violation_found:
            result.status = HarnessStatus.FAILED
            result.messages.append("Fail fixture: no check detected a violation")
    finally:
        if scaffolded_pass:
            shutil.rmtree(scaffolded_pass, ignore_errors=True)
        if scaffolded_fail:
            shutil.rmtree(scaffolded_fail, ignore_errors=True)

    return result


def _check_fixture(
    check: dict[str, Any],
    check_id: str,
    check_type: str,
    expect: str,
    fixture_root: Path,
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
    fixture_name: str,
) -> tuple[bool, CheckRun]:
    """Run a check against a pass fixture. Returns (passed, CheckRun)."""
    if check_type == "mechanical":
        classified = _classify_fixture(fixture_root, file_types)
        cr = _run_mechanical_check(check, fixture_root, classified)
        return cr.passed, CheckRun(check_id, check_type, fixture_name, cr.passed, cr.message)

    if check_type == "deterministic":
        ok, count, msg = _run_deterministic_check(rule.checks_yml, check, fixture_root)
        passed = (ok and count > 0) if expect == "present" else (ok and count == 0)
        return passed, CheckRun(check_id, check_type, fixture_name, passed, msg)

    if check_type == "content_query":
        return True, CheckRun(check_id, check_type, fixture_name, True, "content_query — skipped (requires mapper)")

    return False, CheckRun(check_id, check_type, fixture_name, False, f"unknown check type: {check_type}")


def _check_fixture_for_violation(
    check: dict[str, Any],
    check_id: str,
    check_type: str,
    expect: str,
    fixture_root: Path,
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
) -> tuple[bool, CheckRun]:
    """Run a check against a fail fixture. Returns (violation_found, CheckRun)."""
    if check_type == "mechanical":
        classified = _classify_fixture(fixture_root, file_types)
        cr = _run_mechanical_check(check, fixture_root, classified)
        violation = not cr.passed
        return violation, CheckRun(check_id, check_type, "fail", True, cr.message)

    if check_type == "deterministic":
        ok, count, msg = _run_deterministic_check(rule.checks_yml, check, fixture_root)
        violation = (ok and count == 0) if expect == "present" else (ok and count > 0)
        return violation, CheckRun(check_id, check_type, "fail", True, msg)

    if check_type == "content_query":
        return False, CheckRun(check_id, check_type, "fail", True, "content_query — skipped (requires mapper)")

    return False, CheckRun(check_id, check_type, "fail", False, f"unknown check type: {check_type}")


# ── Batch runner ────────────────────────────────────────────────────


def _build_agent_cache(
    rules_root: Path,
    default_agent: str,
    prefix_map: dict[str, str],
) -> dict[str, tuple[list[FileTypeDeclaration], list[str]]]:
    """Load configs for all agents into a cache keyed by agent name."""
    cache: dict[str, tuple[list[FileTypeDeclaration], list[str]]] = {}
    for agent_name in {default_agent} | set(prefix_map.values()):
        cache[agent_name] = load_agent_config(rules_root, agent_name)
    return cache


def _get_rule_agent(rule_id: str, prefix_map: dict[str, str]) -> str | None:
    """Determine which agent owns a rule based on its prefix.

    Returns agent name if prefix matches, None for CORE/RRAILS rules.
    """
    prefix = rule_id.split(":")[0] if ":" in rule_id else ""
    if prefix in prefix_map:
        return prefix_map[prefix]
    return None


def run_harness(
    rules_root: Path,
    *,
    filter_path: str | None = None,
    filter_rule: str | None = None,
    package_roots: list[Path] | None = None,
    agent: str = "claude",
) -> list[HarnessResult]:
    """Discover and run all rules, returning per-rule results.

    Discovers rules across all agents and dispatches each rule to the
    correct agent's file_types based on its rule_id prefix. CORE/RRAILS rules
    use the default agent's file_types.

    Args:
        rules_root: Primary rules repository root.
        filter_path: Optional path prefix filter.
        filter_rule: Optional rule coordinate filter.
        package_roots: Additional package roots to scan.
        agent: Default agent config for CORE/RRAILS rules.
    """
    # Build prefix→agent mapping and per-agent config cache
    prefix_map = _build_prefix_to_agent_map(rules_root)
    agent_cache = _build_agent_cache(rules_root, agent, prefix_map)
    default_file_types, default_excludes = agent_cache[agent]

    # Discover rules across ALL agents (agent=None)
    rules = discover_rules(
        rules_root,
        filter_path=filter_path,
        filter_rule=filter_rule,
        package_roots=package_roots,
        excludes=default_excludes,
        agent=None,
    )

    results: list[HarnessResult] = []
    for rule in rules:
        rule_agent = _get_rule_agent(rule.rule_id, prefix_map)
        if rule_agent and rule_agent in agent_cache:
            rule_file_types, rule_excludes = agent_cache[rule_agent]
            # Skip rules excluded by their own agent config
            if _rule_matches_exclude(rule.rule_id, rule_excludes):
                continue
        else:
            # CORE/RRAILS rules use default agent file_types
            rule_file_types = default_file_types
        results.append(run_rule(rule, rule_file_types))

    return results


# ── Effectiveness scoring ──────────────────────────────────────────


@dataclass
class ScoreDelta:
    """Per-rule quality delta between pass and fail fixtures."""

    rule_id: str
    slug: str
    pass_score: float
    fail_score: float
    delta: float


def score_fixture(
    fixture_dir: Path,  # noqa: ARG001
    rules_paths: list[Path],  # noqa: ARG001
) -> float:
    """Run full validation scoring on a fixture directory.

    Returns 0.0 — scoring pending pipeline rewrite (0.5.0).
    """
    logger.warning("score_fixture: scoring disabled pending 0.5.0 pipeline rewrite")
    return 0.0


def score_rules(
    rules_root: Path,
    *,
    filter_path: str | None = None,
    filter_rule: str | None = None,
    package_roots: list[Path] | None = None,
    agent: str = "claude",
) -> list[ScoreDelta]:
    """Score pass/fail fixtures for all rules, returning quality deltas.

    Args:
        rules_root: Primary rules repository root.
        filter_path: Optional path prefix filter.
        filter_rule: Optional rule coordinate filter.
        package_roots: Additional package roots to scan.
        agent: Agent config for var resolution.
    """
    _, excludes = load_agent_config(rules_root, agent)
    rules = discover_rules(
        rules_root,
        filter_path=filter_path,
        filter_rule=filter_rule,
        package_roots=package_roots,
        excludes=excludes,
        agent=agent,
    )

    # Collect all rules_paths for scoring
    all_roots = [rules_root]
    if package_roots:
        all_roots.extend(package_roots)

    deltas: list[ScoreDelta] = []
    for rule in rules:
        pass_dir = rule.rule_dir / "tests" / "pass"
        fail_dir = rule.rule_dir / "tests" / "fail"

        if not rule.has_pass_fixture or not rule.has_fail_fixture:
            continue

        pass_score = score_fixture(pass_dir, all_roots)
        fail_score = score_fixture(fail_dir, all_roots)
        deltas.append(
            ScoreDelta(
                rule_id=rule.rule_id,
                slug=rule.slug,
                pass_score=round(pass_score, 1),
                fail_score=round(fail_score, 1),
                delta=round(pass_score - fail_score, 1),
            )
        )

    return deltas


# ── Rule lint ───────────────────────────────────────────────────────


@dataclass
class LintError:
    """A structural integrity error found in a rule."""

    rule_id: str
    check_name: str
    message: str


def _lint_single_rule(
    rule: RuleInfo,
    seen_ids: dict[str, Path],
    category_codes: dict[str, Any],
) -> list[LintError]:
    """Run lint checks on a single rule. Mutates seen_ids for duplicate tracking."""
    errors: list[LintError] = []

    # 1. ID-category match
    parts = rule.rule_id.split(":")
    if len(parts) >= 3:
        cat_code = parts[1]
        expected_cat = category_codes.get(cat_code)
        if expected_cat is None:
            errors.append(
                LintError(
                    rule_id=rule.rule_id,
                    check_name="id_category_match",
                    message=f"Unknown category code '{cat_code}' in rule ID",
                )
            )
        elif expected_cat.value != rule.category:
            errors.append(
                LintError(
                    rule_id=rule.rule_id,
                    check_name="id_category_match",
                    message=(
                        f"ID has category code '{cat_code}' ({expected_cat.value}) "
                        f"but category field is '{rule.category}'"
                    ),
                )
            )

    # 2. Check ID prefix
    expected_prefix = rule.rule_id.replace(":", ".")
    for check in rule.checks:
        check_id = check.get("id", "")
        if check_id and not check_id.startswith(expected_prefix + "."):
            errors.append(
                LintError(
                    rule_id=rule.rule_id,
                    check_name="check_id_prefix",
                    message=f"Check '{check_id}' does not start with '{expected_prefix}.'",
                )
            )

    # 3. No duplicate rule IDs
    if rule.rule_id in seen_ids:
        errors.append(
            LintError(
                rule_id=rule.rule_id,
                check_name="duplicate_rule_id",
                message=f"Duplicate rule ID (also at {seen_ids[rule.rule_id]})",
            )
        )
    else:
        seen_ids[rule.rule_id] = rule.rule_dir

    # 4. Required frontmatter
    for field_name, value in [
        ("id", rule.rule_id),
        ("slug", rule.slug),
        ("title", rule.title),
        ("category", rule.category),
        ("type", rule.rule_type),
    ]:
        if not value:
            errors.append(
                LintError(
                    rule_id=rule.rule_id or "(unknown)",
                    check_name="required_frontmatter",
                    message=f"Missing required field: {field_name}",
                )
            )

    # Severity requires re-reading frontmatter (not stored in RuleInfo)
    rule_md = rule.rule_dir / "rule.md"
    if rule_md.exists():
        meta = parse_frontmatter(rule_md.read_text(encoding="utf-8"))
        if meta and not meta.get("severity"):
            errors.append(
                LintError(
                    rule_id=rule.rule_id or "(unknown)",
                    check_name="required_frontmatter",
                    message="Missing required field: severity",
                )
            )

    return errors


def lint_rules(rules: list[RuleInfo]) -> list[LintError]:
    """Run structural integrity checks on all discovered rules.

    Checks:
    1. ID-category match — category code in rule ID matches category field
    2. Check ID prefix — all check IDs start with the dotted rule ID prefix
    3. No duplicate rule IDs — across all namespaces
    4. Required frontmatter — id, slug, title, category, type, severity present
    """
    from reporails_cli.core.models import CATEGORY_CODES

    errors: list[LintError] = []
    seen_ids: dict[str, Path] = {}

    for rule in rules:
        errors.extend(_lint_single_rule(rule, seen_ids, CATEGORY_CODES))

    return errors


# ── Coverage baseline ──────────────────────────────────────────────


@dataclass
class BaselineEntry:
    """A single entry in the expected-rules baseline."""

    rule_id: str
    slug: str
    has_fixtures: bool


def export_baseline(
    rules_root: Path,
    *,
    package_roots: list[Path] | None = None,
    agent: str = "claude",
) -> list[BaselineEntry]:
    """Export all discovered rule coordinates as a baseline.

    Args:
        rules_root: Primary rules repository root.
        package_roots: Additional package roots to scan.
        agent: Agent config for var resolution.
    """
    _, excludes = load_agent_config(rules_root, agent)
    rules = discover_rules(
        rules_root,
        package_roots=package_roots,
        excludes=excludes,
        agent=agent,
    )

    return [
        BaselineEntry(
            rule_id=r.rule_id,
            slug=r.slug,
            has_fixtures=r.has_pass_fixture or r.has_fail_fixture,
        )
        for r in rules
    ]


@dataclass
class CoverageGap:
    """A rule expected in the baseline but missing or lacking fixtures."""

    rule_id: str
    reason: str


def check_coverage(
    rules_root: Path,
    baseline: list[dict[str, Any]],
    *,
    package_roots: list[Path] | None = None,
    agent: str = "claude",
) -> list[CoverageGap]:
    """Check current rules against an expected-rules baseline.

    Args:
        rules_root: Primary rules repository root.
        baseline: List of baseline entries (dicts with rule_id, slug, has_fixtures).
        package_roots: Additional package roots to scan.
        agent: Agent config for var resolution.

    Returns:
        List of gaps (missing rules or rules without fixtures).
    """
    _, excludes = load_agent_config(rules_root, agent)
    rules = discover_rules(
        rules_root,
        package_roots=package_roots,
        excludes=excludes,
        agent=agent,
    )

    current_ids = {r.rule_id for r in rules}
    current_map = {r.rule_id: r for r in rules}

    gaps: list[CoverageGap] = []
    for entry in baseline:
        rule_id = entry["rule_id"]
        if rule_id not in current_ids:
            gaps.append(CoverageGap(rule_id=rule_id, reason="missing"))
        elif entry.get("has_fixtures") and not (
            current_map[rule_id].has_pass_fixture or current_map[rule_id].has_fail_fixture
        ):
            gaps.append(CoverageGap(rule_id=rule_id, reason="fixtures removed"))

    return gaps
