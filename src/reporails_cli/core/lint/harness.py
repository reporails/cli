"""Rule harness engine — validates rules against their own test fixtures.

Discovers rules, loads agent config, runs mechanical + deterministic +
content-query checks against pass/fail fixtures. Produces per-rule
pass/fail results.

Uses the same check engines as production validation (ails check):
- Mechanical: dispatch_single_check from core.mechanical.runner
- Deterministic: compile_rules and scan_ruleset from core.lint.regex
- Content query: maps the fixture with the real mapper and evaluates it
  through `content_checker._evaluate_check` — the same dispatch `ails
  check` runs content_query checks through.
- Semantic: always pass (no LLM in harness mode)
"""

from __future__ import annotations

import functools
import logging
import shutil
from pathlib import Path

from reporails_cli.core.lint.content_checker import _evaluate_check
from reporails_cli.core.lint.harness_discovery import (
    _build_prefix_to_agent_map,
    _classify_fixture,
    _rule_matches_exclude,
    apply_check_inheritance,
    discover_rules,
    load_agent_config,
)
from reporails_cli.core.lint.harness_models import (
    _FIXTURE_EXCLUDES,
    CheckRun,
    HarnessResult,
    HarnessStatus,
    RuleInfo,
)
from reporails_cli.core.lint.mechanical.runner import UnknownCheckError, run_mechanical_check
from reporails_cli.core.lint.regex import scan_ruleset
from reporails_cli.core.lint.regex.compiler import CompiledCheck, CompiledRuleSet, compile_rules
from reporails_cli.core.lint.rule_scaffold import (
    _scaffold_fail_fixture,
    _scaffold_fixture,
    _scaffold_main_filename,
    _scaffold_scoped_rule_file,
)
from reporails_cli.core.mapper.pipeline import map_ruleset
from reporails_cli.core.platform.adapters.registry import RuleReadError, _load_from_path, read_checks_document
from reporails_cli.core.platform.adapters.rule_builder import load_checks
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object
from reporails_cli.core.platform.dto.checks import CheckResult
from reporails_cli.core.platform.dto.models import Check, ClassifiedFile, FileTypeDeclaration, Rule
from reporails_cli.core.platform.dto.ruleset import RulesetMap

logger = logging.getLogger(__name__)

# ── Check execution ─────────────────────────────────────────────────


def _run_mechanical_check(
    check: Check,
    fixture_root: Path,
    classified_files: list[ClassifiedFile],
    extra_args: JsonObject | None = None,
) -> CheckResult:
    """Run a single mechanical check against a fixture directory.

    `extra_args` carries annotations from prior mechanical checks in the
    same rule chain (e.g. `discovered_markdown_links` flowing from
    `extract_markdown_links` into `check_markdown_link_targets_exist`).
    Merged below the check's own declared args so checks.yml entries
    always win over upstream annotations.
    """
    try:
        result = run_mechanical_check(check, fixture_root, classified_files, extra_args=extra_args)
    except UnknownCheckError:
        logger.warning("Unknown mechanical check: %s", check.check)
        return CheckResult(passed=False, message=f"Unknown mechanical check: {check.check}")
    if result is None:
        return CheckResult(passed=True, message="No skill entry file in scope")

    if check.expect == "absent":
        result = CheckResult(passed=not result.passed, message=result.message, annotations=result.annotations)

    return result


def _find_compiled_check(ruleset: CompiledRuleSet, check_id: str) -> CompiledCheck | None:
    """The compiled check for a check id; a file with a single check serves any check id."""
    dotted = check_id.replace(":", ".")
    for compiled in ruleset.checks:
        if compiled.id == dotted:
            return compiled
    return ruleset.checks[0] if len(ruleset.checks) == 1 else None


def _no_checks_message(checks_yml: Path) -> str:
    """Why `checks_yml` compiled no checks: the problem that refuses its checks, else that it holds none."""
    try:
        load_checks(read_checks_document(checks_yml))
    except RuleReadError as exc:
        return str(exc)
    except ValueError as exc:
        return f"{checks_yml}: {exc}"
    return "checks.yml has no patterns (checks: [])"


def _run_deterministic_check(
    checks_yml: Path,
    check: Check,
    fixture_root: Path,
) -> tuple[bool, int, str]:
    """Run a deterministic check via the CLI regex engine against fixtures.

    Returns:
        Tuple of (engine_ok, findings_count, message).
    """
    if not checks_yml.exists():
        return False, 0, f"checks.yml not found: {checks_yml}"

    ruleset = compile_rules([checks_yml])
    if not ruleset.checks:
        return False, 0, _no_checks_message(checks_yml)

    compiled = _find_compiled_check(ruleset, check.id)
    if compiled is None:
        return False, 0, f"No pattern for check {check.id} in checks.yml"

    try:
        # Discover all files in fixture for path filtering
        fixture_files = [f for f in fixture_root.rglob("*") if f.is_file() and f.name not in _FIXTURE_EXCLUDES]
        sarif = scan_ruleset(
            CompiledRuleSet(checks=[compiled]),
            fixture_root,
            instruction_files=fixture_files if fixture_files else None,
        )
        findings = 0
        for run in as_list(sarif.get("runs")):
            findings += len(as_list(as_object(run).get("results")))
        return True, findings, f"{findings} finding(s)"
    except Exception as exc:  # pylint: disable=broad-exception-caught  # the harness reports an engine failure as a result instead of aborting the batch
        logger.warning("Regex engine error for check %s: %s", check.id, exc)
        return False, 0, f"Regex engine error: {exc}"


def _build_platform_rule(rule: RuleInfo) -> Rule | None:
    """Build the `Rule` object content_checker's shared dispatch expects.

    Loads `rule.md` + `checks.yml` through the same registry loader `ails
    check` loads rules through, so a content_query check's severity, fix
    text, and match targeting come from the identical construction path
    instead of a harness-only rebuild.
    """
    rules = _load_from_path(rule.rule_dir)
    return rules.get(rule.rule_id)


@functools.cache
def _map_fixture(fixture_root: Path) -> RulesetMap:
    """Map a fixture directory with the real mapper.

    Cached per fixture directory so a rule with more than one
    content_query check maps its fixture once, not once per check.
    """
    files = [f for f in fixture_root.rglob("*") if f.is_file() and f.name not in _FIXTURE_EXCLUDES]
    return map_ruleset(files, root=fixture_root, cache_dir=None)


def _run_content_query_check(
    check: Check,
    fixture_root: Path,
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
) -> tuple[bool, str]:
    """Evaluate one content_query check against a fixture.

    Maps the fixture with the real mapper, then runs the check through the
    same `content_checker._evaluate_check` dispatch `ails check` uses for
    content_query checks — one evaluation path, not a second harness-only
    implementation. Returns (violation_found, message).
    """
    platform_rule = _build_platform_rule(rule)
    if platform_rule is None:
        return False, f"content_query — could not load rule {rule.rule_id} for evaluation"

    ruleset_map = _map_fixture(fixture_root)
    if not ruleset_map.files:
        return False, "content_query — no fixture files"

    classified = _classify_fixture(fixture_root, file_types)
    findings = _evaluate_check(ruleset_map, check, platform_rule, classified)
    if findings:
        return True, findings[0].message
    return False, f"content_query: {check.query} — no violation"


# ── Rule runner ─────────────────────────────────────────────────────


def _prepare_fixture(
    fixture_dir: Path,
    kind: str,
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
) -> tuple[list[Path], Path]:
    """Prepare one fixture directory (`kind` is "pass" or "fail") for running.

    Applies the agent-main-filename rename first — so a CORE fixture's
    `CLAUDE.md` matches the target agent's own main-file convention — then
    the scoped-rule-file relocation (a CORE fixture's `.claude/rules/**`
    file moved to the target agent's own scoped-rule layout), then layers
    the existing mechanical-check scaffolds (`file_exists`, `directory_exists`,
    etc.) on top of that base. Every produced temp directory is collected
    for cleanup by the caller.

    Returns (dirs_to_clean_up, effective_fixture_dir).
    """
    cleanup: list[Path] = []
    base = fixture_dir
    renamed = _scaffold_main_filename(fixture_dir, file_types)
    if renamed:
        cleanup.append(renamed)
        base = renamed
    relocated = _scaffold_scoped_rule_file(base, file_types, rule.checks)
    if relocated:
        cleanup.append(relocated)
        base = relocated

    scaffold = _scaffold_fixture if kind == "pass" else _scaffold_fail_fixture
    scaffolded = scaffold(base, rule.checks, file_types)
    if scaffolded:
        cleanup.append(scaffolded)
    return cleanup, scaffolded if scaffolded else base


def _fixtures_of(rule: RuleInfo) -> list[tuple[str, str, Path]]:
    """`(label, kind, directory)` for every fixture the rule runs: pass, fail, then each named case."""
    fixtures: list[tuple[str, str, Path]] = []
    if rule.has_pass_fixture:
        fixtures.append(("pass", "pass", rule.rule_dir / "tests" / "pass"))
    if rule.has_fail_fixture:
        fixtures.append(("fail", "fail", rule.rule_dir / "tests" / "fail"))
    for name, case_dir in rule.fixture_cases()[0]:
        fixtures.append((f"case {name}", "pass" if name.startswith("pass-") else "fail", case_dir))
    return fixtures


def run_rule(
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
) -> HarnessResult:
    """Run all checks for a rule against its fixtures.

    Follows asymmetric pass/fail contract:
    - Pass fixture (`tests/pass`, each `tests/cases/pass-*`): ALL checks must
      pass (no violations).
    - Fail fixture (`tests/fail`, each `tests/cases/fail-*`): AT LEAST ONE
      check must detect a violation.
    - Semantic checks: always pass (skipped, no LLM).
    - Any other `tests/cases/` entry is not run and is named in `cases_not_run`.
    """
    result = HarnessResult(
        rule_id=rule.rule_id,
        slug=rule.slug,
        title=rule.title,
        status=HarnessStatus.PASSED,
    )
    result.cases_not_run = rule.fixture_cases()[1]

    if rule.load_failure:
        result.status = HarnessStatus.FAILED
        result.messages.append(rule.load_failure)
        return result

    if not rule.has_checks:
        result.status = HarnessStatus.NOT_IMPLEMENTED
        result.messages.append("checks: [] — not implemented")
        return result

    fixtures = _fixtures_of(rule)
    if not fixtures:
        result.status = HarnessStatus.NO_FIXTURES
        result.messages.append("No test fixtures (tests/pass/, tests/fail/ or tests/cases/ empty)")
        return result

    for label, kind, fixture_dir in fixtures:
        cleanup, effective_dir = _prepare_fixture(fixture_dir, kind, rule, file_types)
        try:
            violation_found = _run_fixture_checks(
                rule, file_types, kind=kind, label=label, effective_dir=effective_dir, result=result
            )
        finally:
            for scaffolded_dir in cleanup:
                shutil.rmtree(scaffolded_dir, ignore_errors=True)
        if label.startswith("case "):
            result.cases_run.append(label[len("case ") :])
        if kind == "fail" and not violation_found:
            result.status = HarnessStatus.FAILED
            what = "Fail fixture" if label == "fail" else f"Case {label[len('case ') :]}"
            result.messages.append(f"{what}: no check detected a violation")

    return result


def _run_fixture_checks(
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
    *,
    kind: str,
    label: str,
    effective_dir: Path,
    result: HarnessResult,
) -> bool:
    """Run every check of the rule against one fixture directory.

    Threads a per-fixture annotation accumulator so chained checks like
    `extract_markdown_links` -> `check_markdown_link_targets_exist` see
    each other's `discovered_*` annotations; each fixture has its own, so an
    annotation never bleeds from one fixture into another.
    Returns whether a fail fixture saw at least one violation.
    """
    violation_found = False
    extra: JsonObject = {}
    for check in rule.checks:
        if kind == "pass":
            passed, run, raw = _check_fixture(check, effective_dir, rule, file_types, label, extra_args=extra)
            if not passed:
                result.status = HarnessStatus.FAILED
        else:
            violation, run, raw = _check_fixture_for_violation(check, effective_dir, rule, file_types, extra_args=extra)
            run.fixture = label
            violation_found = violation_found or violation
        result.check_runs.append(run)
        if raw is not None and raw.annotations:
            extra.update(raw.annotations)
    return violation_found


def _check_fixture(
    check: Check,
    fixture_root: Path,
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
    fixture_name: str,
    *,
    extra_args: JsonObject | None = None,
) -> tuple[bool, CheckRun, CheckResult | None]:
    """Run a check against a pass fixture. Returns (passed, CheckRun, raw_result).

    `raw_result` is the mechanical-check `CheckResult` (with annotations),
    or None for non-mechanical paths; the caller threads annotations into
    subsequent checks via the `extra_args` parameter.
    """
    check_id, check_type, expect = check.id, check.type, check.expect
    if check_type == "mechanical":
        classified = _classify_fixture(fixture_root, file_types)
        cr = _run_mechanical_check(check, fixture_root, classified, extra_args=extra_args)
        return cr.passed, CheckRun(check_id, check_type, fixture_name, cr.passed, cr.message), cr

    if check_type == "deterministic":
        ok, count, msg = _run_deterministic_check(
            rule.inherited_checks_yml.get(check_id, rule.checks_yml), check, fixture_root
        )
        passed = (ok and count > 0) if expect == "present" else (ok and count == 0)
        return passed, CheckRun(check_id, check_type, fixture_name, passed, msg), None

    ok, msg = _run_content_query_check(check, fixture_root, rule, file_types)
    passed = not ok
    return passed, CheckRun(check_id, check_type, fixture_name, passed, msg), None


def _check_fixture_for_violation(
    check: Check,
    fixture_root: Path,
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
    *,
    extra_args: JsonObject | None = None,
) -> tuple[bool, CheckRun, CheckResult | None]:
    """Run a check against a fail fixture. Returns (violation_found, CheckRun, raw_result).

    Same annotation-threading contract as `_check_fixture`: the raw
    `CheckResult` propagates so accumulator state survives chained checks.
    """
    check_id, check_type, expect = check.id, check.type, check.expect
    if check_type == "mechanical":
        classified = _classify_fixture(fixture_root, file_types)
        cr = _run_mechanical_check(check, fixture_root, classified, extra_args=extra_args)
        violation = not cr.passed
        return violation, CheckRun(check_id, check_type, "fail", True, cr.message), cr

    if check_type == "deterministic":
        ok, count, msg = _run_deterministic_check(
            rule.inherited_checks_yml.get(check_id, rule.checks_yml), check, fixture_root
        )
        violation = (ok and count == 0) if expect == "present" else (ok and count > 0)
        return violation, CheckRun(check_id, check_type, "fail", True, msg), None

    violation, msg = _run_content_query_check(check, fixture_root, rule, file_types)
    return violation, CheckRun(check_id, check_type, "fail", True, msg), None


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
    # Runner-only: merge inherited (`supersedes:`/`inherited:`) checks into
    # each successor rule so its fixtures exercise the same check set `ails
    # check` runs at runtime. `lint_rules` discovers rules separately and
    # never sees this merge (see `apply_check_inheritance`'s docstring).
    apply_check_inheritance(rules)

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
