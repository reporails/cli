"""Rule harness engine — validates rules against their own test fixtures.

Discovers rules, loads agent config, runs mechanical + deterministic +
content-query checks against pass/fail fixtures. Produces per-rule
pass/fail results.

Uses the same check engines as production validation (ails check):
- Mechanical: dispatch_single_check from core.mechanical.runner
- Deterministic: compile_check and scan_ruleset from core.lint.regex
- Content query: maps the fixture with the real mapper and evaluates it
  through `content_checker._evaluate_check` — the same dispatch `ails
  check` runs content_query checks through.
- Semantic: always pass (no LLM in harness mode)
"""

from __future__ import annotations

import logging
import shutil
from collections.abc import Callable
from functools import partial
from pathlib import Path

from reporails_cli.core.discovery.exclusions import no_exclusions
from reporails_cli.core.lint.content_checker import _evaluate_check
from reporails_cli.core.lint.harness_discovery import (
    _build_prefix_to_agent_map,
    _classify_fixture,
    _fixture_files,
    _rule_matches_exclude,
    apply_check_inheritance,
    discover_rules,
    load_agent_config,
)
from reporails_cli.core.lint.harness_models import HarnessStatus, fixture_cases, has_fail_fixture, has_pass_fixture
from reporails_cli.core.lint.mechanical.runner import UnknownCheckError, run_mechanical_check
from reporails_cli.core.lint.regex import scan_ruleset
from reporails_cli.core.lint.regex.compiler import compile_check
from reporails_cli.core.lint.rule_scaffold import (
    _scaffold_fail_fixture,
    _scaffold_fixture,
    _scaffold_main_filename,
    _scaffold_scoped_rule_file,
)
from reporails_cli.core.mapper.models import Models
from reporails_cli.core.mapper.pipeline import map_ruleset
from reporails_cli.core.platform.contract.json_value import JsonObject, as_list, as_object
from reporails_cli.core.platform.dto.checks import CheckResult
from reporails_cli.core.platform.dto.lint import CheckRun, CompiledCheck, CompiledRuleSet, HarnessResult, RuleInfo
from reporails_cli.core.platform.dto.models import Check, ClassifiedFile, FileTypeDeclaration, Rule
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.policy.matching import deterministic_targets
from reporails_cli.core.platform.rules.registry import RuleReadError, read_rule

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
        result = run_mechanical_check(
            check, fixture_root, classified_files, extra_args=extra_args, exclusions=no_exclusions(fixture_root)
        )
    except UnknownCheckError:
        logger.warning("Unknown mechanical check: %s", check.check)
        return CheckResult(passed=False, message=f"Unknown mechanical check: {check.check}")
    if result is None:
        return CheckResult(passed=True, message="No skill entry file in scope")

    if check.expect == "absent":
        result = CheckResult(passed=not result.passed, message=result.message, annotations=result.annotations)

    return result


def _run_deterministic_check(
    check: Check,
    fixture_root: Path,
    platform_rule: Rule | str,
    targets: list[Path],
) -> tuple[bool, int, str]:
    """Run a deterministic check via the CLI regex engine against fixtures.

    `targets` are the fixture files the rule's `match` selects, as in `ails check`.
    `platform_rule` is the loaded rule, or the message saying why it did not load.

    Returns:
        Tuple of (engine_ok, findings_count, message).
    """
    if isinstance(platform_rule, str):
        return False, 0, platform_rule

    compiled = compile_check(check)

    try:
        findings = _count_findings(compiled, fixture_root, targets)
        return True, findings, f"{findings} finding(s)"
    except Exception as exc:  # pylint: disable=broad-exception-caught  # the harness reports an engine failure as a result instead of aborting the batch
        logger.warning("Regex engine error for check %s: %s", check.id, exc)
        return False, 0, f"Regex engine error: {exc}"


def _count_findings(compiled: CompiledCheck, fixture_root: Path, targets: list[Path]) -> int:
    """How many findings the compiled check reports on `targets`; none when there is no target."""
    if not targets:
        return 0
    sarif = scan_ruleset(
        CompiledRuleSet(checks=[compiled]),
        fixture_root,
        targets,
    )
    return sum(len(as_list(as_object(run).get("results"))) for run in as_list(sarif.get("runs")))


def _build_platform_rule(rule: RuleInfo) -> Rule | str:
    """Build the `Rule` object content_checker's shared dispatch expects, or say why it did not load.

    Loads `rule.md` + `checks.yml` through the same registry loader `ails
    check` loads rules through, so a content_query check's severity, fix
    text, and match targeting come from the identical construction path
    instead of a harness-only rebuild.
    """
    try:
        read = read_rule(rule.rule_dir / "rule.md")
    except RuleReadError as exc:
        return f"could not load rule {rule.rule_id}: {exc}"
    if read is None or read.rule.id != rule.rule_id:
        return f"could not load rule {rule.rule_id} for evaluation"
    platform_rule = read.rule
    return platform_rule


def fixture_mapper(models: Models) -> Callable[[Path], RulesetMap]:
    """A map of a fixture directory with the real mapper, made with `models`.

    A rule with more than one content_query check maps its fixture once, not once per check.
    """
    maps: dict[Path, RulesetMap] = {}

    def map_fixture(fixture_root: Path) -> RulesetMap:
        mapped = maps.get(fixture_root)
        if mapped is None:
            mapped = maps[fixture_root] = map_ruleset(
                _fixture_files(fixture_root), models=models, root=fixture_root, cache_dir=None
            )
        return mapped

    return map_fixture


def _run_content_query_check(
    check: Check,
    fixture_root: Path,
    platform_rule: Rule | str,
    classified: list[ClassifiedFile],
    map_fixture: Callable[[Path], RulesetMap],
) -> tuple[bool, str]:
    """Evaluate one content_query check against a fixture.

    Maps the fixture with the real mapper, then runs the check through the
    same `content_checker._evaluate_check` dispatch `ails check` uses for
    content_query checks — one evaluation path, not a second harness-only
    implementation. Returns (violation_found, message).
    """
    if isinstance(platform_rule, str):
        return False, f"content_query — {platform_rule}"

    ruleset_map = map_fixture(fixture_root)
    if not ruleset_map.files:
        return False, "content_query — no fixture files"

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
    if has_pass_fixture(rule):
        fixtures.append(("pass", "pass", rule.rule_dir / "tests" / "pass"))
    if has_fail_fixture(rule):
        fixtures.append(("fail", "fail", rule.rule_dir / "tests" / "fail"))
    for name, case_dir in fixture_cases(rule)[0]:
        fixtures.append((f"case {name}", "pass" if name.startswith("pass-") else "fail", case_dir))
    return fixtures


def run_rule(
    rule: RuleInfo,
    file_types: list[FileTypeDeclaration],
    map_fixture: Callable[[Path], RulesetMap],
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
    result.cases_not_run = fixture_cases(rule)[1]

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

    platform_rule = _build_platform_rule(rule)
    for label, kind, fixture_dir in fixtures:
        cleanup, effective_dir = _prepare_fixture(fixture_dir, kind, rule, file_types)
        try:
            violation_found = _run_fixture_checks(
                rule,
                platform_rule,
                file_types,
                map_fixture,
                kind=kind,
                label=label,
                effective_dir=effective_dir,
                result=result,
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
    platform_rule: Rule | str,
    file_types: list[FileTypeDeclaration],
    map_fixture: Callable[[Path], RulesetMap],
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
    run_check = _fixture_check_runner(platform_rule, file_types, map_fixture, kind=kind, fixture_root=effective_dir)
    violation_found = False
    extra: JsonObject = {}
    for check in rule.checks:
        ok, run, raw = run_check(check, extra)
        if kind == "pass" and not ok:
            result.status = HarnessStatus.FAILED
        violation_found = violation_found or (kind != "pass" and ok)
        run.fixture = label
        result.check_runs.append(run)
        if raw is not None and raw.annotations:
            extra.update(raw.annotations)
    return violation_found


def _fixture_check_runner(
    platform_rule: Rule | str,
    file_types: list[FileTypeDeclaration],
    map_fixture: Callable[[Path], RulesetMap],
    *,
    kind: str,
    fixture_root: Path,
) -> Callable[[Check, JsonObject | None], tuple[bool, CheckRun, CheckResult | None]]:
    """The check runner of one fixture directory, bound to what its checks share.

    The fixture is classified once, and the files the rule's `match` selects are
    worked out once, for all of the rule's checks.
    """
    classified = _classify_fixture(fixture_root, file_types)
    targets = (
        []
        if isinstance(platform_rule, str)
        else deterministic_targets(platform_rule.match, _fixture_files(fixture_root), classified)
    )
    return partial(
        _check_fixture if kind == "pass" else _check_fixture_for_violation,
        fixture_root=fixture_root,
        classified=classified,
        platform_rule=platform_rule,
        targets=targets,
        map_fixture=map_fixture,
    )


def _check_fixture(
    check: Check,
    extra_args: JsonObject | None,
    *,
    fixture_root: Path,
    classified: list[ClassifiedFile],
    platform_rule: Rule | str,
    targets: list[Path],
    map_fixture: Callable[[Path], RulesetMap],
) -> tuple[bool, CheckRun, CheckResult | None]:
    """Run a check against a pass fixture. Returns (passed, CheckRun, raw_result).

    `raw_result` is the mechanical-check `CheckResult` (with annotations),
    or None for non-mechanical paths; the caller threads annotations into
    subsequent checks via the `extra_args` parameter and names the fixture on the run.
    """
    check_id, check_type = check.id, check.type
    if check_type == "mechanical":
        cr = _run_mechanical_check(check, fixture_root, classified, extra_args=extra_args)
        return cr.passed, CheckRun(check_id, check_type, "pass", cr.passed, cr.message), cr

    if check_type == "deterministic":
        ok, count, msg = _run_deterministic_check(check, fixture_root, platform_rule, targets)
        passed = (ok and count > 0) if check.expect == "present" else (ok and count == 0)
        return passed, CheckRun(check_id, check_type, "pass", passed, msg), None

    ok, msg = _run_content_query_check(check, fixture_root, platform_rule, classified, map_fixture)
    passed = not ok
    return passed, CheckRun(check_id, check_type, "pass", passed, msg), None


def _check_fixture_for_violation(
    check: Check,
    extra_args: JsonObject | None,
    *,
    fixture_root: Path,
    classified: list[ClassifiedFile],
    platform_rule: Rule | str,
    targets: list[Path],
    map_fixture: Callable[[Path], RulesetMap],
) -> tuple[bool, CheckRun, CheckResult | None]:
    """Run a check against a fail fixture. Returns (violation_found, CheckRun, raw_result).

    Same annotation-threading contract as `_check_fixture`: the raw
    `CheckResult` propagates so accumulator state survives chained checks.
    """
    check_id, check_type = check.id, check.type
    if check_type == "mechanical":
        cr = _run_mechanical_check(check, fixture_root, classified, extra_args=extra_args)
        return not cr.passed, CheckRun(check_id, check_type, "fail", True, cr.message), cr

    if check_type == "deterministic":
        ok, count, msg = _run_deterministic_check(check, fixture_root, platform_rule, targets)
        violation = (ok and count == 0) if check.expect == "present" else (ok and count > 0)
        return violation, CheckRun(check_id, check_type, "fail", True, msg), None

    violation, msg = _run_content_query_check(check, fixture_root, platform_rule, classified, map_fixture)
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
    models: Models,
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
        models: The models the fixtures are mapped with.
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

    return _run_rules(rules, prefix_map, agent_cache, default_file_types, models)


def _run_rules(
    rules: list[RuleInfo],
    prefix_map: dict[str, str],
    agent_cache: dict[str, tuple[list[FileTypeDeclaration], list[str]]],
    default_file_types: list[FileTypeDeclaration],
    models: Models,
) -> list[HarnessResult]:
    """Run each rule with its agent's file types, skipping the rules its agent config excludes."""
    results: list[HarnessResult] = []
    map_fixture = fixture_mapper(models)
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
        results.append(run_rule(rule, rule_file_types, map_fixture))

    return results
