"""Rule loading and resolution. Loads rules from directories, applies filters and overrides."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from fnmatch import fnmatch
from functools import cache, lru_cache
from pathlib import Path
from typing import NamedTuple

import yaml

from reporails_cli.core.platform.adapters.rule_builder import RuleFieldError, build_rule, load_checks
from reporails_cli.core.platform.config.bootstrap import get_package_paths
from reporails_cli.core.platform.config.capabilities import agent_capabilities
from reporails_cli.core.platform.config.config import (
    get_agent_config,
    get_project_config,
    get_rules_path,
    iter_agent_configs,
)
from reporails_cli.core.platform.contract.errors import ConfigUnreadableError
from reporails_cli.core.platform.contract.json_value import JsonObject, as_str
from reporails_cli.core.platform.dto.models import Check, Execution, FieldProblem, Rule, RuleType, Severity
from reporails_cli.core.platform.dto.results import AgentConfig, ProjectConfig
from reporails_cli.core.platform.policy.applicability import filter_by_capability
from reporails_cli.core.platform.utils.utils import (
    load_yaml_file,
    read_frontmatter,
    unreadable_file_problem,
)

logger = logging.getLogger(__name__)


@lru_cache(maxsize=8)
def structural_rule_ids(agent: str = "") -> frozenset[str]:
    """Bundled rule ids of the structural family — mechanical rules that run locally (bundled rules only).

    These check section / config / file presence and hygiene. Sourced from the registry
    (single source of truth).

    Must be resolved with the SAME agent the findings were produced under: an agent
    rule that supersedes a core structural rule (e.g. `CODEX:E:0001` superseding
    `CORE:E:0001`) replaces it under the agent's id, so the no-agent (core-only) set
    would miss it and the finding under the agent's id would not be counted as structural.
    """
    rules = load_rules(agent=agent)
    return frozenset(
        rid for rid, rule in rules.items() if rule.type == RuleType.MECHANICAL and rule.execution == Execution.LOCAL
    )


@lru_cache(maxsize=8)
def registry_rule_ids(agent: str = "") -> frozenset[str]:
    """Every bundled rule id the registry defines under `agent` (bundled rules only; package rules are not in it)."""
    return frozenset(load_rules(agent=agent))


def _file_level_ids(rules: Mapping[str, Rule]) -> frozenset[str]:
    """Ids of the content checks of `rules` that require something in a file."""
    return frozenset(
        check.id
        for rule in rules.values()
        for check in rule.checks
        if check.type == "content_query" and check.expect == "present" and check.id
    )


@lru_cache(maxsize=8)
def file_level_check_ids(agent: str = "") -> frozenset[str]:
    """Ids of the bundled content checks that require something in a file (bundled rules only).

    A finding from one of these concerns the whole file: there is no line to point at.
    """
    return _file_level_ids(load_rules(agent=agent))


def convention_check_ids(rules: Mapping[str, Rule]) -> frozenset[str]:
    """Ids of the checks of `rules` flagged `convention: true`: their finding names a missing convention."""
    return frozenset(check.id for rule in rules.values() for check in rule.checks if check.convention and check.id)


def whole_run_check_ids(rules: Mapping[str, Rule]) -> frozenset[str]:
    """Ids of the checks of `rules` whose finding stands for the matched files as a whole.

    These are the content checks that require something in a file and the project-aggregate
    checks: neither points at one file or line.
    """
    return _file_level_ids(rules) | frozenset(
        check.id for rule in rules.values() for check in rule.checks if check.project_scope and check.id
    )


def rule_dependencies(rules: Mapping[str, Rule]) -> dict[str, frozenset[str]]:
    """`{rule id: the rule ids it depends on}` across `rules`, resolved through supersession.

    A dependency on a rule an agent rule supersedes names the superseding rule, which carries
    the findings under its own id.
    """
    successor = {r.supersedes: rid for rid, r in rules.items() if r.supersedes}
    return {
        rid: frozenset(successor.get(dep, dep) for dep in rule.depends_on)
        for rid, rule in rules.items()
        if rule.depends_on
    }


def get_rules_dir() -> Path:
    """Get rules directory (~/.reporails/rules/)."""
    return get_rules_path()


def _load_from_path(path: Path) -> dict[str, Rule]:
    """Load the bundled framework rules of a single directory, returning {id: Rule}. Cached per path."""
    if not path.exists():
        return {}
    return dict(_read_rules(path))


@cache
def _read_rules(path: Path) -> dict[str, Rule]:
    """Read every rule under a framework `path`. Cached per path: framework rules do not change within a run."""
    return _scan_rules(path)


class RuleReadError(ValueError):
    """A rule that cannot be built from its `rule.md` and `checks.yml`.

    `path` is the file at fault and `problem` what is wrong with it; the message is `<path>: <problem>`.
    `problem` is empty when the failure is only rejected `rule.md` fields: the message is then one
    `<path>: <field>: <message>` line per entry of `field_problems`.
    `frontmatter` is whatever the rule's frontmatter yielded before the failure (empty when unread).
    `checks` are the checks that built (empty when the checks failed); `field_problems` the
    `rule.md` fields the build rejected.
    """

    def __init__(
        self,
        path: Path,
        problem: str,
        frontmatter: JsonObject,
        *,
        checks: list[Check] | None = None,
        field_problems: tuple[FieldProblem, ...] = (),
    ) -> None:
        if problem or not field_problems:
            super().__init__(f"{path}: {problem}")
        else:
            super().__init__("\n".join(f"{path}: {p.field}: {p.message}" for p in field_problems))
        self.path = path
        self.problem = problem
        self.frontmatter = frontmatter
        self.checks = checks or []
        self.field_problems = field_problems


def _rejected_fields(
    frontmatter: JsonObject, md_path: Path, yml_path: Path | None, checks: list[Check]
) -> tuple[FieldProblem, ...]:
    """The `rule.md` fields of a non-empty `frontmatter` that do not validate; empty when it is unread."""
    if not frontmatter:
        return ()
    try:
        build_rule(frontmatter, md_path, yml_path, checks)
    except RuleFieldError as exc:
        return tuple(exc.problems)
    return ()


def read_checks_document(yml_path: Path) -> JsonObject:
    """The top-level mapping of the `checks.yml` at `yml_path` (empty for an empty file).

    Raises RuleReadError naming the file and the problem when it is unreadable, not UTF-8,
    not valid YAML, or not a mapping.
    """
    try:
        data = load_yaml_file(yml_path)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise RuleReadError(yml_path, unreadable_file_problem(exc), {}) from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise RuleReadError(yml_path, f"must be a mapping with a `checks` list, not a {type(data).__name__}", {})
    return data


class RuleRead(NamedTuple):
    """A rule built from its files, with the frontmatter mapping it was built from."""

    rule: Rule
    frontmatter: JsonObject


def read_rule(md_path: Path) -> RuleRead | None:
    """The rule built from the `rule.md` at `md_path` and its sibling `checks.yml`, fresh from disk.

    Returns None when the file has no frontmatter mapping. Raises RuleReadError naming the file
    and the problem when the rule or its checks cannot be read or built.
    """
    try:
        raw = md_path.read_bytes()
    except OSError as exc:
        raise RuleReadError(md_path, f"cannot be read ({exc.strerror or exc})", {}) from exc
    try:
        content = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        recovered = read_frontmatter(raw.decode("utf-8", errors="replace")).data
        raise RuleReadError(
            md_path,
            "is not UTF-8 text",
            recovered or {},
            field_problems=_rejected_fields(recovered or {}, md_path, None, []),
        ) from exc
    frontmatter = read_frontmatter(content).data
    if not frontmatter:
        return None

    checks_yml = md_path.parent / "checks.yml"
    yml_path: Path | None = checks_yml if checks_yml.exists() else None
    checks_source = md_path
    if yml_path is not None and not frontmatter.get("checks"):
        checks_source = yml_path
        try:
            frontmatter["checks"] = read_checks_document(yml_path).get("checks") or []
        except RuleReadError as exc:
            raise RuleReadError(
                exc.path,
                exc.problem,
                frontmatter,
                field_problems=_rejected_fields(frontmatter, md_path, yml_path, []),
            ) from exc
    try:
        checks = load_checks(frontmatter)
    except ValueError as exc:
        raise RuleReadError(
            checks_source,
            str(exc),
            frontmatter,
            field_problems=_rejected_fields(frontmatter, md_path, yml_path, []),
        ) from exc
    try:
        return RuleRead(build_rule(frontmatter, md_path, yml_path, checks), frontmatter)
    except RuleFieldError as exc:
        raise RuleReadError(md_path, "", frontmatter, checks=checks, field_problems=tuple(exc.problems)) from exc


def _scan_rules(path: Path) -> dict[str, Rule]:
    """Read every rule under `path`, fresh from disk; a rule that cannot be read is logged and skipped."""
    rules: dict[str, Rule] = {}

    for md_path in path.rglob("rule.md"):
        # Skip test fixtures and deferred (not-yet-ready) rules
        if "tests" in md_path.parts or "_deferred" in md_path.parts:
            continue
        try:
            read = read_rule(md_path)
        except RuleReadError as exc:
            logger.warning("Skipping rule: %s", exc)
            continue
        if read is not None:
            rules[read.rule.id] = read.rule

    return rules


def _load_packages(
    root: Path,
    packages: list[str],
    bundled_ids: set[str],
    owners: dict[str, str],
) -> dict[str, Rule]:
    """The rules of the listed packages; a package rule never reuses a bundled or another package's ID.

    `owners` maps each package rule ID already loaded to its package name and is updated here.
    Raises ConfigUnreadableError naming the package and the ID on a collision.
    """
    loaded: dict[str, Rule] = {}
    for pkg_path in get_package_paths(root, packages):
        name = pkg_path.name
        for rule_id, rule in _scan_rules(pkg_path).items():
            if rule_id in bundled_ids:
                raise ConfigUnreadableError(
                    f"packages: rule package '{name}' redefines bundled rule {rule_id}; "
                    f"give package rules their own ID prefix such as {name.upper()}:S:0001"
                )
            other = owners.get(rule_id)
            if other is not None and other != name:
                raise ConfigUnreadableError(
                    f"packages: rule packages '{other}' and '{name}' both define rule {rule_id}; "
                    "give each package's rules their own ID prefix"
                )
            owners[rule_id] = name
            loaded[rule_id] = rule
    return loaded


def _load_all_packages(roots: list[tuple[Path, list[str]]], bundled_ids: set[str]) -> dict[str, Rule]:
    """The rules of every root's listed packages, checked against the bundled IDs and each other."""
    owners: dict[str, str] = {}
    loaded: dict[str, Rule] = {}
    for root, packages in roots:
        loaded.update(_load_packages(root, packages, bundled_ids, owners))
    return loaded


def load_rules(
    rules_paths: list[Path] | None = None,
    project_root: Path | None = None,
    agent: str = "",
    scan_root: Path | None = None,
) -> dict[str, Rule]:
    """Load rules from directories, filtered by agent and project config."""
    if not rules_paths:
        rules_paths = [get_rules_dir()]

    primary = rules_paths[0]
    extra_paths = rules_paths[1:]

    if not primary.exists():
        return {}

    rules: dict[str, Rule] = {}
    config = _load_project_config(project_root)
    scan_config = _load_project_config(scan_root) if scan_root and scan_root != project_root else ProjectConfig()

    # 1. Load framework rules from primary path (core + selected agent)
    rules.update(_load_from_path(primary / "core"))

    if agent:
        rules.update(_load_from_path(primary / agent))

    # 2. Load additional rule sources
    for extra in extra_paths:
        if extra.exists():
            rules.update(_load_from_path(extra))

    # 2b. Load the project's rule packages after the framework rules: a package rule
    # reusing a bundled rule's ID (or another package's) stops the run.
    if project_root is not None:
        roots = [(project_root, config.packages)]
        if scan_root and scan_root != project_root:
            roots.append((scan_root, scan_config.packages))
        rules.update(_load_all_packages(roots, set(rules)))

    on_disk_ids = set(rules)

    # 3-4b2. Apply agent excludes, overrides, namespace filter, and capability gating.
    rules = _filter_by_agent(rules, agent)

    # 4c. Handle supersession: agent rules that supersede CORE rules
    # inherit the CORE checks and replace the CORE rule in the set.
    superseded_by = _apply_supersession(rules)

    # 4d. Handle inheritance: rules that inherit checks from a parent
    # without replacing the parent (both stay active).
    _apply_inheritance(rules)

    # 4e. Validate depends_on: detect circular dependency chains. Supersession
    # redirects are honored — a depends_on pointing at a superseded rule is
    # satisfied by its active successor. A dependency the agent filter left out
    # is absent without a warning; only an id no loaded rule file defines warns.
    _validate_depends_on(rules, superseded_by, on_disk_ids)

    # 5. Remove disabled rules (merge from project_root + scan_root configs)
    disabled: set[str] = set(config.disabled_rules or []) | set(scan_config.disabled_rules or [])
    if disabled:
        rules = {k: v for k, v in rules.items() if k not in disabled}

    return rules


def apply_agent_excludes(rules: dict[str, Rule], agent_config: AgentConfig) -> dict[str, Rule]:
    """Drop the rules whose id matches one of the agent config's `excludes` globs."""
    if not agent_config.excludes:
        return rules
    return {k: v for k, v in rules.items() if not any(fnmatch(k, pat) for pat in agent_config.excludes)}


def _filter_by_agent(rules: dict[str, Rule], agent: str) -> dict[str, Rule]:
    """Apply agent excludes, overrides, namespace filter, and capability gating.

    Excludes/overrides come from the agent's config; the namespace filter drops
    other agents' rules; capability gating drops rules requiring a capability the
    agent lacks per framework/capabilities_matrix.yml (no-op for an unknown or
    empty agent — see filter_by_capability).
    """
    agent_config = get_agent_config(agent) if agent else AgentConfig()
    rules = apply_agent_excludes(rules, agent_config)
    if agent_config.overrides:
        rules = _apply_agent_overrides(rules, agent_config.overrides)

    if agent:
        agent_prefix = agent_config.prefix or agent.upper()
        known = _agent_prefixes()
        rules = {k: v for k, v in rules.items() if not _is_other_agent_rule(k, agent_prefix, known)}
        rules = filter_by_capability(rules, agent_capabilities(agent))

    return rules


_AGNOSTIC_PREFIXES = frozenset({"CORE", "RRAILS"})


def infer_agent_from_rule_id(rule_id: str) -> str:
    """Infer agent name from a rule ID prefix.

    Returns lowercase agent name for agent-specific rules (e.g., "claude"
    for CLAUDE:S:0012), empty string for CORE/RRAILS rules.
    """
    prefix = rule_id.split(":")[0] if ":" in rule_id else ""
    if not prefix or prefix in _AGNOSTIC_PREFIXES:
        return ""
    return prefix.lower()


def _agent_prefixes() -> frozenset[str]:
    """The rule-id prefixes the bundled agent configs declare."""
    return frozenset(p for _, data in iter_agent_configs(get_rules_dir()) if (p := as_str(data.get("prefix"))))


def _is_other_agent_rule(rule_id: str, agent_prefix: str, known_prefixes: frozenset[str]) -> bool:
    """Check if a rule belongs to a different known agent.

    Agent-agnostic namespaces (CORE, RRAILS) and namespaces no agent config declares
    (a rule package's own prefix) are always kept. A namespace naming another agent's
    prefix is kept only if it also contains the selected agent's prefix.
    """
    namespace = rule_id.split(":")[0]
    if namespace in _AGNOSTIC_PREFIXES or agent_prefix in namespace:
        return False
    return any(prefix in namespace for prefix in known_prefixes)


def _apply_supersession(rules: dict[str, Rule]) -> dict[str, str]:
    """Handle rule supersession: agent rules inherit CORE checks and replace CORE rules.

    When CLAUDE:S:0012 supersedes CORE:S:0038, the CORE checks are inherited
    (unless explicitly replaced) and its `depends_on`, and the CORE rule is removed from
    the set. Modifies the rules dict in place.

    Returns a mapping `{superseded_id: successor_id}` so downstream validators
    (e.g. `_validate_depends_on`) can resolve `depends_on: [CORE:S:xxxx]`
    references that point at a superseded rule. The successor satisfies the
    dependency in place of the original.
    """
    superseded_by: dict[str, str] = {}
    for rule_id, rule in list(rules.items()):
        if not rule.supersedes or rule.supersedes not in rules:
            continue
        parent = rules[rule.supersedes]
        superseded_by[rule.supersedes] = rule_id
        # Inherit parent checks that aren't replaced by the agent rule
        replaced_ids = {c.replaces for c in rule.checks if c.replaces}
        inherited = [c for c in parent.checks if c.id not in replaced_ids]
        depends_on = list(dict.fromkeys([*parent.depends_on, *rule.depends_on]))
        rules[rule_id] = rule.model_copy(update={"checks": inherited + list(rule.checks), "depends_on": depends_on})
    for sid in superseded_by:
        del rules[sid]
    return superseded_by


def _apply_inheritance(rules: dict[str, Rule]) -> None:
    """Handle rule inheritance: child accumulates parent checks, both rules stay active.

    When CLAUDE:S:0015 inherits CORE:S:0038, the CORE checks are copied into
    the child (unless explicitly replaced), but the CORE rule stays in the set.
    Modifies the rules dict in place.
    """
    for rule_id, rule in list(rules.items()):
        if not rule.inherited or rule.inherited not in rules:
            continue
        parent = rules[rule.inherited]
        replaced_ids = {c.replaces for c in rule.checks if c.replaces}
        parent_checks = [c for c in parent.checks if c.id not in replaced_ids]
        rules[rule_id] = rule.model_copy(update={"checks": parent_checks + list(rule.checks)})


def _validate_depends_on(
    rules: dict[str, Rule],
    superseded_by: dict[str, str] | None = None,
    known_ids: set[str] | None = None,
) -> None:
    """Validate depends_on references and detect circular dependency chains.

    Logs warnings for invalid references and circular chains rather than
    raising errors, so rule loading is resilient to bad metadata.

    `superseded_by` maps removed rule ids to their successor ids; a depends_on
    pointing at a superseded rule is satisfied by the successor.
    `known_ids` holds every rule id defined on disk before agent filtering; a
    depends_on naming one of them is not warned about when the filter left it out.
    """
    redirects = superseded_by or {}
    known = known_ids or set()
    for rule_id, rule in rules.items():
        for dep_id in rule.depends_on:
            if dep_id in rules:
                continue
            if dep_id in redirects and redirects[dep_id] in rules:
                # Dependency was superseded by an active rule — treat as satisfied.
                continue
            if dep_id in known:
                continue
            logger.warning("Rule %s depends_on %s which is not loaded", rule_id, dep_id)

    _detect_dependency_cycles(rules)


def _detect_dependency_cycles(rules: dict[str, Rule]) -> None:
    """Detect circular depends_on chains via DFS. Logs warnings for cycles."""
    visited: set[str] = set()
    in_stack: set[str] = set()

    def _has_cycle(rid: str) -> bool:
        if rid in in_stack:
            return True
        if rid in visited:
            return False
        visited.add(rid)
        in_stack.add(rid)
        rule = rules.get(rid)
        if rule:
            for dep in rule.depends_on:
                if dep in rules and _has_cycle(dep):
                    return True
        in_stack.discard(rid)
        return False

    for rule_id in rules:
        if rule_id not in visited and _has_cycle(rule_id):
            logger.warning("Circular depends_on chain detected involving %s", rule_id)


def _parse_override_severity(raw: object, owner: str) -> Severity | None:
    """The `Severity` an override names, or None when it names none or an invalid one (logged)."""
    parsed = None
    if raw:
        try:
            parsed = Severity(raw)
        except ValueError:
            logger.warning("Invalid severity '%s' in override for %s, skipping", raw, owner)
    return parsed


def _apply_agent_overrides(
    rules: dict[str, Rule],
    overrides: dict[str, JsonObject],
) -> dict[str, Rule]:
    """Apply agent overrides: severity at rule level, disabled at check level."""
    result = {}
    for rule_id, rule in rules.items():
        # Rule-level severity override (keyed by rule_id)
        rule_override = overrides.get(rule_id)
        new_rule = rule
        if rule_override:
            parsed_severity = _parse_override_severity(rule_override.get("severity"), rule_id)
            if parsed_severity is not None:
                new_rule = new_rule.model_copy(update={"severity": parsed_severity})

        # Check-level overrides: only handle disabled
        new_checks = []
        for check in new_rule.checks:
            override = overrides.get(check.id)
            if override is not None and override.get("disabled", False):
                continue  # Drop this check
            # Legacy: check-level severity override → lift to rule
            if override and not rule_override:
                parsed_severity = _parse_override_severity(override.get("severity"), check.id)
                if parsed_severity is not None:
                    new_rule = new_rule.model_copy(update={"severity": parsed_severity})
            new_checks.append(check)
        result[rule_id] = new_rule.model_copy(update={"checks": new_checks})
    return result


def _load_project_config(project_root: Path | None) -> ProjectConfig:
    """Load project config, returning defaults when project_root is None."""
    if project_root is None:
        return ProjectConfig()
    return get_project_config(project_root)
