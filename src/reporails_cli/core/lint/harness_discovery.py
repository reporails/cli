"""Rule discovery for the rule-test harness.

Walks the framework rule tree (``core/<slug>/`` + ``<agent>/<slug>/``), loads
each rule's frontmatter + checks into a ``RuleInfo``, resolves agent config, and
classifies fixture files. This is the harness's lowest layer — the run, score,
and lint stages all build on the ``RuleInfo`` list it produces, so it depends on
the models but on no other harness module.
"""

from __future__ import annotations

import logging
from pathlib import Path

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.lint.harness_models import _FIXTURE_EXCLUDES, RuleInfo
from reporails_cli.core.platform.adapters.registry import RuleReadError, read_rule
from reporails_cli.core.platform.config.config import get_agent_config, get_agent_config_path, iter_agent_configs
from reporails_cli.core.platform.contract.json_value import JsonObject, as_str
from reporails_cli.core.platform.dto.models import Check, ClassifiedFile, FieldProblem, FileTypeDeclaration, Rule

logger = logging.getLogger(__name__)


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
    config_path = get_agent_config_path(agent, rules_root)
    if not config_path.exists():
        logger.warning("Agent config not found: %s", config_path)
        return [], []
    return load_file_types(agent, [rules_root]), get_agent_config(agent, rules_root).excludes


def _classify_fixture(
    fixture_root: Path,
    file_types: list[FileTypeDeclaration],
) -> list[ClassifiedFile]:
    """Classify files in a fixture directory against file type declarations."""
    files = [f for f in fixture_root.rglob("*") if f.is_file() and f.name not in _FIXTURE_EXCLUDES]
    return classify_files(fixture_root, files, file_types)


def _build_prefix_to_agent_map(rules_root: Path) -> dict[str, str]:
    """Build NAMESPACE_PREFIX → agent_name map from agent configs.

    Reads the ``prefix`` field of each agent config.
    Returns mapping like ``{"CLAUDE": "claude", "CODEX": "codex"}``.
    """
    prefixes: dict[str, str] = {}
    for _, data in iter_agent_configs(rules_root):
        prefix, agent = as_str(data.get("prefix")), as_str(data.get("agent"))
        if prefix and agent:
            prefixes[prefix] = agent
    return prefixes


# ── Rule discovery ──────────────────────────────────────────────────


def _relative(path: Path, root: Path) -> str:
    """`path` relative to `root` as posix text, `path` itself when it lies outside `root`."""
    return path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)


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

    Layout: core/{slug}/ for core rules, {agent}/{slug}/ for each agent folder.
    """
    dirs: list[Path] = []

    core_dir = root / "core"
    if core_dir.exists():
        dirs.extend(d for d in sorted(core_dir.iterdir()) if d.is_dir())

    for folder, _ in iter_agent_configs(root):
        if folder.name == "core" or (agent and folder.name != agent):
            continue
        dirs.extend(d for d in sorted(folder.iterdir()) if d.is_dir() and d.name != "tests")

    return dirs


def discover_rules(
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
    excludes = excludes or []
    all_roots = [rules_root] + (package_roots or [])
    loaded = (
        _load_rule(root, slug_dir, filter_path, filter_rule, excludes)
        for root in all_roots
        for slug_dir in _scan_root(root, agent)
    )
    return [rule for rule in loaded if rule is not None]


def _load_rule(
    root: Path,
    slug_dir: Path,
    filter_path: str | None,
    filter_rule: str | None,
    excludes: list[str],
) -> RuleInfo | None:
    """The rule in `slug_dir`, or None when it has no `rule.md` frontmatter or a filter or exclude drops it.

    A rule whose checks cannot be read is returned with `load_error` set; one whose `rule.md` fields are
    rejected is returned with them in `field_problems`.
    """
    rule_md = slug_dir / "rule.md"
    if not rule_md.exists():
        return None
    rel_dir = slug_dir.relative_to(root).as_posix()
    if filter_path and not rel_dir.startswith(filter_path.rstrip("/")):
        return None

    rule: Rule | None = None
    meta: JsonObject = {}
    load_error = ""
    built_checks: list[Check] = []
    problems: tuple[FieldProblem, ...] = ()
    try:
        read = read_rule(rule_md)
    except RuleReadError as exc:
        meta = exc.frontmatter
        load_error = f"{_relative(exc.path, root)}: {exc.problem}" if exc.problem else ""
        built_checks, problems = exc.checks, exc.field_problems
    else:
        if read is None:
            return None
        rule, meta = read
    rule_id = rule.id if rule else as_str(meta.get("id"))
    if (filter_rule and rule_id != filter_rule) or _rule_matches_exclude(rule_id, excludes):
        return None

    return RuleInfo(
        rule_id=rule_id,
        slug=rule.slug if rule else as_str(meta.get("slug")),
        title=rule.title if rule else as_str(meta.get("title")),
        category=rule.category.value if rule else as_str(meta.get("category")),
        checks=list(rule.checks) if rule else built_checks,
        rule_dir=slug_dir,
        checks_yml=slug_dir / "checks.yml",
        supersedes=(rule.supersedes if rule else as_str(meta.get("supersedes"))) or "",
        inherited=(rule.inherited if rule else as_str(meta.get("inherited"))) or "",
        frontmatter_read=bool(meta),
        severity_declared=bool(meta.get("severity")),
        enforcement_required=bool(meta.get("enforcement_required")),
        enforcement_mechanism_named=bool(meta.get("enforcement_mechanism")),
        load_error=load_error,
        field_problems=problems,
        rule_md_label=_relative(rule_md, root),
    )


def discover_agent_rules(
    rules_root: Path,
    agent: str,
    *,
    package_roots: list[Path] | None = None,
) -> list[RuleInfo]:
    """Discover the rules of one agent: its own rules plus core, minus what its config excludes."""
    _, excludes = load_agent_config(rules_root, agent)
    return discover_rules(
        rules_root,
        package_roots=package_roots,
        excludes=excludes,
        agent=agent,
    )


def apply_check_inheritance(rules: list[RuleInfo]) -> None:
    """Merge a parent's checks into every rule that `supersedes:` or `inherited:` it.

    Mirrors `registry._apply_supersession` / `_apply_inheritance` — production
    `ails check` runs an agent rule's inherited CORE checks alongside its own
    (unless a check `replaces:` the inherited one), so the harness *runner*
    must run the same merged set against the rule's own fixtures. Without
    this, a rule like `CURSOR:S:0001` passes its harness on checks alone
    while its inherited `CORE:S:0038` checks fire unnoticed at runtime
    (`ails check`).

    Deliberately NOT called from `discover_rules` itself: `lint_rules`
    (`ails test --lint`) discovers the same rules to validate each check's
    id prefix against its OWN rule id (`CORE.S.0038.*` must start with
    `CORE:S:0038`), and a merged parent check on the child would fail that
    structural check. Only the runner path (`run_harness`) opts in, after
    discovery, once lint's use of the unmerged list is done.

    Modifies each affected `RuleInfo.checks` in place. A parent outside the
    discovered set (filtered out by `filter_path` / `filter_rule` / `excludes`)
    leaves the child's checks unmerged — the same fixture-only scope that
    `discover_rules`'s filters already impose elsewhere.
    """
    by_id = {r.rule_id: r for r in rules if not r.load_failure}
    for rule in rules:
        parent_id = rule.supersedes or rule.inherited
        if not parent_id:
            continue
        parent = by_id.get(parent_id)
        if parent is None:
            continue
        replaced_ids = {c.replaces for c in rule.checks if c.replaces}
        inherited_checks = [c for c in parent.checks if c.id not in replaced_ids]
        rule.checks = inherited_checks + list(rule.checks)
        for c in inherited_checks:
            rule.inherited_checks_yml[c.id] = parent.checks_yml
