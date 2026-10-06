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
from typing import Any

import yaml
from pydantic import ValidationError

from reporails_cli.core.classify import classify_files, load_file_types
from reporails_cli.core.lint.harness_models import _FIXTURE_EXCLUDES, RuleInfo
from reporails_cli.core.platform.dto.models import Check, ClassifiedFile, FileTypeDeclaration
from reporails_cli.core.platform.utils.utils import read_frontmatter

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


def _read_checks_yml(checks_yml: Path, source: str) -> tuple[Any, str]:
    """`(raw checks, error)` from a rule's checks.yml; the error names the file and the problem."""
    try:
        data = yaml.safe_load(checks_yml.read_text(encoding="utf-8"))
    except OSError as exc:
        return [], f"{source}: cannot be read ({exc.strerror or exc})"
    except yaml.YAMLError as exc:
        problem = str(getattr(exc, "problem", "") or exc).strip().splitlines()[0]
        return [], f"{source}: is not valid YAML ({problem})"
    if data is None:
        return [], ""
    if not isinstance(data, dict):
        return [], f"{source}: must be a mapping with a `checks` list, not a {type(data).__name__}"
    return data.get("checks") or [], ""


def _validate_checks(raw_checks: Any, source: str) -> tuple[list[Check], str]:
    """`(checks, error)`: every entry validated against the Check model; the error names the first problems."""
    if not isinstance(raw_checks, list):
        return [], f"{source}: `checks` must be a list, not a {type(raw_checks).__name__}"
    checks: list[Check] = []
    problems: list[str] = []
    for index, raw in enumerate(raw_checks, start=1):
        if not isinstance(raw, dict):
            problems.append(f"check {index} must be a mapping, not a {type(raw).__name__}")
            continue
        try:
            checks.append(Check.model_validate(raw))
        except ValidationError as exc:
            label = f"check {index}" + (f" ({raw['id']})" if isinstance(raw.get("id"), str) else "")
            for err in exc.errors()[:2]:
                field_name = ".".join(str(part) for part in err["loc"]) or "value"
                problems.append(f"{label}: {field_name}: {err['msg']}")
    if problems:
        return [], f"{source}: " + "; ".join(problems[:3])
    return checks, ""


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
            rel = slug_dir.relative_to(root).as_posix()
            if not rel.startswith(filter_path.rstrip("/")):
                continue

        try:
            content = rule_md.read_text(encoding="utf-8")
        except OSError:
            continue

        read = read_frontmatter(content)
        meta = read.data
        if not meta:
            continue

        rule_id = meta.get("id", "")
        if filter_rule and rule_id != filter_rule:
            continue
        if _rule_matches_exclude(rule_id, excludes):
            continue

        raw_checks = meta.get("checks", [])
        source = f"{slug_dir.relative_to(root).as_posix()}/rule.md"
        load_error = ""
        if not raw_checks and checks_yml.exists():
            source = f"{slug_dir.relative_to(root).as_posix()}/checks.yml"
            raw_checks, load_error = _read_checks_yml(checks_yml, source)
        # Route every check through the Check model so a schema-invalid entry is
        # reported against its file instead of silently loading as an untyped dict.
        checks: list[Check] = []
        if not load_error:
            checks, load_error = _validate_checks(raw_checks, source)

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
                supersedes=meta.get("supersedes") or "",
                inherited=meta.get("inherited") or "",
                load_error=load_error,
            )
        )

    return rules


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
    by_id = {r.rule_id: r for r in rules}
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
