"""Read-side queries over the framework rule registry.

Loads rules across agents, filters by capability + severity, sorts into
authoring-workflow order, extracts Pass / Fail example sections from
rule.md bodies.
"""

from __future__ import annotations

import re
from fnmatch import fnmatch
from pathlib import Path

from reporails_cli.core.platform.adapters.registry import _load_from_path, get_rules_dir
from reporails_cli.core.platform.config.bootstrap import get_agent_config
from reporails_cli.core.platform.dto.models import Category, Rule, Severity

_CATEGORY_ORDER: dict[Category, int] = {
    Category.STRUCTURE: 0,
    Category.DIRECTION: 1,
    Category.COHERENCE: 2,
    Category.EFFICIENCY: 3,
    Category.MAINTENANCE: 4,
    Category.GOVERNANCE: 5,
}

_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# Mirror of `core.classify.capability_paths._CAPABILITY_FOLD`. Duplicated
# to respect the adapter-layer boundary; keep in sync.
_CAPABILITY_FOLD: dict[str, tuple[str, ...]] = {
    "main": ("main", "override"),
    "memories": ("memory", "subagent_memory"),
    "memory": ("memory", "subagent_memory"),
}


def list_known_agents(rules_dir: Path | None = None) -> list[str]:
    """Agent IDs declared under `framework/rules/<agent>/`, excluding `core`."""
    root = rules_dir if rules_dir is not None else get_rules_dir()
    if not root.exists():
        return []
    return sorted(p.name for p in root.iterdir() if p.is_dir() and p.name != "core" and not p.name.startswith("_"))


def load_all_rules(agents: list[str] | None = None, rules_dir: Path | None = None) -> list[Rule]:
    """Load CORE + every requested agent's rules; apply per-agent excludes."""
    root = rules_dir if rules_dir is not None else get_rules_dir()
    if not root.exists():
        return []
    agent_ids = agents if agents is not None else list_known_agents(root)
    by_id: dict[str, Rule] = {}
    by_id.update(_load_from_path(root / "core"))
    for agent in agent_ids:
        agent_rules = _load_from_path(root / agent)
        excludes = list(get_agent_config(agent).excludes or [])
        if excludes:
            agent_rules = {k: v for k, v in agent_rules.items() if not any(fnmatch(k, pat) for pat in excludes)}
        by_id.update(agent_rules)
    return sorted(by_id.values(), key=lambda r: r.id)


def filter_rules_by_capability(rules: list[Rule], capability: str) -> list[Rule]:
    """Keep rules whose `match.type` includes `capability` (or are universal)."""
    targets = set(_CAPABILITY_FOLD.get(capability, (capability,)))
    out: list[Rule] = []
    for rule in rules:
        if rule.match is None or rule.match.type is None:
            out.append(rule)
            continue
        rule_types = rule.match.type if isinstance(rule.match.type, list) else [rule.match.type]
        if any(t in targets for t in rule_types):
            out.append(rule)
    return out


def filter_rules_by_severity(rules: list[Rule], min_severity: Severity) -> list[Rule]:
    """Keep rules at or above `min_severity` (critical > high > medium > low)."""
    threshold = _SEVERITY_ORDER[min_severity]
    return [r for r in rules if _SEVERITY_ORDER.get(r.severity, 99) <= threshold]


def sort_rules_for_authoring(rules: list[Rule]) -> list[Rule]:
    """Sort by category (workflow order), then severity, then id."""
    return sorted(
        rules,
        key=lambda r: (
            _CATEGORY_ORDER.get(r.category, 99),
            _SEVERITY_ORDER.get(r.severity, 99),
            r.id,
        ),
    )


def load_rule_examples(rule: Rule) -> dict[str, str | None]:
    """Extract `### Pass` and `### Fail` sections from rule.md body."""
    result: dict[str, str | None] = {"pass": None, "fail": None}
    if rule.md_path is None or not rule.md_path.exists():
        return result
    try:
        text = rule.md_path.read_text(encoding="utf-8")
    except OSError:
        return result
    result["pass"] = _extract_section(text, "Pass")
    result["fail"] = _extract_section(text, "Fail")
    return result


def _extract_section(text: str, heading: str) -> str | None:
    """Body of `## <heading>` or `### <heading>` to next equal-or-shallower heading, fence-aware."""
    pattern = re.compile(rf"^(#{{2,3}})\s+{re.escape(heading)}\s*$", re.MULTILINE)
    m = pattern.search(text)
    if m is None:
        return None
    depth = len(m.group(1))
    start = m.end() + 1
    heading_re = re.compile(rf"^#{{1,{depth}}}\s+\S")
    body_lines: list[str] = []
    in_fence = False
    fence_marker = ""
    for line in text[start:].splitlines(keepends=False):
        stripped = line.lstrip()
        if not in_fence:
            for marker in ("~~~~", "~~~", "```"):
                if stripped.startswith(marker):
                    in_fence = True
                    fence_marker = marker
                    body_lines.append(line)
                    break
            else:
                if heading_re.match(line):
                    break
                body_lines.append(line)
        else:
            body_lines.append(line)
            if stripped.startswith(fence_marker):
                in_fence = False
                fence_marker = ""
    body = "\n".join(body_lines).strip()
    return body or None


def rules_for_capability(
    capability: str,
    agents: list[str] | None = None,
    min_severity: Severity | None = None,
    rules_dir: Path | None = None,
) -> list[Rule]:
    """Composite: load + filter (capability + optional severity) + sort."""
    rules = load_all_rules(agents=agents, rules_dir=rules_dir)
    rules = filter_rules_by_capability(rules, capability)
    if min_severity is not None:
        rules = filter_rules_by_severity(rules, min_severity)
    return sort_rules_for_authoring(rules)


def find_rule_by_id(
    rule_id: str,
    agents: list[str] | None = None,
    rules_dir: Path | None = None,
) -> Rule | None:
    """Return the rule with `rule_id`, or None."""
    for rule in load_all_rules(agents=agents, rules_dir=rules_dir):
        if rule.id == rule_id:
            return rule
    return None
