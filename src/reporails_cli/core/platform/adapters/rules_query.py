"""Read-side queries over the framework rule registry.

Loads rules across agents, filters by capability + severity, sorts into
authoring-workflow order.
"""

from __future__ import annotations

from pathlib import Path

from reporails_cli.core.platform.adapters.registry import _load_from_path, apply_agent_excludes, get_rules_dir
from reporails_cli.core.platform.config.config import get_agent_config
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
        by_id.update(apply_agent_excludes(_load_from_path(root / agent), get_agent_config(agent)))
    return sorted(by_id.values(), key=lambda r: r.id)


def capability_file_types(capability: str | list[str]) -> set[str]:
    """The config file types a capability word names: a config key itself, a word a user may
    type for one (`skill`, `agent`), or a display alias folding several (`memories`)."""
    from reporails_cli.core.platform.config.vocabulary import load_capability_vocabulary

    vocab = load_capability_vocabulary()
    caps = [capability] if isinstance(capability, str) else list(capability)
    targets: set[str] = set()
    for cap in caps:
        key = vocab.input_forms.get(cap, cap)
        targets.update(vocab.fold.get(key, [key]))
    return targets


def filter_rules_by_capability(rules: list[Rule], capability: str | list[str]) -> list[Rule]:
    """Keep rules whose `match.type` includes any of the capabilities (or are universal)."""
    targets = capability_file_types(capability)
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
