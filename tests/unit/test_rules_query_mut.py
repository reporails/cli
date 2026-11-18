"""Mutation-closing tests for `core/platform/rules/rules_query.py`."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.dto.models import Category, Rule, RuleType, Severity
from reporails_cli.core.platform.rules import rules_query
from reporails_cli.core.platform.rules.rules_query import load_all_rules


def _make_rule(rule_id: str) -> Rule:
    return Rule(
        id=rule_id,
        title=rule_id,
        slug=rule_id.lower().replace(":", "-"),
        category=Category.STRUCTURE,
        type=RuleType.MECHANICAL,
        severity=Severity.HIGH,
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_all_rules_applies_agent_excludes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, use_agent_configs
) -> None:
    """A non-empty `excludes` list must actually drop matching rules.

    Kills the `excludes or [] -> excludes and []` mutant: with `and`, a truthy
    excludes list collapses to `[]`, so no rule is filtered and the excluded
    rule survives.
    """
    agent_rules = {"AGT:S:0001": _make_rule("AGT:S:0001"), "AGT:S:0002": _make_rule("AGT:S:0002")}

    def fake_load(path: Path) -> dict[str, Rule]:
        return {} if path.name == "core" else dict(agent_rules)

    monkeypatch.setattr(rules_query, "load_rules_from_path", fake_load)
    use_agent_configs({"agt": {"excludes": ["AGT:S:0002"]}}, root=tmp_path)
    out = {r.id for r in load_all_rules(agents=["agt"])}
    assert out == {"AGT:S:0001"}
