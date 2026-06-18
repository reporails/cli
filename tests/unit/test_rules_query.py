"""Unit tests for `core/platform/adapters/rules_query.py`."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.platform.adapters.rules_query import (
    _extract_section,
    filter_rules_by_capability,
    filter_rules_by_severity,
    find_rule_by_id,
    list_known_agents,
    load_all_rules,
    load_rule_examples,
    rules_for_capability,
    sort_rules_for_authoring,
)
from reporails_cli.core.platform.dto.models import (
    Category,
    FileMatch,
    Rule,
    RuleType,
    Severity,
)


def _make_rule(
    rule_id: str,
    *,
    category: Category = Category.STRUCTURE,
    severity: Severity = Severity.HIGH,
    match: FileMatch | None = None,
    md_path: Path | None = None,
) -> Rule:
    return Rule(
        id=rule_id,
        title=rule_id,
        slug=rule_id.lower().replace(":", "-"),
        category=category,
        type=RuleType.MECHANICAL,
        severity=severity,
        match=match,
        md_path=md_path,
    )


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_list_known_agents_includes_claude_excludes_core() -> None:
    agents = list_known_agents()
    assert "claude" in agents
    assert "core" not in agents


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_list_known_agents_empty_when_dir_missing(tmp_path: Path) -> None:
    assert list_known_agents(tmp_path / "missing") == []


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_all_rules_includes_core() -> None:
    rules = load_all_rules()
    assert any(r.id.startswith("CORE:") for r in rules)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_all_rules_with_agent_filters_namespace() -> None:
    rules = load_all_rules(agents=["claude"])
    prefixes = {r.id.split(":")[0] for r in rules}
    assert prefixes <= {"CORE", "CLAUDE"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_filter_by_capability_keeps_universal_rules() -> None:
    universal = _make_rule("CORE:S:9001", match=FileMatch())
    skill_only = _make_rule("CORE:S:9002", match=FileMatch(type="skill"))
    out = filter_rules_by_capability([universal, skill_only], "agent")
    ids = {r.id for r in out}
    assert "CORE:S:9001" in ids
    assert "CORE:S:9002" not in ids


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_filter_by_capability_specific_type() -> None:
    skill_rule = _make_rule("CORE:S:9003", match=FileMatch(type="skill"))
    agent_rule = _make_rule("CORE:S:9004", match=FileMatch(type="agent"))
    out = filter_rules_by_capability([skill_rule, agent_rule], "skill")
    assert {r.id for r in out} == {"CORE:S:9003"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_filter_by_capability_main_fold_strict() -> None:
    """`main` folds in `override` only — nested CLAUDE.md / child_instruction are separate capabilities."""
    main_rule = _make_rule("CORE:S:9005", match=FileMatch(type="main"))
    override = _make_rule("CORE:S:9006", match=FileMatch(type="override"))
    nested = _make_rule("CORE:S:9007", match=FileMatch(type="nested_context"))
    child = _make_rule("CORE:S:9008", match=FileMatch(type="child_instruction"))
    other = _make_rule("CORE:S:9009", match=FileMatch(type="skill"))
    out = filter_rules_by_capability([main_rule, override, nested, child, other], "main")
    assert {r.id for r in out} == {"CORE:S:9005", "CORE:S:9006"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_filter_by_capability_list_type() -> None:
    multi = _make_rule("CORE:S:9008", match=FileMatch(type=["skill", "agent"]))
    assert len(filter_rules_by_capability([multi], "agent")) == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_filter_by_severity_at_or_above() -> None:
    rules = [
        _make_rule("CORE:S:9100", severity=Severity.CRITICAL),
        _make_rule("CORE:S:9101", severity=Severity.HIGH),
        _make_rule("CORE:S:9102", severity=Severity.MEDIUM),
        _make_rule("CORE:S:9103", severity=Severity.LOW),
    ]
    out = filter_rules_by_severity(rules, Severity.HIGH)
    assert {r.id for r in out} == {"CORE:S:9100", "CORE:S:9101"}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_sort_for_authoring_category_then_severity() -> None:
    rules = [
        _make_rule("CORE:G:0001", category=Category.GOVERNANCE, severity=Severity.CRITICAL),
        _make_rule("CORE:S:0001", category=Category.STRUCTURE, severity=Severity.MEDIUM),
        _make_rule("CORE:S:0002", category=Category.STRUCTURE, severity=Severity.HIGH),
        _make_rule("CORE:D:0001", category=Category.DIRECTION, severity=Severity.LOW),
    ]
    assert [r.id for r in sort_rules_for_authoring(rules)] == [
        "CORE:S:0002",
        "CORE:S:0001",
        "CORE:D:0001",
        "CORE:G:0001",
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_sort_stable_by_id() -> None:
    rules = [
        _make_rule("CORE:S:0002", category=Category.STRUCTURE, severity=Severity.HIGH),
        _make_rule("CORE:S:0001", category=Category.STRUCTURE, severity=Severity.HIGH),
    ]
    assert [r.id for r in sort_rules_for_authoring(rules)] == ["CORE:S:0001", "CORE:S:0002"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_rule_examples_extracts_pass_and_fail(tmp_path: Path) -> None:
    rule_md = tmp_path / "rule.md"
    rule_md.write_text(
        "---\nid: TEST:S:0001\n---\n# Title\n\nBody.\n\n## Pass / Fail\n\n"
        "### Pass\n\n```markdown\n# Good\n## Inside fence\n```\n\n"
        "### Fail\n\n```markdown\nBad\n```\n\n"
        "## Limitations\n\nSome.\n",
        encoding="utf-8",
    )
    examples = load_rule_examples(_make_rule("TEST:S:0001", md_path=rule_md))
    assert examples["pass"] is not None and "Inside fence" in examples["pass"]
    assert examples["fail"] is not None and "Bad" in examples["fail"]
    assert "Limitations" not in examples["fail"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_rule_examples_none_when_missing(tmp_path: Path) -> None:
    rule_md = tmp_path / "rule.md"
    rule_md.write_text("---\nid: TEST:S:0002\n---\n# Title\n", encoding="utf-8")
    assert load_rule_examples(_make_rule("TEST:S:0002", md_path=rule_md)) == {"pass": None, "fail": None}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_rule_examples_no_path() -> None:
    assert load_rule_examples(_make_rule("TEST:S:0003", md_path=None)) == {"pass": None, "fail": None}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_extract_section_fence_aware() -> None:
    text = "### Pass\n\n~~~~markdown\n# H1\n## H2\n~~~~\n\n### Fail\n\nBody.\n"
    out = _extract_section(text, "Pass")
    assert out is not None and "H2" in out and "Fail" not in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_rules_for_capability_composite() -> None:
    rules = rules_for_capability("skill", agents=["claude"])
    assert len(rules) > 0
    assert rules[0].category == Category.STRUCTURE


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_find_rule_by_id() -> None:
    assert find_rule_by_id("CORE:S:0024") is not None
    assert find_rule_by_id("CORE:S:9999") is None
