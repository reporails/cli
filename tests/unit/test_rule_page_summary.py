"""`rule_page_summary` gives a rule's identity and targeting, with `match` in a fixed key order."""

from __future__ import annotations

import pytest

from reporails_cli.core.lint.rule_pages import rule_page_summary, serialize_match
from reporails_cli.core.platform.dto.models import Category, FileMatch, Rule, RuleType, Severity

_FULL_MATCH = FileMatch(
    type="main",
    scope="project",
    format="freeform",
    content_format=["prose"],
    cardinality="single",
    lifecycle="persistent",
    maintainer="human",
    vcs="tracked",
    loading="session_start",
    precedence="project",
    loading_verb="read",
    link_source_type="import",
)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_match_keys_keep_their_serialized_order() -> None:
    assert list(serialize_match(_FULL_MATCH)) == [
        "type",
        "scope",
        "format",
        "content_format",
        "cardinality",
        "lifecycle",
        "maintainer",
        "vcs",
        "loading",
        "precedence",
        "loading_verb",
        "link_source_type",
    ]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_summary_names_the_rule_without_description_or_examples() -> None:
    rule = Rule(
        id="CORE:S:0001",
        title="Instruction File Exists",
        slug="instruction-file-exists",
        category=Category.STRUCTURE,
        type=RuleType.MECHANICAL,
        severity=Severity.HIGH,
        match=FileMatch(type="main"),
    )
    assert rule_page_summary(rule) == {
        "id": "CORE:S:0001",
        "title": "Instruction File Exists",
        "slug": "instruction-file-exists",
        "category": "structure",
        "severity": "high",
        "type": "mechanical",
        "match": {"type": "main"},
    }
