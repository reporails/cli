"""Unit tests for `core/lint/rule_pages.py`: a rule page's sections are read from its markdown parse."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.lint.rule_pages import (
    _section,
    load_rule_description,
    load_rule_examples,
    load_rule_guides,
)
from reporails_cli.core.platform.dto.models import Category, Rule, RuleType, Severity


def _rule(md_path: Path | None) -> Rule:
    return Rule(
        id="TEST:S:0001",
        title="TEST:S:0001",
        slug="test-s-0001",
        category=Category.STRUCTURE,
        type=RuleType.MECHANICAL,
        severity=Severity.HIGH,
        md_path=md_path,
    )


def _page(tmp_path: Path, text: str) -> Rule:
    md = tmp_path / "rule.md"
    md.write_text(text, encoding="utf-8")
    return _rule(md)


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_rule_examples_extracts_pass_and_fail(tmp_path: Path) -> None:
    rule = _page(
        tmp_path,
        "---\nid: TEST:S:0001\n---\n# Title\n\nBody.\n\n## Pass / Fail\n\n"
        "### Pass\n\n```markdown\n# Good\n## Inside fence\n```\n\n"
        "### Fail\n\n```markdown\nBad\n```\n\n"
        "## Limitations\n\nSome.\n",
    )
    examples = load_rule_examples(rule)
    assert examples["pass"] is not None and "Inside fence" in examples["pass"]
    assert examples["fail"] is not None and "Bad" in examples["fail"]
    assert "Limitations" not in examples["fail"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_rule_examples_none_when_missing(tmp_path: Path) -> None:
    rule = _page(tmp_path, "---\nid: TEST:S:0002\n---\n# Title\n")
    assert load_rule_examples(rule) == {"pass": None, "fail": None}


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_load_rule_examples_no_path() -> None:
    assert load_rule_examples(_rule(None)) == {"pass": None, "fail": None}


@pytest.mark.unit
@pytest.mark.subsys_lint
@pytest.mark.parametrize("fence", ["```", "~~~", "~~~~", "````"])
def test_heading_looking_line_inside_a_fence_does_not_end_the_section(fence: str) -> None:
    text = f"### Pass\n\n{fence}markdown\n# H1\n## H2\n{fence}\n\n### Fail\n\nBody.\n"
    out = _section(text, "Pass")
    assert out is not None and "## H2" in out and "Fail" not in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_unclosed_fence_runs_to_the_end_of_the_page() -> None:
    out = _section("### Pass\n\n```markdown\n# H1\n### Fail\nBody.\n", "Pass")
    assert out is not None and "### Fail" in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_section_ends_at_equal_or_shallower_heading_only() -> None:
    text = "## Pass\n\none\n\n#### Deeper\n\ntwo\n\n## Fail\n\nthree\n"
    assert _section(text, "Pass") == "one\n\n#### Deeper\n\ntwo"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_section_preserves_line_spacing() -> None:
    text = "### Pass\n\nline one\nline two\nline three\n\n### Fail\n\nother\n"
    assert _section(text, "Pass") == "line one\nline two\nline three"


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_section_of_last_heading_runs_to_the_end_and_blank_section_is_none() -> None:
    assert _section("### Pass\n\nlast\n", "Pass") == "last"
    assert _section("### Pass\n\n### Fail\n\nx\n", "Pass") is None
    assert _section("### Other\n\nx\n", "Pass") is None


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_description_drops_frontmatter_and_the_pass_fail_section(tmp_path: Path) -> None:
    rule = _page(
        tmp_path,
        "---\nid: TEST:S:0001\n---\n# Title\n\nBody.\n\n## Pass / Fail\n\n"
        "### Pass\n\n```markdown\n## Pass / Fail\n```\n\n### Fail\n\nBad\n\n## Limitations\n\nSome.\n",
    )
    assert load_rule_description(rule) == "# Title\n\nBody.\n\n## Limitations\n\nSome."


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_description_none_without_frontmatter(tmp_path: Path) -> None:
    assert load_rule_description(_page(tmp_path, "# Title\n\nBody.\n")) is None


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_guides_carry_title_pass_and_antipatterns() -> None:
    guides = load_rule_guides(["CORE:S:0024", "CORE:S:0024", "CORE:S:9999"])
    assert list(guides) == ["CORE:S:0024"]
    assert guides["CORE:S:0024"]["title"]


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_description_drops_frontmatter_that_opens_with_a_comment(tmp_path: Path) -> None:
    rule = _page(tmp_path, "---\n# the rule's identity\nid: TEST:S:0001\n---\n# Title\n\nBody.\n")
    assert load_rule_description(rule) == "# Title\n\nBody."
