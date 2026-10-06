"""Mutation-closing tests for `formatters/text/rules.py`."""

from __future__ import annotations

import pytest

from reporails_cli.formatters.text.rules import format_rule


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_only_pass_example_still_rendered() -> None:
    """A rule with a Pass example but no Fail must still render the Pass block.

    Kills the `not pass and not fail -> or` mutant: with `or`, the "no examples"
    branch fires whenever either side is missing, so a real Pass example is
    dropped and replaced by the "none" line.
    """
    out = format_rule(
        "CORE:S:0001",
        {"title": "X", "examples": {"pass": "GOOD_EXAMPLE_BODY", "fail": None}},
    )
    assert "GOOD_EXAMPLE_BODY" in out
    assert "this rule has no Pass / Fail examples" not in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_check_label_prefers_name_over_type() -> None:
    """A check's `name` labels it; `type` is only the fallback.

    Kills the `name or type -> name and type` mutant: with `and`, a present
    name is discarded and the type is shown as the label instead.
    """
    out = format_rule(
        "CORE:S:0001",
        {
            "title": "X",
            "checks": [{"id": "c1", "name": "HumanReadableLabel", "type": "regex", "severity": "high"}],
        },
    )
    assert "c1: HumanReadableLabel [regex]" in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_renders_match_properties() -> None:
    """The `ails explain` text renderer must show every set MATCH_PROPERTIES entry, not just
    `title`/`category`/`type` — before the fix it rendered no `match` property at all, so a rule
    author who set `content_format` / `loading_verb` / `link_source_type` never saw it here
    even though `ails rules list` carried it."""
    match = {
        "type": "skills",
        "content_format": ["markdown"],
        "loading_verb": ["read"],
        "link_source_type": ["main"],
    }
    out = format_rule("CORE:S:0999", {"title": "T", "category": "structure", "type": "deterministic", "match": match})
    assert "content_format: markdown" in out
    assert "loading_verb: read" in out
    assert "link_source_type: main" in out
