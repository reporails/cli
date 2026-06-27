"""`ails explain` and `ails rules -f md` agree on Pass / Fail example presence.

Both surfaces extract examples through `load_rule_examples`, and both name an
absent example block rather than omitting it silently.
"""

from __future__ import annotations

import pytest

from reporails_cli.formatters.mcp import format_rule as mcp_format_rule
from reporails_cli.formatters.text.rules import format_rule


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_explain_renders_examples_when_present() -> None:
    data = {"title": "X", "examples": {"pass": "PASS-BODY", "fail": "FAIL-BODY"}}
    out = format_rule("CORE:S:0001", data)
    assert "Examples:" in out
    assert "Pass:" in out and "PASS-BODY" in out
    assert "Fail:" in out and "FAIL-BODY" in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_explain_names_absent_examples() -> None:
    """A rule with no parseable Pass / Fail is named as such, not silently omitted."""
    out = format_rule("CORE:S:0001", {"title": "X", "examples": {"pass": None, "fail": None}})
    assert "this rule has no Pass / Fail examples" in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_explain_without_examples_key_is_back_compat() -> None:
    """Callers that pass no `examples` key (JSON) get no Examples section."""
    out = format_rule("CORE:S:0001", {"title": "X"})
    assert "Examples:" not in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mcp_explain_renders_examples_in_parity_with_cli() -> None:
    """The MCP `explain` surface shows the same Pass / Fail examples as `ails explain`."""
    out = mcp_format_rule("CORE:S:0001", {"title": "X", "examples": {"pass": "PB", "fail": "FB"}})
    assert "Examples:" in out and "PB" in out and "FB" in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_mcp_explain_names_absent_examples() -> None:
    out = mcp_format_rule("CORE:S:0001", {"title": "X", "examples": {"pass": None, "fail": None}})
    assert "no Pass / Fail examples" in out
