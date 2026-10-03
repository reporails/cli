"""Mutation-closing behavioral tests for formatters/mcp.py.

Drives `format_rule` with inputs that pin the correct output, so each test
reddens when its injected bug returns: the scope-line guard, the heading-strip
filter, and the one-sided-examples branch. (The compact-format helpers these
also covered — `_line_ref` / `_file_from_location` / `_compact_judgment` /
`_compact_delta` — were removed as dead code; the envelope is covered by
`test_mcp_validate_envelope.py`.)
"""

from __future__ import annotations

import pytest

from reporails_cli.formatters.mcp import format_rule


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_scope_without_type_omits_scope() -> None:
    """A `match` mapping without a `type` key must not emit a scope line — kills `and` -> `or`
    (the mutant would KeyError on `scope['type']`)."""
    out = format_rule("CORE:S:0001", {"title": "T", "match": {"applies_to": "docs"}})
    assert "scope:" not in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_scope_with_type_emits_scope() -> None:
    out = format_rule("CORE:S:0001", {"title": "T", "match": {"type": "file"}})
    assert "scope: file" in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_keeps_non_heading_title_mention() -> None:
    """Only the heading line matching the title is stripped; a body line that merely mentions
    the title survives — kills `and` -> `or` on the heading filter."""
    out = format_rule("CORE:S:0001", {"title": "Widget", "description": "# Widget\nThe Widget must be named."})
    assert "The Widget must be named." in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_one_sided_examples_render() -> None:
    """A rule with only a pass example still renders it (not 'Examples: none') — kills `and` -> `or`
    on the both-absent guard."""
    out = format_rule("CORE:S:0001", {"title": "T", "examples": {"pass": "PB", "fail": None}})
    assert "PB" in out
    assert "Examples: none" not in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_renders_every_set_match_property_not_just_type() -> None:
    """`explain` must render every non-`type` MATCH_PROPERTIES entry the match dict carries
    (the same dict `rules list` emits via `_serialize_match`), not silently drop it.

    Before the fix, `format_rule` only ever appended a `scope: <type>` line — a rule whose
    `match:` set `content_format` / `loading_verb` / `link_source_type` showed those values in
    `rules list` JSON but nowhere in `explain` text."""
    match = {
        "type": "skills",
        "content_format": ["markdown"],
        "loading_verb": ["read"],
        "link_source_type": ["main"],
    }
    out = format_rule("CORE:S:0999", {"title": "T", "match": match})
    assert "scope: skills" in out
    assert "content_format: markdown" in out
    assert "loading_verb: read" in out
    assert "link_source_type: main" in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_renders_category_and_type() -> None:
    """`explain` must show the rule's own `category` and `type`:
    `explain_tool` (`interfaces/mcp/tools.py`) sets both on `rule_data`, and the MCP
    tool description promises "title, category, type, description, checks", but the text
    renderer never read either key."""
    out = format_rule("CORE:C:0042", {"title": "T", "category": "coherence", "type": "mechanical", "severity": "high"})
    assert "category: coherence" in out
    assert "type: mechanical" in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_omits_category_and_type_when_absent() -> None:
    """No spurious `category:` / `type:` line when the caller's `rule_data` carries neither
    (mirrors the existing `scope`-without-`type` guard)."""
    out = format_rule("CORE:S:0001", {"title": "T"})
    assert "category:" not in out
    assert "type:" not in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_scope_with_list_type_joins_instead_of_python_repr() -> None:
    """A list-typed `match.type` (a rule scoped to several file kinds) must join into
    readable text, not the bare Python list repr `formatters/mcp.py` used to interpolate
    directly (it used to render `scope: ['config', 'hooks']`)."""
    out = format_rule("CLAUDE:S:0007", {"title": "T", "match": {"type": ["config", "hooks"]}})
    assert "scope: config, hooks" in out
    assert "[" not in out and "]" not in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_explain_tool_returns_the_whole_rule_body_without_repeating_examples(tmp_path) -> None:
    """MCP `explain` gives the agent the rule's full body (it was cut at 500 characters, which
    dropped every bundled rule's later antipatterns) and stops before the Pass / Fail section,
    whose examples render on their own."""
    from reporails_cli.interfaces.mcp.rule_tools import explain_tool

    d = tmp_path / "core" / "core-s-0902"
    d.mkdir(parents=True)
    filler = " ".join(f"word{i}" for i in range(120))
    (d / "rule.md").write_text(
        '---\nid: "CORE:S:0902"\ntitle: "Rule"\ncategory: structure\ntype: deterministic\n'
        "slug: core-s-0902\nmatch:\n  type: main\n---\n"
        f"{filler}\n\n## Antipatterns\n\n- **Late antipattern**: past character 500.\n\n"
        "## Pass / Fail\n\n### Pass\n\n~~~~markdown\nUse `ruff`.\n~~~~\n",
        encoding="utf-8",
    )
    out = explain_tool("CORE:S:0902", [tmp_path])
    assert isinstance(out, str)
    assert "Late antipattern" in out
    assert out.count("Use `ruff`.") == 1


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_title_heading_strip_leaves_fenced_comment_lines() -> None:
    """Only the page's own level-1 title heading is dropped; a `# T` line inside a fenced
    example is code and stays."""
    desc = "# T rule\n\nBody.\n\n```bash\n# T rule install step\nmake\n```\n"
    out = format_rule("CORE:S:0999", {"title": "T rule", "description": desc})
    lines = out.splitlines()
    assert "# T rule" not in lines
    assert "# T rule install step" in lines


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_format_rule_title_heading_strip_counts_lines_after_frontmatter() -> None:
    """A description that opens with a `---` block loses its title heading, not the lines above it."""
    desc = "---\nid: x\n---\n# T rule\n\nBody line.\n"
    out = format_rule("CORE:S:0999", {"title": "T rule", "description": desc})
    assert "# T rule" not in out.splitlines()
    assert "Body line." in out


@pytest.mark.unit
@pytest.mark.subsys_lint
def test_title_heading_is_dropped_by_file_line_past_a_form_feed() -> None:
    from reporails_cli.formatters.mcp import _without_title_heading

    text = "# Title\n\nbefore\x0cmid\nafter line\n"
    assert _without_title_heading(text, "title") == "before\x0cmid\nafter line"
