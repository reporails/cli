"""Mutation-killing tests for mapper/markdown_extract.py.

Seam tests over the pure structure helpers: prose-line detection, config-block
boundary detection, trailing-config-tail blanking, body-YAML blanking, repo-dump
scaffolding removal, frontmatter offset, softbreak splitting, inline-code
extraction, and block-stack → format mapping. Each asserts the extracted result,
so a mutated operator produces the wrong structure and reddens the test.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.markdown_extract import (
    _blank_body_yaml_blocks,
    _blank_repo_dump_headers,
    _blank_trailing_config_tail,
    _config_block_end,
    _determine_format,
    _extract_texts,
    _is_prose_line,
    _split_at_softbreaks,
    _strip_frontmatter,
)


class _Child:
    """Minimal markdown-it inline child stand-in (has .type and .content)."""

    def __init__(self, type_: str, content: str = "") -> None:
        self.type = type_
        self.content = content


# ──────────────────────────────────────────────────────────────────
# _is_prose_line  (L80 or/==, L81 return False)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_is_prose_line_only_content_lines_are_prose() -> None:
    assert _is_prose_line("This is a prose sentence.") is True
    # Each non-prose form must be rejected (kills each or→and, the ==→!=, and L81).
    assert _is_prose_line("") is False
    assert _is_prose_line("---") is False
    assert _is_prose_line("# Heading") is False
    assert _is_prose_line("- list item") is False
    assert _is_prose_line("key: value") is False


# ──────────────────────────────────────────────────────────────────
# _config_block_end  (L96, L98, L100, L103, L106, L145 via _blank_body_yaml_blocks)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_config_block_end_closed_yaml_block() -> None:
    lines = ["---", "key: value", "---", "prose after"]
    assert _config_block_end(lines, 0, len(lines)) == 2  # kills L103 !=→==


@pytest.mark.unit
@pytest.mark.subsys_map
def test_config_block_end_skips_leading_blank() -> None:
    lines = ["---", "", "key: value", "---", "x"]
    assert _config_block_end(lines, 0, len(lines)) == 3  # kills L96 and→or (mutant crashes)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_config_block_end_all_blank_to_eof_is_none() -> None:
    lines = ["---", "", ""]
    assert _config_block_end(lines, 0, len(lines)) is None  # kills L98 >=→> (mutant crashes)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_config_block_end_hash_led_block_strips() -> None:
    lines = ["---", "# rule config", "globs: *.py", "---", "real prose here"]
    assert _config_block_end(lines, 0, len(lines)) == 3  # kills L100 or→and


@pytest.mark.unit
@pytest.mark.subsys_map
def test_config_block_end_unclosed_block_closes_at_eof() -> None:
    lines = ["---", "key: value", "more: stuff"]
    assert _config_block_end(lines, 0, len(lines)) == 2  # kills L103 and→or (mutant crashes)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_config_block_end_prose_in_keyed_block_is_not_stripped() -> None:
    lines = ["---", "key: value", "This is a prose sentence.", "---", "x"]
    assert _config_block_end(lines, 0, len(lines)) is None  # kills L106 and→or


@pytest.mark.unit
@pytest.mark.subsys_map
def test_blank_body_yaml_block_only_on_triple_dash() -> None:
    text = "Intro line.\n---\nkey: value\n---\nOutro.\n"
    out = _blank_body_yaml_blocks(text)
    assert "key: value" not in out  # kills L145 ==→! (mutant leaves the block intact)
    assert "Intro line." in out
    assert "Outro." in out


# ──────────────────────────────────────────────────────────────────
# _blank_trailing_config_tail  (L119 saw_key init, L120 or→and, L122 saw_key set)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_trailing_empty_key_tail_is_blanked() -> None:
    lines = ["Real prose.", "", "description:", "globs:"]
    _blank_trailing_config_tail(lines)
    assert lines[0] == "Real prose."
    assert lines[2] == ""  # kills L120 or→and and L122 True→False (key must be blanked)
    assert lines[3] == ""


@pytest.mark.unit
@pytest.mark.subsys_map
def test_trailing_whitespace_only_line_is_preserved() -> None:
    # No empty-key line in the tail → saw_key stays False → nothing is blanked.
    lines = ["Real prose.", "   "]
    _blank_trailing_config_tail(lines)
    assert lines[1] == "   "  # kills L119 False→True (mutant would blank the ws line)


# ──────────────────────────────────────────────────────────────────
# _blank_repo_dump_headers  (L170/L171 and→or, L172 or→and)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repo_dump_paired_rule_blanks_file_header() -> None:
    out = _blank_repo_dump_headers("====\nFile: src/foo.py\n====\nbody\n")
    assert "File: src/foo.py" not in out
    assert "body" in out


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repo_dump_one_sided_rule_still_blanks() -> None:
    out = _blank_repo_dump_headers("====\nFile: src/foo.py\nbody\n")
    assert "File: src/foo.py" not in out  # kills L172 or→and


@pytest.mark.unit
@pytest.mark.subsys_map
def test_file_header_without_any_rule_is_preserved() -> None:
    out = _blank_repo_dump_headers("intro\nFile: src/foo.py\nbody\n")
    # No adjacent ==== rule → a genuine "File:" line, must stay (kills L170/L171 and→or).
    assert "File: src/foo.py" in out
    assert "intro" in out


# ──────────────────────────────────────────────────────────────────
# _strip_frontmatter offset  (L207 !=→==)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_strip_frontmatter_reports_removed_line_offset() -> None:
    _, offset = _strip_frontmatter("---\nkey: value\n---\nBody prose.\n")
    assert offset == 3  # kills L207 ==-mutant (would leave offset at 0)


# ──────────────────────────────────────────────────────────────────
# _split_at_softbreaks  (L222 ==→!=)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_split_at_softbreaks_splits_and_drops_break() -> None:
    children = [_Child("text", "a"), _Child("softbreak"), _Child("text", "b")]
    segs = _split_at_softbreaks(children)
    assert len(segs) == 2
    assert all(c.type != "softbreak" for s in segs for c in s)


# ──────────────────────────────────────────────────────────────────
# _extract_texts inline code  (L264 ==→!=)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_extract_texts_inline_code_becomes_backtick_token() -> None:
    md_text, plain_text, inline = _extract_texts([_Child("code_inline", "npm")])
    assert plain_text == "npm"
    assert md_text == "`npm`"
    assert any(t.text == "npm" and t.format == "backtick" for t in inline)


# ──────────────────────────────────────────────────────────────────
# _determine_format  (L287/289/291/293 ==→!=)
# ──────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("stack", "expected"),
    [
        (["table"], "table"),
        (["blockquote"], "blockquote"),
        (["ordered_list"], "numbered"),
        (["bullet_list"], "list"),
        ([], "prose"),
    ],
)
@pytest.mark.unit
@pytest.mark.subsys_map
def test_determine_format_maps_block_tag(stack: list[str], expected: str) -> None:
    assert _determine_format(stack) == expected


@pytest.mark.unit
@pytest.mark.subsys_map
def test_split_at_softbreaks_splits_hardbreak_too() -> None:
    # A hardbreak (trailing two-space / `\` break) ends a logical line like a softbreak,
    # so two lines never merge into one atom.
    class _Tok:
        def __init__(self, t: str) -> None:
            self.type = t

    assert len(_split_at_softbreaks([_Tok("text"), _Tok("hardbreak"), _Tok("text")])) == 2
    assert len(_split_at_softbreaks([_Tok("text"), _Tok("softbreak"), _Tok("text")])) == 2


# ──────────────────────────────────────────────────────────────────
# A body ``---`` block whose content is headings +
# bullets under a prose-shaped label line (`Usage:`, `Trigger:`) must NOT be
# read as a YAML block and blanked — every non-blank line must be YAML-shaped
# for the block to qualify.
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_h1_unclosed_heading_bullet_block_is_not_blanked() -> None:
    text = (
        "# Agent guide\n\n"
        "Intro paragraph that survives.\n\n"
        "---\n\n"
        "Usage: invoke the agent with a target path\n\n"
        "## Rules\n\n"
        "- Never commit secrets to the repository.\n"
        "- Always run the test suite before pushing.\n\n"
        "## Notes\n\n"
        "- Keep the diff small.\n"
    )
    out = _blank_body_yaml_blocks(text)
    assert "Usage: invoke the agent with a target path" in out
    assert "## Rules" in out
    assert "Never commit secrets to the repository." in out
    assert "Always run the test suite before pushing." in out
    assert "## Notes" in out
    assert "Keep the diff small." in out


@pytest.mark.unit
@pytest.mark.subsys_map
def test_h1_closed_heading_bullet_block_is_not_blanked() -> None:
    text = (
        "Intro line.\n\n"
        "---\n\n"
        "Trigger: when the user asks\n\n"
        "## Rules\n\n"
        "- Never commit secrets to the repository.\n"
        "- Always run the test suite before pushing.\n\n"
        "---\n\n"
        "More text after.\n"
    )
    out = _blank_body_yaml_blocks(text)
    assert "Trigger: when the user asks" in out
    assert "## Rules" in out
    assert "Never commit secrets to the repository." in out
    assert "Always run the test suite before pushing." in out
    assert "More text after." in out


@pytest.mark.unit
@pytest.mark.subsys_map
def test_h1_genuine_yaml_block_with_list_under_key_still_blanked() -> None:
    # A real YAML block (key + a `- ` item that is a YAML list value under that
    # key, not a markdown bullet under a heading) must still be stripped.
    text = "Prose before.\n\n---\ntags:\n  - one\n  - two\n---\n\nProse after.\n"
    out = _blank_body_yaml_blocks(text)
    assert "tags:" not in out
    assert "Prose before." in out
    assert "Prose after." in out


# ──────────────────────────────────────────────────────────────────
# `_blank_body_yaml_blocks` must never blank content
# inside a fenced code block — a ``---``-delimited YAML sample inside a
# ```yaml fence is real content, not body frontmatter.
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_h2_yaml_sample_inside_fence_is_not_blanked() -> None:
    text = "Some intro.\n\n```yaml\n---\npaths: src/**/*.py\n---\n```\n\nMore text.\n"
    out = _blank_body_yaml_blocks(text)
    assert "paths: src/**/*.py" in out
    assert "Some intro." in out
    assert "More text." in out


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("fence", ["~~~yaml", "````yaml"])
def test_yaml_sample_inside_tilde_or_long_fence_is_not_blanked(fence: str) -> None:
    closer = fence[: len(fence) - len("yaml")]
    text = f"Intro.\n\n{fence}\n---\npaths: src/**/*.py\n---\n```\n{closer}\n\nMore text.\n"
    assert "paths: src/**/*.py" in _blank_body_yaml_blocks(text)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_h2_yaml_block_outside_fence_still_blanked() -> None:
    text = "Prose before.\n\n---\nkey: value\n---\n\n```text\nnot a fence marker really\n```\n\nProse after.\n"
    out = _blank_body_yaml_blocks(text)
    assert "key: value" not in out
    assert "Prose before." in out
    assert "not a fence marker really" in out
    assert "Prose after." in out


# ──────────────────────────────────────────────────────────────────
# `_strip_frontmatter`'s leading strip needs a YAML
# guard (a `#` heading right after the opener is NOT frontmatter) and must
# match the closer as a whole ``---`` line, not any substring prefix (`----`).
# ──────────────────────────────────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_strip_frontmatter_requires_yaml_key_after_opener() -> None:
    content = "---\n# Title\nNever commit secrets.\n---\nMore text here.\n"
    stripped, offset = _strip_frontmatter(content)
    assert stripped == content
    assert offset == 0


@pytest.mark.unit
@pytest.mark.subsys_map
def test_strip_frontmatter_closer_must_be_whole_line_not_prefix() -> None:
    content = "---\nkey: value\n----\n---\nBody prose.\n"
    stripped, offset = _strip_frontmatter(content)
    assert stripped == "Body prose.\n"
    assert offset == 4


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_backtick_line_with_a_backtick_in_its_info_string_opens_no_fence() -> None:
    """A config block after a line that only looks like a fence is still blanked."""
    text = "# T\n\n``` `x`\n---\nname: v\n---\n\nAfter.\n"
    assert _blank_body_yaml_blocks(text) == "# T\n\n``` `x`\n\n\n\n\nAfter.\n"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_config_sample_inside_a_real_fence_is_kept() -> None:
    text = "# T\n\n```js\n---\nname: v\n---\n```\n\nAfter.\n"
    assert _blank_body_yaml_blocks(text) == text
