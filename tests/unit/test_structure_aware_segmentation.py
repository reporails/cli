"""Format-aware segmentation routing in the atomizer (structure-aware mode).

Prose splits into whole sentences; list/numbered items stay whole; the mode is
opt-in; the default keeps each paragraph line and list item whole.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper import bio_pipeline
from reporails_cli.core.mapper.parse import tokenize

_needs_model = pytest.mark.skipif(not bio_pipeline.multislot_available(), reason="multislot model not bundled")


def _texts(atoms, fmt: str) -> list[str]:
    return [a.text for a in atoms if a.format == fmt and a.kind != "heading"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_prose_splits_into_whole_sentences() -> None:
    md = "Read the file before editing. Do not skip this step. Always verify the result."
    atoms = tokenize(md, "structure-aware")
    assert _texts(atoms, "prose") == [
        "Read the file before editing.",
        "Do not skip this step.",
        "Always verify the result.",
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_prose_does_not_fragment_at_dash_or_colon() -> None:
    md = "Do not skip this step — it is required: never omit it."
    prose = _texts(tokenize(md, "structure-aware"), "prose")
    assert prose == ["Do not skip this step — it is required: never omit it."]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_list_items_kept_whole() -> None:
    # A SAME-charge compound list item is not fragmented — only a charge-sign
    # flip splits, so two prohibitions stay one atom.
    md = "- Never commit secrets, and never push credentials\n- Use the pipeline\n"
    items = _texts(tokenize(md, "structure-aware"), "list")
    assert items == [
        "Never commit secrets, and never push credentials",
        "Use the pipeline",
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_list_item_splits_at_charge_flip() -> None:
    # A list item packing a prohibition and a directive reads as the two instructions it gives,
    # so the +1 "always check…" is not swallowed by the -1 lead prohibition.
    md = "- Never commit without running the tests, and always check the output first\n"
    atoms = [a for a in bio_pipeline.apply_multislot(tokenize(md, "structure-aware")) if a.kind != "heading"]
    assert sorted(a.charge_value for a in atoms) == [-1, 1]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_numbered_items_kept_whole_across_semicolon_and_comma() -> None:
    md = "1. First install the deps; then run the build\n2. Configure the token, the region, and the endpoint\n"
    items = _texts(tokenize(md, "numbered"), "numbered")
    assert items == [
        "First install the deps; then run the build",
        "Configure the token, the region, and the endpoint",
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_legacy_is_the_default_mode() -> None:
    # No mode arg resolves to the legacy segmentation path.
    md = "Read the file. Do not skip this — always verify."
    assert _texts(tokenize(md), "prose") == _texts(tokenize(md, "legacy"), "prose")


@pytest.mark.unit
@pytest.mark.subsys_map
@_needs_model
def test_charge_flip_recovered_in_both_modes() -> None:
    # Both modes read a sentence giving two instructions as two, so the prohibition is never swallowed.
    md = "Read the whole file, do not skim it."
    for mode in ("legacy", "structure-aware"):
        atoms = [a for a in bio_pipeline.apply_multislot(tokenize(md, mode)) if a.kind != "heading"]
        signs = sorted(a.charge_value for a in atoms)
        assert signs == [-1, 1], f"mode={mode} signs={signs}"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_body_yaml_block_stripped() -> None:
    # A body ---delimited YAML block is a config, not an instruction: without the
    # strip, markdown-it reads the closing --- as a setext underline and the whole
    # block leaks in as one atom.
    md = (
        "Use tabs for indentation.\n\n"
        "---\n"
        "progressive_disclosure:\n"
        "  entry_point:\n"
        '    summary: "E2E testing"\n'
        "---\n\n"
        "Verify the result.\n"
    )
    texts = [a.text for a in tokenize(md, "structure-aware")]
    assert "Use tabs for indentation." in texts
    assert "Verify the result." in texts
    assert not any("progressive_disclosure" in t or "entry_point" in t for t in texts)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_divider_and_setext_are_not_yaml_blocks() -> None:
    # A lone --- (thematic break) and a text/--- setext heading must survive — only
    # a --- whose first content line is a YAML key opens a strippable block.
    md = "Prose before.\n\n---\n\nSetext Heading\n---\nBody after.\n"
    texts = [a.text for a in tokenize(md, "structure-aware")]
    assert "Setext Heading" in texts
    assert "Body after." in texts


@pytest.mark.unit
@pytest.mark.subsys_map
def test_cursor_heading_led_frontmatter_stripped() -> None:
    # A Cursor .mdc carries a second ---block whose first line is a # heading, so
    # the description:/globs: keys below would read as a setext heading. It has
    # YAML keys and no prose, so it is stripped like a YAML-key-first block.
    md = (
        "---\n"
        "alwaysApply: true\n"
        "---\n"
        "---\n"
        "# rule for SQL files\n"
        "description: SQL conventions\n"
        "globs: *.sql\n"
        "---\n\n"
        "Use parameterized queries.\n"
    )
    texts = [a.text for a in tokenize(md, "structure-aware")]
    assert "Use parameterized queries." in texts
    assert not any("description" in t or "globs" in t or "SQL conventions" in t for t in texts)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_trailing_empty_key_block_stripped() -> None:
    # A dangling description:/globs: tail at EOF (no closing ---) is config residue.
    md = "Prefer explicit imports.\n\ndescription:\nglobs:\n"
    texts = [a.text for a in tokenize(md, "structure-aware")]
    assert "Prefer explicit imports." in texts
    assert not any(t.strip() in {"description:", "globs:"} for t in texts)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_repo_dump_file_header_stripped() -> None:
    # A concatenated .cursorrules dump separates members with a ====rule and a
    # File: <path> header; markdown reads the rule as a setext underline, so the
    # path leaks in as a heading. Both are scaffolding, not instructions.
    md = (
        "Follow the style guide.\n\n"
        "======================\n"
        "File: rules/python.mdc\n"
        "======================\n\n"
        "Keep functions small.\n"
    )
    texts = [a.text for a in tokenize(md, "structure-aware")]
    assert "Follow the style guide." in texts
    assert "Keep functions small." in texts
    assert not any("rules/python.mdc" in t or t.startswith("File:") for t in texts)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_inline_triple_backtick_mention_survives() -> None:
    # Over-strip guard: an instruction that names ``` inline is a real instruction,
    # not a fenced block. It must survive the config/scaffolding strips.
    md = "Do not use triple backticks (```) to enclose the code.\n"
    texts = [a.text for a in tokenize(md, "structure-aware")]
    assert any("triple backticks" in t for t in texts)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_escaped_code_fence_reads_as_code_not_prose() -> None:
    # A Cursor .mdc often escapes its code fences (\\`\\`\\`) so markdown never sees a
    # fence: the marker and its code leak as prose atoms. The escaped marker line is
    # rewritten to a real fence, so the whole block reads as code and drops out.
    md = (
        "Never generate this pattern:\n\n"
        "\\`\\`\\`typescript\n"
        "const bad = cookieStore.get(name)\n"
        "\\`\\`\\`\n\n"
        "Use the server client instead.\n"
    )
    atoms = [a for a in tokenize(md, "structure-aware") if a.format != "code_block"]
    texts = [a.text for a in atoms]
    assert "Never generate this pattern:" in texts
    assert "Use the server client instead." in texts
    assert not any("```" in t or "cookieStore" in t for t in texts)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_unclosed_yaml_block_at_eof_stripped() -> None:
    # A body ---block opened by a YAML key with no closing --- (a Cursor
    # progressive_disclosure fragment running to EOF) is config, not instruction.
    md = (
        "# Skill\n\n"
        "---\n"
        "progressive_disclosure:\n"
        "  entry_point:\n"
        '    summary: "E2E testing"\n'
        "    when_to_use:\n"
        '      - "When testing web apps"\n'
    )
    texts = [a.text for a in tokenize(md, "structure-aware")]
    assert not any("progressive_disclosure" in t or "entry_point" in t or "when_to_use" in t for t in texts)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_real_divider_then_list_to_eof_survives() -> None:
    # Guard for the EOF-close relaxation: a genuine --- thematic break followed by a
    # real bullet list to EOF must survive — it opens no block (first line is a list
    # item, not a YAML key), so its items are not mistaken for config.
    md = "Setup steps.\n\n---\n\n- Install the toolchain.\n- Run the migration.\n"
    texts = [a.text for a in tokenize(md, "structure-aware")]
    assert "Install the toolchain." in texts
    assert "Run the migration." in texts
