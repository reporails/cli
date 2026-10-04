"""Content-format detection for freeform (markdown) instruction files.

Reports which markdown region types (prose, heading, list, table, blockquote,
code/data block) and inline modes (bold, inline_code, link) a file contains,
read from the markdown parse so examples inside fenced blocks don't
false-positive. This is markdown analysis, not agent-specific file classification.
"""

from __future__ import annotations

from typing import Any

from reporails_cli.core.mapper.parse import parse_blocks

_DATA_LANGS = frozenset({"mermaid", "yaml", "yml", "json", "toml", "xml", "csv"})

# Block token type that opens each region type.
_BLOCK_OPENERS = {
    "heading_open": "heading",
    "table_open": "table",
    "bullet_list_open": "list",
    "ordered_list_open": "list",
    "blockquote_open": "blockquote",
}

# Shortest paragraph line (stripped) that counts as prose.
_PROSE_MIN_LEN = 10


def _fence_format(info: str) -> str:
    """``data_block`` for a fence whose language tag names structured data, else ``code_block``."""
    words = info.split()
    return "data_block" if words and words[0].lower() in _DATA_LANGS else "code_block"


def _has_prose(tokens: list[Any], index: int) -> bool:
    """Whether the top-level paragraph opened at ``tokens[index]`` has a non-trivial line."""
    lines = tokens[index + 1].content.split("\n")
    return any(len(line.strip()) > _PROSE_MIN_LEN for line in lines)


def detect_content_format(text: str) -> list[str]:
    """Detect which content region types are present in markdown text.

    Content format is intrinsic to freeform (markdown) files — not agent-specific.
    Returns the list of content_format values found.

    Block-level values:
      prose: natural language paragraphs
      heading: markdown section headers
      code_block: fenced code blocks
      data_block: structured data/visualization (mermaid, yaml, json, toml)
      table: markdown tables
      list: ordered/unordered lists
      blockquote: quoted blocks

    Inline values (detected outside code blocks):
      inline_code: code spans
      bold: **text** or __text__ emphasis
      link: [text](url) hyperlinks and images
    """
    formats: set[str] = set()
    tokens, _ = parse_blocks(text)

    for i, tok in enumerate(tokens):
        if tok.type == "fence":
            formats.add(_fence_format(tok.info))
        elif tok.type in _BLOCK_OPENERS:
            formats.add(_BLOCK_OPENERS[tok.type])
        elif tok.type == "paragraph_open" and tok.level == 0 and _has_prose(tokens, i):
            formats.add("prose")
        elif tok.type == "inline":
            kinds = {child.type for child in tok.children or []}
            if "code_inline" in kinds:
                formats.add("inline_code")
            if kinds & {"link_open", "image"}:
                formats.add("link")
            if "strong_open" in kinds:
                formats.add("bold")

    return sorted(formats)
