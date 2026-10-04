# ruff: noqa: PERF401
"""Markdown text extraction — the charge-free half of the atomizer.

Frontmatter stripping, softbreak segmentation, and the md-text / plain-text /
inline-token split from a markdown-it inline segment, plus block-stack → format
mapping. Pure markdown structure: no charge classification, so it splits cleanly
out of ``parse.py`` while the charge layer stays put.
"""

from __future__ import annotations

import re
from typing import Any

from reporails_cli.core.mapper.lexicon import load_markdown_tokens
from reporails_cli.core.mapper.md_parser import md_parser
from reporails_cli.core.platform.dto.ruleset import InlineToken
from reporails_cli.core.platform.utils.utils import frontmatter_block, strip_frontmatter

# Emoji, pictographic, and box-drawing ranges stripped from atom text. Covers the
# pictographic/emoticon/transport/supplemental blocks, misc symbols, dingbats,
# technical, misc-symbols-and-arrows, regional-indicator flags, geometric shapes
# used as bullets, the emoji-property singletons outside those blocks, and the
# variation selectors + ZWJ + keycap that build emoji sequences.
#
# Trademark marks (`™ ® ©`) and arrows (`→ ↔ ↩`) carry the emoji property but are
# deliberately kept: a mark attaches to a product name that is part of the
# instruction, and an arrow is a gloss marker the sentence splitter reads.
# Box-drawing runs (`├── src/`) ARE stripped: a diagram frame is decoration on
# the text it encloses, exactly as an emoji is, and `│ Deploy to prod │` should
# embed as its words. A fenced code block never passes through here (`parse.py`
# reads `tok.content` directly), so a tree diagram inside a fence keeps its
# frame. A pure ASCII rule (`|-----+-----|`) carries no letter and is dropped
# downstream as a unit, so its `|` and `-` need no character-level strip — one
# that did would maim every hyphenated word and every real table row.
_EMOJI_RE = re.compile(
    "[\U0001f000-\U0001faff"  # pictographs, emoticons, transport, supplemental, extended-A, skin tones
    "\U00002600-\U000026ff"  # miscellaneous symbols (⚠ ☀ ⚡)
    "\U00002700-\U000027bf"  # dingbats (✅ ✂ ✈ ✔)
    "\U00002300-\U000023ff"  # miscellaneous technical (⌚ ⏰ ⏳)
    "\U00002b00-\U00002bff"  # miscellaneous symbols and arrows (⬆ ⬇ ⭐)
    "\U0001f1e6-\U0001f1ff"  # regional indicator symbols (flags)
    "\U00002500-\U0000259f"  # box drawing + block elements — ASCII-art frames
    "\U000025a0-\U000025ff"  # geometric shapes used as bullets
    "\U0000203c\U00002049"  # double-exclamation, exclamation-question
    "\U00002139\U000024c2"  # information source, circled M
    "\U00002934\U00002935"  # curved arrows (emoji presentation)
    "\U00003030\U0000303d"  # wavy dash, part alternation mark
    "\U00003297\U00003299"  # circled ideographs (congratulation, secret)
    "\U0000fe00-\U0000fe0f"  # variation selectors (emoji presentation)
    "\U000020e3"  # combining enclosing keycap
    "\U0000200d]+",  # zero-width joiner
    flags=re.UNICODE,
)


def _strip_decoration(text: str) -> str:
    """Remove emoji, pictographs, and diagram frames; collapse the gaps they leave."""
    return re.sub(r"\s+", " ", _EMOJI_RE.sub(" ", text)).strip()


# A YAML key line — `key:` / `key: value` / `nested-key.dotted:`. Distinguishes a
# `---`-delimited YAML block from a bare `---` thematic-break/setext divider: the
# line after the opening `---` is a key here, prose there.
_YAML_KEY_RE = re.compile(r"^\s*[\w][\w.-]*:(\s|$)")
# A YAML key with an empty value (`description:`, `globs:`) — config residue, not prose.
_EMPTY_YAML_KEY_RE = re.compile(r"^\s*[\w][\w.-]*:\s*$")
# A repo-dump separator: a rule of `=` and its `File: <path>` member header.
_RULE_RE = re.compile(r"^={4,}\s*$")
_FILE_HEADER_RE = re.compile(r"^File:\s*\S")
# A whole line that is only a backslash-escaped code-fence marker (`\`\`\`` or
# `\`\`\`lang`). markdown reads the escaped backticks as literal text, so the
# marker and its "code" leak as prose; converting the line to a real fence lets
# the code-block path claim the block. An inline mention keeps text on the line,
# so the line anchors (`^…$`) never match it.
_ESCAPED_FENCE_RE = re.compile(r"^(\s*)(?:\\`){3,}\s*([\w+-]*)\s*$")


def _is_prose_line(line: str) -> bool:
    """A content line that is neither a ``#`` heading, a YAML key, nor a YAML list item."""
    s = line.strip()
    if not s or s == "---" or s.startswith("#") or s.startswith("- "):
        return False
    return not _YAML_KEY_RE.match(line)


def _body_is_all_yaml_shaped(body: list[str]) -> bool:
    """True when every non-blank line of a candidate YAML block is YAML-shaped.

    YAML-shaped: a ``key:`` line, an indented continuation of the previous key,
    or a ``- `` item directly following a key (a YAML list value). A ``#``
    heading is allowed only as the block's very first line — the Cursor
    ``.mdc`` heading-led rule-config variant — because a heading anywhere else
    is a real section title, not config. A markdown bullet under such a
    heading (`- Never commit secrets…`) is content, not a YAML list value, so
    it disqualifies the block once no key has opened it. A block with no key
    line at all is never config.
    """
    saw_key = False
    for idx, raw in enumerate(body):
        s = raw.strip()
        if not s:
            continue
        if idx == 0 and s.startswith("#"):
            continue
        if _YAML_KEY_RE.match(raw):
            saw_key = True
            continue
        if saw_key and (raw[:1] in (" ", "\t") or s.startswith("- ")):
            continue
        return False
    return saw_key


def _config_block_end(lines: list[str], i: int, n: int, fence_mask: list[bool] | None = None) -> int | None:
    """End index of a strippable ``---``-fenced config block opened at ``i``, or None.

    Opens when the first non-blank line is a YAML key or a ``#`` heading/comment;
    strips only when EVERY non-blank line of the body is YAML-shaped (see
    :func:`_body_is_all_yaml_shaped`), and is closed by a matched ``---`` or by
    end-of-file (an unclosed frontmatter fragment). This covers the Cursor
    ``.mdc`` variant whose block is led by a ``#`` heading. A genuine
    ``---``/heading/prose section (no YAML keys, or any non-YAML-shaped line)
    is left intact — the all-YAML-shaped guard is what makes EOF-closing safe.
    ``fence_mask``, when given, marks line indices inside a fenced code block —
    a body that reaches into one is never a config block (fence content is not
    scanned across a boundary).
    """
    j = i + 1
    while j < n and not lines[j].strip():
        j += 1
    if j >= n:
        return None
    if not (_YAML_KEY_RE.match(lines[j]) or lines[j].lstrip().startswith("#")):
        return None
    k = j
    while k < n and lines[k].strip() != "---":
        k += 1
    body = lines[j:k]  # up to the closing --- (or EOF)
    if fence_mask and any(fence_mask[idx] for idx in range(j, k)):
        return None
    if _body_is_all_yaml_shaped(body):
        return k if k < n else n - 1
    return None


def _blank_trailing_config_tail(lines: list[str]) -> None:
    """Blank a dangling empty-key config tail (`description:`/`globs:`) at EOF, in place.

    A Cursor ``.mdc`` frontmatter fragment can trail at EOF with no closing ``---``;
    its empty-valued keys are config residue. A run of blank + empty-YAML-key lines
    reaching EOF is blanked when it carries at least one such key and no prose.
    """
    k = len(lines)
    saw_key = False
    while k > 0 and (not lines[k - 1].strip() or _EMPTY_YAML_KEY_RE.match(lines[k - 1])):
        if lines[k - 1].strip():
            saw_key = True
        k -= 1
    if saw_key:
        for idx in range(k, len(lines)):
            lines[idx] = ""


def _fence_mask(text: str, line_count: int) -> list[bool]:
    """Per-line mask: True for every line of `text` inside a code block (fenced, open through close).

    An unterminated fence runs to the end of the file, and a line that only looks like
    a fence (a backtick opener whose info string holds a backtick) opens nothing.
    A text with no `---` line has no block to tell apart, so its mask is all False.
    """
    mask = [False] * line_count
    if not any(line.strip() == "---" for line in text.split("\n")):
        return mask
    for tok in md_parser.parse(text):
        if tok.type in ("fence", "code_block") and tok.map:
            for idx in range(tok.map[0], min(tok.map[1], line_count)):
                mask[idx] = True
    return mask


def _blank_body_yaml_blocks(text: str) -> str:
    """Blank out ``---``-delimited config blocks in the body, preserving line count.

    markdown-it reads a body ``---\\nkey: v\\n---`` block as a setext heading (the
    closing ``---`` underlines the config), so the whole block leaks in as one
    atom. A config block is not an instruction — drop it. Lines are replaced with
    blanks rather than removed so every downstream atom keeps its source line
    number. A lone ``---`` (thematic break, or a setext underline under prose) is
    left intact: only a ``---`` block whose content is YAML keys (see
    :func:`_config_block_end`) opens a stripped block, and a dangling empty-key
    tail at EOF is blanked too. A ``---`` sitting inside a fenced code block
    (`_fence_mask`) never opens a block — that content is a code sample, not
    frontmatter.
    """
    lines = text.split("\n")
    fence_mask = _fence_mask(text, len(lines))
    out: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        end = _config_block_end(lines, i, n, fence_mask) if lines[i].strip() == "---" and not fence_mask[i] else None
        if end is not None:
            out.extend([""] * (end - i + 1))
            i = end + 1
            continue
        out.append(lines[i])
        i += 1
    _blank_trailing_config_tail(out)
    return "\n".join(out)


def _blank_repo_dump_headers(text: str) -> str:
    """Blank concatenated-repo-dump scaffolding (`====` rules + `File: <path>` headers).

    A `.cursorrules` dump pasted into one file separates members with a `====` rule
    and a `File: <path>` line; markdown reads the rule as a setext underline, so the
    path leaks in as a heading. Blank the rule and its `File:` header, preserving
    line count. A `====` rule not paired with a `File:` header is a genuine setext
    underline and is left intact.
    """
    lines = text.split("\n")
    n = len(lines)
    for i in range(n):
        if not _FILE_HEADER_RE.match(lines[i]):
            continue
        prev_rule = i > 0 and _RULE_RE.match(lines[i - 1])
        next_rule = i + 1 < n and _RULE_RE.match(lines[i + 1])
        if prev_rule or next_rule:
            lines[i] = ""
            if prev_rule:
                lines[i - 1] = ""
            if next_rule:
                lines[i + 1] = ""
    return "\n".join(lines)


def _convert_escaped_fences(text: str) -> str:
    """Rewrite backslash-escaped code-fence marker lines to real fence markers.

    A line that is only ``\\`\\`\\``` (optionally with a language tag) becomes
    ```` ``` ````/```` ```lang ````, so the fenced-code path reads the block as
    code rather than letting the marker and its body leak as prose. Line count is
    preserved; an inline ``\\`\\`\\``` mention keeps other text on its line, so the
    anchored pattern never matches it.
    """
    out = [
        (f"{m.group(1)}```{m.group(2)}" if (m := _ESCAPED_FENCE_RE.match(line)) else line) for line in text.split("\n")
    ]
    return "\n".join(out)


def _strip_frontmatter(content: str) -> tuple[str, int]:
    """Strip YAML frontmatter + body config blocks + repo-dump scaffolding.

    Returns (stripped, lines_removed). The leading block is stripped only when
    the first non-blank line after the opener is a YAML key line — a ``#``
    heading or prose there means the leading ``---`` is a thematic break, not
    frontmatter, and is left for the AST to read as its own token. A leading
    second ``---`` block (the Cursor ``.mdc`` double frontmatter) is left to
    :func:`_blank_body_yaml_blocks`, which blanks it in place so line numbers
    stay aligned.
    """
    block = frontmatter_block(content)
    first = next((line for line in block.text.split("\n") if line.strip()), "") if block else ""
    if block is None or not _YAML_KEY_RE.match(first):
        return _convert_escaped_fences(_blank_repo_dump_headers(_blank_body_yaml_blocks(content))), 0
    rest = strip_frontmatter(content)
    return _convert_escaped_fences(_blank_repo_dump_headers(_blank_body_yaml_blocks(rest))), block.body_line


def _split_at_softbreaks(children: list[Any]) -> list[list[Any]]:
    """Split inline children into per-line segments at line-break boundaries.

    Both `softbreak` (a bare newline) and `hardbreak` (a trailing two-space or `\\` break)
    end a logical line. A hardbreak that was not split merged the two lines into one atom —
    gluing the trailing and leading words together and dropping the second line's charge.
    """
    segments: list[list[Any]] = [[]]
    for child in children:
        if child.type in ("softbreak", "hardbreak"):
            segments.append([])
        else:
            segments[-1].append(child)
    return [s for s in segments if s]


def _append_content_tokens(
    content: str,
    fmt: str,
    md_parts: list[str],
    plain_parts: list[str],
    inline_tokens: list[InlineToken],
    md_prefix: str = "",
) -> None:
    """Append text content with format tracking to md/plain/inline collectors."""
    md_parts.append(f"{md_prefix}{content}" if md_prefix else content)
    plain_parts.append(content)
    for word in content.split():
        inline_tokens.append(InlineToken(text=word, format=fmt))


def _extract_texts(
    segment: list[Any],
) -> tuple[str, str, list[InlineToken]]:
    """Extract md_text, plain_text, and inline_tokens from AST children.

    md_text preserves `backtick`, **bold**, *italic* markers for check_specificity().
    plain_text strips all markers for 3rd-person detection.
    inline_tokens provides per-word format context for Phase 3 backtick filter.
    """
    tokens = load_markdown_tokens()
    format_open = tokens.format_open
    format_close = tokens.format_close
    md_parts: list[str] = []
    plain_parts: list[str] = []
    inline_tokens: list[InlineToken] = []
    format_stack: list[str] = ["plain"]

    for child in segment:
        if child.type in ("text", "html_inline"):
            _append_content_tokens(child.content, format_stack[-1], md_parts, plain_parts, inline_tokens)
        elif child.type == "code_inline":
            md_parts.append(f"`{child.content}`")
            plain_parts.append(child.content)
            for word in child.content.split():
                inline_tokens.append(InlineToken(text=word, format="backtick"))
        elif child.type in format_open:
            marker, fmt = format_open[child.type]
            md_parts.append(marker)
            format_stack.append(fmt)
        elif child.type in format_close:
            md_parts.append(format_close[child.type])
            if len(format_stack) > 1:
                format_stack.pop()
        # link_open, link_close: skip — text child handles content

    md_text = _strip_decoration("".join(md_parts).strip())
    plain_text = _strip_decoration("".join(plain_parts).strip())
    return md_text, plain_text, inline_tokens


def _determine_format(block_stack: list[str]) -> str:
    """Map the current block nesting stack to a format string."""
    for tag in reversed(block_stack):
        if tag == "table":
            return "table"
        if tag == "blockquote":
            return "blockquote"
        if tag == "ordered_list":
            return "numbered"
        if tag == "bullet_list":
            return "list"
    return "prose"
