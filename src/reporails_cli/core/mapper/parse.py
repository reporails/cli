"""Markdown-it AST walk and atom assembly.

Parses the markdown source into an AST and walks it, tracking block nesting
(lists, blockquotes, tables, code fences) to populate each atom's `format` and
`position_index`. Each inline segment yields two parallel text streams: `md_text`
(formatting markers preserved) and `plain_text` (markers stripped). The walk ends
with the post-classify passes (sentence splitting, embedded-marker scans), so the
returned atom list is ready for embedding.

Public entry point: `tokenize(content)`.
"""

from __future__ import annotations

import re

from markdown_it.token import Token
from markdown_it.utils import EnvType

from reporails_cli.core.mapper.atom_build import (
    _atom_from_sentence,
    _ends_with_colon,
    _make_inline_atom,
    _specificity_fields,
)
from reporails_cli.core.mapper.charge_floors import TABLE_HEADER_RULE, _classify_content, is_quoted_line
from reporails_cli.core.mapper.classify import classify_charge
from reporails_cli.core.mapper.embedded_markers import (
    _scan_charged_for_compound_markers,
    _scan_neutral_for_embedded_markers,
)
from reporails_cli.core.mapper.fence_atoms import _make_fence_atom, _process_fence
from reporails_cli.core.mapper.lexicon import load_markdown_tokens
from reporails_cli.core.mapper.markdown_extract import (
    _determine_format,
    _extract_texts,
    _split_at_softbreaks,
    _strip_decoration,
    _strip_frontmatter,
)
from reporails_cli.core.mapper.md_parser import (
    CODE_BLOCK_TOKENS,
    LINE_BREAK_TOKENS,
    md_parser,
    replace_code_spans,
    tok_line,
)
from reporails_cli.core.mapper.prose_split import SEGMENTATION_STRUCTURE_AWARE, carries_word, split_prose_sentences
from reporails_cli.core.platform.dto.ruleset import LIST_OBJECT_ROLE, SENTENCE_SPLIT_FORMATS, Atom, AtomFormat


def _drop_contentless_atoms(atoms: list[Atom]) -> list[Atom]:
    """Drop every unit holding no letter, and re-index what remains.

    A run of bare markers (`» » » »`, `-> -> ->`, `1. 2. 3. 4.`) carries no
    instruction, so it must not survive as a unit: it would be classified,
    embedded, grouped, and counted like any other, diluting every measure it
    lands in. The length floor upstream counts characters, which a repeated
    marker passes at any length — content decides, not size.

    A WORD is what makes a span content. A bare figure (`-> 3 <-`, `100`) has
    nothing for the embedder to place: a number means something only through the
    words around it, so a span carrying digits but no letters is a marker too.
    Nor does a lone letter qualify — `A. … | … | … | …` is a template row whose
    label is a list marker, not a word, so content needs a run of at least two
    letters. A non-Latin script is exempt from the run length: a single CJK
    character is a word, and `isalpha` is Unicode-wide.
    """
    kept = [a for a in atoms if carries_word(a.text)]
    reindex_positions(kept)
    return kept


def holds_position(atom: Atom) -> bool:
    """Whether an atom takes a place in its file's document order.

    Every unit of running text does, and so does a heading that gives an instruction. A
    heading that only titles its section does not, nor does a list item read as the
    object of the instruction that introduces it.
    """
    if atom.role == LIST_OBJECT_ROLE:
        return False
    return atom.kind != "heading" or atom.charge_value != 0


def reindex_positions(atoms: list[Atom]) -> None:
    """Number each file's place-holding atoms 0..n in document order.

    A list item read as an object takes `-1`; a heading that only titles its section
    keeps the default `0` and no place of its own.
    """
    next_pos: dict[str, int] = {}
    for atom in atoms:
        if holds_position(atom):
            pos = next_pos.get(atom.file_path, 0)
            atom.position_index = pos
            next_pos[atom.file_path] = pos + 1
        elif atom.role == LIST_OBJECT_ROLE:
            atom.position_index = -1
        else:
            atom.position_index = 0


def inline_line(tok: Token, line_offset: int, pos: int) -> int:
    """The file line that offset `pos` of the inline token `tok`'s source text falls on."""
    content: str = tok.content
    return tok_line(tok, line_offset) + content.count("\n", 0, pos)


def _segment_lines(tok: Token, line_offset: int) -> list[int]:
    """The file line each line segment of the inline token `tok` starts on, in the order
    `_split_at_softbreaks` returns them: a line break ends a line, and any inline construct whose
    recorded source span runs onto the next line (code span, inline HTML tag, image, link) moves every
    later segment down with it."""
    line = tok_line(tok, line_offset)
    starts: list[int] = []
    open_segment = False
    link_end_line: list[int] = []
    for child in tok.children or []:
        if child.type in LINE_BREAK_TOKENS:
            line += 1
            open_segment = False
            continue
        if not open_segment:
            starts.append(line)
            open_segment = True
        span = child.meta.get("span")
        if span is not None:
            newlines = tok.content.count("\n", span[0], span[1])
            if child.type == "link_open":
                link_end_line.append(line + newlines)
            else:
                line += newlines
        elif child.type == "link_close" and link_end_line:
            line = link_end_line.pop()
    return starts


def _make_heading_atom(
    tok: Token,
    tokens: list[Token],
    i: int,
    line_offset: int,
) -> tuple[Atom, str]:
    """Create a heading atom and return (atom, heading_text)."""
    raw = tokens[i + 1].content if i + 1 < len(tokens) and tokens[i + 1].type == "inline" else ""
    # Headings read `.content` raw, unlike inline/table atoms that route through
    # `_extract_texts`; strip the same decoration so a leading emoji ("⛔ ...") does
    # not survive into the atom text or bias its charge classification.
    heading_text = _strip_decoration(raw)
    charge, cv, mod, rule, sc = classify_charge(heading_text)
    children = tokens[i + 1].children if i + 1 < len(tokens) and tokens[i + 1].type == "inline" else None
    plain_heading = _extract_texts(children)[1] if children else heading_text
    sf = _specificity_fields(heading_text, plain_heading)
    atom = Atom(
        line=tok_line(tok, line_offset),
        text=heading_text,
        kind="heading",
        charge=charge,
        charge_value=cv,
        modality=mod,
        specificity=sf["specificity"],
        format="heading",
        depth=int(tok.tag[1]),
        named_tokens=sf["named_tokens"],
        token_count=sf["token_count"],
        rule=rule,
        scope_conditional=sc,
    )
    return atom, heading_text


def _collect_table_cells(tokens: list[Token], start: int) -> tuple[str, str, int]:
    """Join one row's cells into that row's line. Returns (md, plain, next_index).

    A row is one LINE and the pipe is a mid-line delimiter, so the cells are
    joined rather than kept apart: a cell edge weakens what crosses it without
    yielding a second unit. Each cell is read through its own inline children,
    which is what gives the row a marker-free parallel form and what removes
    decoration from a cell exactly as it is removed from a paragraph.
    """
    md_cells: list[str] = []
    plain_cells: list[str] = []
    j = start + 1
    while j < len(tokens) and tokens[j].type != "tr_close":
        if tokens[j].type == "inline":
            md_cell, plain_cell = _extract_texts(tokens[j].children or [])
            md_cells.append(md_cell.strip())
            plain_cells.append(plain_cell.strip())
        j += 1
    return " | ".join(md_cells), " | ".join(plain_cells), j + 1


def _make_table_row_atom(
    tok: Token,
    tokens: list[Token],
    i: int,
    line_offset: int,
    *,
    pos_idx: int,
    current_heading: str,
) -> tuple[Atom | None, int]:
    """Create a table row atom. Returns (atom_or_None, next_token_index).

    A body row is classified like any other line. A header row names the table's
    columns, so it is a label row, never an instruction (`Leverage tier | Severity
    floor` does not tell the reader to leverage anything): it is NEUTRAL and marked
    `TABLE_HEADER_RULE`. Its words are still read, so a rules table headed
    `Requirement` places differently from the same table headed `Item`.
    """
    md_text, plain_text, next_i = _collect_table_cells(tokens, i)
    if len(md_text) < 5:
        return None, next_i
    header = i + 1 < len(tokens) and tokens[i + 1].type == "th_open"
    atom = _make_inline_atom(
        md_text,
        plain_text,
        "table",
        tok_line(tok, line_offset),
        pos_idx=pos_idx,
        current_heading=current_heading,
        precomputed=("NEUTRAL", 0, "none", TABLE_HEADER_RULE, False) if header else None,
    )
    return atom, next_i


def _update_block_stack(tok: Token, block_stack: list[str]) -> None:
    """Push/pop the block-nesting stack per a markdown-it block open/close token."""
    md_tokens = load_markdown_tokens()
    if tok.type in md_tokens.block_types:
        block_stack.append(md_tokens.block_types[tok.type])
    elif tok.type in md_tokens.block_close and block_stack:
        block_stack.pop()


_TASK_BOX_RE = re.compile(r"^\[[ xX]\]\s+")

# The blocks a paragraph can introduce: a list, a code block or a table.
_LEAD_IN_BLOCKS = frozenset({"bullet_list_open", "ordered_list_open", "table_open"}) | CODE_BLOCK_TOKENS


def _block_follows_paragraph(tokens: list[Token], i: int) -> bool:
    """True when the inline token at `i` ends its paragraph and a list, code block or table is the
    next block, whatever list items or quotes the paragraph's own block closes first."""
    if i + 1 >= len(tokens) or tokens[i + 1].type != "paragraph_close":
        return False
    j = i + 2
    while j < len(tokens) and tokens[j].type.endswith("_close"):
        j += 1
    return j < len(tokens) and tokens[j].type in _LEAD_IN_BLOCKS


def keep_lead_in_on_last(pieces: list[Atom]) -> None:
    """Of the pieces one line was cut into, only the last can end the line, so only it keeps `lead_in`."""
    for piece in pieces[:-1]:
        piece.lead_in = False


def _segment_atom(
    segment: list[Token], fmt: AtomFormat, line: int, pos_idx: int, current_heading: str, *, task_box: bool
) -> Atom | None:
    """The atom of one line segment of an inline token, or None when the line is too short to read."""
    md_text, plain_text = _extract_texts(segment)
    if task_box:
        md_text, plain_text = _TASK_BOX_RE.sub("", md_text), _TASK_BOX_RE.sub("", plain_text)
    if len(md_text) < 5:
        return None
    return _make_inline_atom(md_text, plain_text, fmt, line, pos_idx=pos_idx, current_heading=current_heading)


def _process_inline_segments(
    tok: Token,
    line_offset: int,
    block_stack: list[str],
    *,
    pos_idx: int,
    current_heading: str,
    atoms: list[Atom],
    block_follows: bool = False,
) -> int:
    """Process inline token segments, appending atoms. Returns updated pos_idx.

    `block_follows` is set when a list, code block or table comes right after the paragraph: its
    last line then ends a lead-in when the line ends with a colon.
    """
    fmt = _determine_format(block_stack)
    if fmt == "table":
        return pos_idx
    list_depth = sum(1 for tag in block_stack if tag in ("bullet_list", "ordered_list"))
    segments = _split_at_softbreaks(tok.children or [])
    for seg_idx, (segment, seg_line) in enumerate(zip(segments, _segment_lines(tok, line_offset), strict=True)):
        # A task list's checkbox marks the item's state; it is not a word of the item.
        atom = _segment_atom(
            segment, fmt, seg_line, pos_idx, current_heading, task_box=seg_idx == 0 and bool(list_depth)
        )
        if atom is None:
            continue
        atom.list_depth = list_depth
        atom.lead_in = block_follows and seg_idx == len(segments) - 1 and _ends_with_colon(atom.plain_text)
        atoms.append(atom)
        pos_idx += 1
    return pos_idx


def parse_blocks(content: str, env: EnvType | None = None) -> tuple[list[Token], int]:
    """The markdown-it token stream of `content` (front matter stripped) and the number of lines the
    stripping removed from the top, the offset every token's `map` line needs to be a file line.

    A caller that passes `env` finds the file's link reference definitions in it afterwards, under
    `env["references"]`, each with its `href` and the `map` lines it sits on.
    """
    stripped_content, line_offset = _strip_frontmatter(content)
    return md_parser.parse(stripped_content, env if env is not None else {}), line_offset


def inline_plain_text(md_text: str) -> str:
    """The plain text of one inline markdown fragment, read from its markdown AST.

    Emphasis, code-span and link markup drop out while every character they wrap
    stays, so a glob (`*.pem`) or an identifier (`fetch_bundled_model`) survives.
    """
    blocks = md_parser.parseInline(md_text)
    return _extract_texts(blocks[0].children or [])[1] if blocks else md_text


def tokenize(content: str, segmentation: str = "legacy") -> list[Atom]:
    """Split instruction file content into classified atoms.

    Uses markdown-it-py AST for structure (headings, lists, blockquotes,
    bold/italic/code spans) and rule-based charge classification.

    `segmentation` selects the post-parse boundary policy: `legacy` keeps each
    paragraph line and list item whole; `structure-aware` routes by format — prose
    splits into whole sentences, list/numbered items stay whole.
    """
    tokens, line_offset = parse_blocks(content)

    atoms: list[Atom] = []
    pos_idx = 0
    current_heading = ""
    block_stack: list[str] = []

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        _update_block_stack(tok, block_stack)

        if tok.type == "fence":
            pos_idx = _process_fence(tok, line_offset, pos_idx, current_heading, atoms)
            i += 1
            continue

        if tok.type == "code_block":
            # An indented (4-space/tab) code block — markdown-it's non-fenced code
            # token. It carries no language tag and no directive cascade; it stays a
            # single neutral block exactly like an untagged fence that reads as code.
            atoms.append(_make_fence_atom(tok, line_offset))
            i += 1
            continue

        if tok.type == "hr":
            i += 1
            continue

        if tok.type == "heading_open":
            atom, current_heading = _make_heading_atom(tok, tokens, i, line_offset)
            atoms.append(atom)
            i += 3
            continue

        if tok.type == "tr_open":
            row_atom, next_i = _make_table_row_atom(
                tok,
                tokens,
                i,
                line_offset,
                pos_idx=pos_idx,
                current_heading=current_heading,
            )
            if row_atom is not None:
                atoms.append(row_atom)
                pos_idx += 1
            i = next_i
            continue

        if tok.type == "inline" and tok.children:
            pos_idx = _process_inline_segments(
                tok,
                line_offset,
                block_stack,
                pos_idx=pos_idx,
                current_heading=current_heading,
                atoms=atoms,
                block_follows=_block_follows_paragraph(tokens, i),
            )

        i += 1

    atoms = _drop_contentless_atoms(atoms)

    if segmentation == SEGMENTATION_STRUCTURE_AWARE:
        atoms = _segment_structure_aware(atoms)

    _scan_neutral_for_embedded_markers(atoms)
    _scan_charged_for_compound_markers(atoms)

    return atoms


def _build_scope_mask(text: str) -> list[bool]:
    """Build a per-character mask: True where the character is inside quotes or parens.

    Tracks: "..." (straight quotes toggle), \u201c...\u201d (curly), (...).
    Backtick spans are not tracked here — they're handled by inline_tokens.
    """
    mask = [False] * len(text)
    in_straight_quote = False
    in_curly_quote = False
    paren_depth = 0
    for i, ch in enumerate(text):
        if ch == '"':
            if in_straight_quote:
                # Closing — mark this char as inside, then exit
                mask[i] = True
                in_straight_quote = False
                continue
            in_straight_quote = True
        elif ch == "\u201c":
            in_curly_quote = True
        elif ch == "\u201d" and in_curly_quote:
            mask[i] = True
            in_curly_quote = False
            continue
        elif ch == "(" and not in_straight_quote and not in_curly_quote:
            paren_depth += 1
        elif ch == ")" and paren_depth > 0:
            mask[i] = True
            paren_depth -= 1
            continue
        if in_straight_quote or in_curly_quote or paren_depth > 0:
            mask[i] = True
    return mask


def build_split_atom(clause: str, parent: Atom, *, plain_sent: str) -> Atom:
    """Build a sub-atom from one clause of an over-merged parent atom.

    Re-classifies the clause's charge independently — one charge per topic, and
    a clause is a fine-grained enough unit for that — and carries the parent's
    file/format/heading context. The resulting sub-atoms are emitted as
    separate atoms; this function does not decide how they relate to one
    another.
    """
    plain = re.sub(r"[*_]+", "", replace_code_spans(clause, "x")).strip()
    atom = _atom_from_sentence(clause, parent, _classify_content(clause, plain, parent.format), plain_sent=plain_sent)
    atom.file_path = parent.file_path
    return atom


def _split_prose_atom(atom: Atom) -> list[Atom]:
    """Split one prose atom into whole-sentence sub-atoms; re-classify each.

    Returns the original atom unchanged when it holds a single sentence, so a
    one-sentence prose run is never rebuilt. Each sentence is charge-classified
    independently and carries the parent's file/format/heading context.
    """
    sentences = split_prose_sentences(atom.text, atom.named_tokens)
    if len(sentences) < 2:
        return [atom]
    # Split the AST-clean text in step so each sentence keeps a plain form the
    # markdown never touched. Counts agree on this corpus; a divergence falls
    # back to the per-sentence strip rather than pairing the wrong halves.
    plains = split_prose_sentences(atom.plain_text, atom.named_tokens) if atom.plain_text else []
    if len(plains) != len(sentences):
        plains = [inline_plain_text(sent) for sent in sentences]
    subs: list[Atom] = []
    for idx, sent in enumerate(sentences):
        plain = re.sub(r"[*_]+", "", replace_code_spans(sent, "x")).strip()
        verdict = _classify_content(sent, plain, atom.format)
        sub = _atom_from_sentence(sent, atom, verdict, plain_sent=plains[idx])
        sub.file_path = atom.file_path
        subs.append(sub)
    keep_lead_in_on_last(subs)
    return subs


def _segment_structure_aware(atoms: list[Atom]) -> list[Atom]:
    """Format-aware segmentation — the structure-aware alternative to the split.

    Reads each atom's `format` (never overwriting it) and routes by structural
    unit: prose and table rows split into whole sentences (rule-based, no
    clause/comma/colon fragments); list/numbered/code/blockquote items and
    headings stay whole, as does a line that is wholly a quotation. Positions
    are re-indexed in document order (:func:`reindex_positions`).

    A table row runs the ordinary sentence rule over its joined cells, so two
    sentences in one row become two units while one sentence spanning three
    cells stays one — the cell edge is a delimiter, never a boundary.

    A bare negative deontic heading imposes a one-way prohibition floor on its
    section's list items — but that is a CHARGE-level effect applied after the
    head runs (see `_apply_deontic_floor`, called during span decoding), so
    segmentation only carries the `heading_context` the floor later reads.
    """
    result: list[Atom] = []
    for atom in atoms:
        if (
            atom.kind != "heading"
            and atom.format in SENTENCE_SPLIT_FORMATS
            and atom.rule != TABLE_HEADER_RULE
            and not is_quoted_line(atom.text)
        ):
            result.extend(_split_prose_atom(atom))
        else:
            result.append(atom)

    reindex_positions(result)
    return result
