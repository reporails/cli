# ruff: noqa: SIM102, N806, PERF401, RUF034
"""Stages 1 + 2 — markdown-it AST walk + per-atom text extraction.

Stage 1 parses the markdown source into an AST and walks it, tracking block
nesting (lists, blockquotes, tables, code fences) to populate each atom's
`format` and `position_index`. Stage 2 extracts two parallel text streams from
each inline segment: `md_text` (formatting markers preserved, fed to annotate)
and `plain_text` (markers stripped, fed to classify and embed). The walker
also runs post-classify hooks — mixed-charge splitting, confidence scoring,
neutral-atom scanning — so the returned atom list is ready for clustering.

Public entry point: `tokenize(content)`.

Imports `classify_charge` + `_ALL_VERBS` + `_strip_md_for_classify` from classify
(Stage 3) and `check_specificity` + `_BACKTICK_RE` from annotate (Stage 4) so
tokenize can produce fully-classified atoms in a single pass.
"""

from __future__ import annotations

import re
from typing import Any

from markdown_it import MarkdownIt

from reporails_cli.core.mapper.annotate import _BACKTICK_RE, check_specificity
from reporails_cli.core.mapper.classify import _ALL_VERBS, classify_charge
from reporails_cli.core.platform.dto.ruleset import Atom, InlineToken

# ──────────────────────────────────────────────────────────────────
# TOKENIZER (markdown-it AST)
# ──────────────────────────────────────────────────────────────────

_md_parser = MarkdownIt().enable("table")

_QUOTED_START_RE = re.compile(r'^["\u201c\u201e]')
_DEFN_LABEL_RE = re.compile(r"^\*{2}\S+\*{2}\s*[:\u2014\u2013(/-]\s?")

_BOLD_LABEL_RE = re.compile(
    r"^\*{2}[^*]{1,60}\*{2}\s*[:\u2014\u2013/-]\s*\S",
)
_INSTRUCTION_WORDS_RE = re.compile(
    r"\b(never|always|must|shall|do not|don't|no |only|NEVER|NO |MUST|ALWAYS|avoid"
    r"|ensure|require|use |prefer |forbidden|prohibited"
    # Imperative verbs — bold labels starting with these are instructions
    r"|read |check |run |add |verify |follow |create |update |write "
    r"|find |set |install |identify |build |keep |include"
    r"|configure |validate |define |generate |execute |review "
    r"|apply |load |locate |deploy |export |import |remove |test )\b",
    re.IGNORECASE,
)

_THIRD_PERSON_RE = re.compile(
    r"^(Triggers|Sends|Supports|Handles|Manages|Contains"
    r"|Provides|Returns|Creates|Runs|Fetches|Stores"
    r"|Processes|Generates|Validates|Implements"
    r"|Connects|Accepts|Includes|Maintains"
    r"|Represents|Defines|Operates|Applies"
    r"|Describes|Specifies|Determines|Requires)\s",
)

_CMD_REF_RE = re.compile(r"^`[^`]+`\s*[-\u2013\u2014:]\s+")
_VERSION_NOTE_RE = re.compile(r"^[`><=~!]\s*[\d.]")
_LABEL_ONLY_RE = re.compile(r"^[A-Z][a-z\s]{0,30}:\s*$")
_PIPE_REF_RE = re.compile(r"^`[^`]+`\s*\|")
_FILE_LISTING_RE = re.compile(r"^\*{2}[a-zA-Z_./]+\.\w+\*{2}\s*[-\u2013\u2014:]")
_CLAUSE_SPLIT_RE = re.compile(r"\s[\u2014\u2013]\s|:\s*[\"'\u201c]")


def _strip_frontmatter(content: str) -> tuple[str, int]:
    """Strip YAML frontmatter. Returns (stripped_content, lines_removed)."""
    if not content.startswith("---"):
        return content, 0
    end = content.find("\n---", 3)
    if end == -1:
        return content, 0
    # Count lines in frontmatter including both --- delimiters
    fm = content[: end + 4]
    offset = fm.count("\n") + (0 if fm.endswith("\n") else 0)
    rest = content[end + 4 :]
    if rest.startswith("\n"):
        rest = rest[1:]
        offset += 1
    return rest, offset


def _split_at_softbreaks(children: list[Any]) -> list[list[Any]]:
    """Split inline children into per-line segments at softbreak boundaries."""
    segments: list[list[Any]] = [[]]
    for child in children:
        if child.type == "softbreak":
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


# Maps markdown-it open/close tokens to their markdown marker and stack format.
_FORMAT_OPEN = {"strong_open": ("**", "bold"), "em_open": ("*", "italic")}
_FORMAT_CLOSE = {"strong_close": "**", "em_close": "*"}


def _extract_texts(
    segment: list[Any],
) -> tuple[str, str, list[InlineToken]]:
    """Extract md_text, plain_text, and inline_tokens from AST children.

    md_text preserves `backtick`, **bold**, *italic* markers for check_specificity().
    plain_text strips all markers for 3rd-person detection.
    inline_tokens provides per-word format context for Phase 3 backtick filter.
    """
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
        elif child.type in _FORMAT_OPEN:
            marker, fmt = _FORMAT_OPEN[child.type]
            md_parts.append(marker)
            format_stack.append(fmt)
        elif child.type in _FORMAT_CLOSE:
            md_parts.append(_FORMAT_CLOSE[child.type])
            if len(format_stack) > 1:
                format_stack.pop()
        # link_open, link_close: skip — text child handles content

    md_text = "".join(md_parts).strip()
    plain_text = "".join(plain_parts).strip()
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


def _is_structural(md_text: str) -> bool:
    """Check if text is structural meta-text that should be forced NEUTRAL.

    Only catches genuinely non-instructive CONTENT patterns — reference
    tables, file listings, version notes. Formatting (bold labels, italic
    emphasis) does NOT override charge — formatting is handled separately,
    not in charge classification.
    """
    # Single-word bold definitions: **Term**: description
    # But not if the term is a verb — that's an instruction label
    is_defn = bool(_DEFN_LABEL_RE.match(md_text))
    if is_defn:
        m = re.match(r"^\*{2}(\S+)\*{2}", md_text)
        if m and m.group(1).lower() in _ALL_VERBS:
            is_defn = False

    return bool(
        _QUOTED_START_RE.match(md_text)
        or is_defn
        or _CMD_REF_RE.match(md_text)
        or _VERSION_NOTE_RE.match(md_text)
        or _LABEL_ONLY_RE.match(md_text)
        or _PIPE_REF_RE.match(md_text)
        or _FILE_LISTING_RE.match(md_text)
    )


def _classify_content(
    md_text: str,
    plain_text: str,
    fmt: str,
    *,
    inline_tokens: list[InlineToken] | None = None,
) -> tuple[str, int, str, str, bool]:
    """Classify an atom's charge and modality.

    Uses md_text for structural detection and rule-based classification.
    Uses plain_text for 3rd-person description detection.
    Returns: (charge, charge_value, modality, rule_trace, scope_conditional)
    """
    if fmt == "table" or _is_structural(md_text):
        return "NEUTRAL", 0, "none", "structural", False

    # 3rd-person descriptions on plain text (no markers to confuse)
    if _THIRD_PERSON_RE.match(plain_text):
        return "NEUTRAL", 0, "none", "third_person", False

    return classify_charge(md_text, plain_text=plain_text, inline_tokens=inline_tokens)


def _make_fence_atom(tok: Any) -> Atom:
    """Create a code block atom from a fence token."""
    lang = (tok.info or "").strip().lower()
    return Atom(
        line=tok.map[0] + 1 if tok.map else 0,
        text=tok.content[:200],
        kind="excitation",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity="named" if lang else "abstract",
        format="code_block",
        named_tokens=[lang] if lang else [],
        file_path="",
        plain_text=f"code_block:{lang}" if lang else "code_block",
    )


def _specificity_fields(text: str) -> dict[str, Any]:
    """Build specificity-related Atom fields from text."""
    spec, named, unformatted, italic, bold = check_specificity(text)
    return {
        "specificity": spec,
        "named_tokens": named,
        "unformatted_code": unformatted,
        "italic_tokens": italic,
        "bold_tokens": bold,
        "token_count": len(_BACKTICK_RE.sub("x", text).split()),
    }


def _tok_line(tok: Any, line_offset: int) -> int:
    """Extract line number from a markdown-it token."""
    return (tok.map[0] if tok.map else 0) + line_offset + 1


def _make_heading_atom(
    tok: Any,
    tokens: list[Any],
    i: int,
    line_offset: int,
) -> tuple[Atom, str]:
    """Create a heading atom and return (atom, heading_text)."""
    heading_text = tokens[i + 1].content if i + 1 < len(tokens) and tokens[i + 1].type == "inline" else ""
    charge, cv, mod, rule, sc = classify_charge(heading_text)
    sf = _specificity_fields(heading_text)
    atom = Atom(
        line=_tok_line(tok, line_offset),
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


def _collect_table_cells(tokens: list[Any], start: int) -> tuple[str, int]:
    """Collect table cells from tr_open to tr_close. Returns (cell_text, next_index)."""
    cells: list[str] = []
    j = start + 1
    while j < len(tokens) and tokens[j].type != "tr_close":
        if tokens[j].type == "inline":
            cells.append(tokens[j].content.strip())
        j += 1
    return " | ".join(cells), j + 1


def _make_table_row_atom(
    tok: Any,
    tokens: list[Any],
    i: int,
    line_offset: int,
    pos_idx: int,
    current_heading: str,
) -> tuple[Atom | None, int]:
    """Create a table row atom. Returns (atom_or_None, next_token_index)."""
    cell_text, next_i = _collect_table_cells(tokens, i)
    if len(cell_text) < 5:
        return None, next_i
    sf = _specificity_fields(cell_text)
    atom = Atom(
        line=_tok_line(tok, line_offset),
        text=cell_text,
        kind="excitation",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity=sf["specificity"],
        format="table",
        named_tokens=sf["named_tokens"],
        italic_tokens=sf["italic_tokens"],
        bold_tokens=sf["bold_tokens"],
        unformatted_code=sf["unformatted_code"],
        position_index=pos_idx,
        token_count=sf["token_count"],
        heading_context=current_heading,
    )
    return atom, next_i


def _make_inline_atom(
    md_text: str,
    plain_text: str,
    fmt: str,
    base_line: int,
    seg_idx: int,
    pos_idx: int,
    current_heading: str,
    inline_tokens: list[InlineToken],
) -> Atom:
    """Create an inline content atom with charge classification."""
    charge, cv, mod, rule_trace, scope_cond = _classify_content(
        md_text,
        plain_text,
        fmt,
        inline_tokens=inline_tokens,
    )
    sf = _specificity_fields(md_text)
    return Atom(
        line=base_line + seg_idx,
        text=md_text,
        kind="excitation",
        charge=charge,
        charge_value=cv,
        modality=mod,
        scope_conditional=scope_cond,
        specificity=sf["specificity"],
        format=fmt,
        named_tokens=sf["named_tokens"],
        italic_tokens=sf["italic_tokens"],
        bold_tokens=sf["bold_tokens"],
        unformatted_code=sf["unformatted_code"],
        position_index=pos_idx,
        token_count=sf["token_count"],
        heading_context=current_heading,
        plain_text=plain_text,
        rule=rule_trace,
        ambiguous=rule_trace.endswith("!amb"),
    )


# Map block types from markdown-it token types
_BLOCK_TYPES = {
    "bullet_list_open": "bullet_list",
    "ordered_list_open": "ordered_list",
    "blockquote_open": "blockquote",
    "table_open": "table",
}
_BLOCK_CLOSE = {
    "bullet_list_close",
    "ordered_list_close",
    "blockquote_close",
    "table_close",
}


def _process_inline_segments(
    tok: Any,
    line_offset: int,
    block_stack: list[str],
    pos_idx: int,
    current_heading: str,
    atoms: list[Atom],
) -> int:
    """Process inline token segments, appending atoms. Returns updated pos_idx."""
    base_line = _tok_line(tok, line_offset)
    fmt = _determine_format(block_stack)
    if fmt == "table":
        return pos_idx
    for seg_idx, segment in enumerate(_split_at_softbreaks(tok.children)):
        md_text, plain_text, inline_toks = _extract_texts(segment)
        if len(md_text) >= 5:
            atoms.append(
                _make_inline_atom(
                    md_text,
                    plain_text,
                    fmt,
                    base_line,
                    seg_idx,
                    pos_idx,
                    current_heading,
                    inline_toks,
                )
            )
            pos_idx += 1
    return pos_idx


def tokenize(content: str) -> list[Atom]:
    """Split instruction file content into classified atoms.

    Uses markdown-it-py AST for structure (headings, lists, blockquotes,
    bold/italic/code spans) and rule-based charge classification.
    """
    stripped_content, line_offset = _strip_frontmatter(content)
    tokens = _md_parser.parse(stripped_content)

    atoms: list[Atom] = []
    pos_idx = 0
    current_heading = ""
    block_stack: list[str] = []

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        # Track block nesting
        if tok.type in _BLOCK_TYPES:
            block_stack.append(_BLOCK_TYPES[tok.type])
        elif tok.type in _BLOCK_CLOSE:
            if block_stack:
                block_stack.pop()

        if tok.type == "fence":
            atoms.append(_make_fence_atom(tok))
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
                pos_idx,
                current_heading,
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
                pos_idx,
                current_heading,
                atoms,
            )

        i += 1

    atoms = _split_mixed_charge_atoms(atoms)

    for atom in atoms:
        atom.charge_confidence = _rule_confidence(atom.rule, atom.charge)

    _scan_neutral_for_embedded_markers(atoms)
    _scan_charged_for_compound_markers(atoms)

    return atoms


# Sentence boundary: period/exclamation/question followed by whitespace
# and then uppercase letter or markdown emphasis (*bold*, **italic**).
# Excludes common abbreviations (e.g., i.e., etc., vs.).
_SENTENCE_SPLIT_RE = re.compile(
    r"(?<!\be\.g)(?<!\bi\.e)(?<!\betc)(?<!\bvs)"
    r"[.!?]\s+(?=[A-Z*])"
)


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
            else:
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


def _split_sentences(text: str) -> list[str] | None:
    """Split text at sentence and em-dash boundaries outside quoted scope.

    Boundaries inside "..." or (...) are skipped — those are inline
    examples, not real instruction boundaries.
    Returns None if fewer than 2 sentences.
    """
    candidates = list(_SENTENCE_SPLIT_RE.finditer(text))
    if not candidates:
        return None

    scope_mask = _build_scope_mask(text)
    # Keep only boundaries that fall outside quotes/parens
    splits = [m for m in candidates if not scope_mask[m.start()]]
    if not splits:
        return None

    boundaries = [0] + [m.end() for m in splits] + [len(text)]
    sentences = [text[boundaries[i] : boundaries[i + 1]].strip() for i in range(len(boundaries) - 1)]
    sentences = [s for s in sentences if len(s) >= 5]
    return sentences if len(sentences) >= 2 else None


def _atom_from_sentence(
    sent: str,
    atom: Atom,
    charge: str,
    cv: int,
    mod: str,
    rule: str,
    scope: bool,
) -> Atom:
    """Create an atom from a sub-sentence of a split atom."""
    spec, named, unformatted, italic, bold = check_specificity(sent)
    return Atom(
        line=atom.line,
        text=sent,
        kind="excitation",
        charge=charge,
        charge_value=cv,
        modality=mod,
        scope_conditional=scope,
        specificity=spec,
        format=atom.format,
        named_tokens=named,
        italic_tokens=italic,
        bold_tokens=bold,
        unformatted_code=unformatted,
        position_index=atom.position_index,
        token_count=len(_BACKTICK_RE.sub("x", sent).split()),
        heading_context=atom.heading_context,
        plain_text=re.sub(r"[*_`]+", "", sent).strip(),
        rule=rule,
        ambiguous=rule.endswith("!amb"),
    )


def _split_mixed_charge_atoms(atoms: list[Atom]) -> list[Atom]:
    """Split multi-sentence atoms when sub-sentences carry different charges.

    Handles two cases:
    1. Charged atom with charge flip: "Do not output cheerleading. Go straight
       to content." -> CONSTRAINT + IMPERATIVE.
    2. Neutral atom with embedded charge: "You are the reviewer. Never burden
       the user." -> NEUTRAL + CONSTRAINT.

    Without case 2, compound sentences classified by their first clause lose
    charged sub-sentences entirely (5.8% false-negative rate in audit).

    Only splits when: (1) atom has 2+ sentences, (2) at least one sub-sentence
    has a different charge than the atom's current classification.
    """
    result: list[Atom] = []
    for atom in atoms:
        if atom.kind == "heading":
            result.append(atom)
            continue

        sentences = _split_sentences(atom.text)
        if sentences is None:
            result.append(atom)
            continue

        # Classify each sentence independently
        classified = []
        for sent in sentences:
            plain = re.sub(r"[*_]+", "", _BACKTICK_RE.sub("x", sent)).strip()
            charge, cv, mod, rule, scope = _classify_content(sent, plain, atom.format)
            classified.append((sent, charge, cv, mod, rule, scope))

        # Only split if charges actually differ
        if len({cv for _, _, cv, _, _, _ in classified}) < 2:
            result.append(atom)
            continue

        for sent, charge, cv, mod, rule, scope in classified:
            result.append(_atom_from_sentence(sent, atom, charge, cv, mod, rule, scope))

    # Re-index positions
    pos_idx = 0
    for a in result:
        if a.kind != "heading":
            a.position_index = pos_idx
            pos_idx += 1

    return result


# ──────────────────────────────────────────────────────────────────
# CONFIDENCE SCORING
# ──────────────────────────────────────────────────────────────────

# Rule traces grouped by reliability. High-precision rules produce
# confident classifications. Ambiguous rules (verb-noun, rescue paths)
# produce lower confidence.
_HIGH_CONFIDENCE_RULES = frozenset(
    {
        "p1_negation_phrase",
        "p1_prohibition_start",
        "p1_caps_negation",
        "p1_mid_negation",
        "p1_late_donot",
        "p2_modal_must",
        "p2_modal_shall",
        "p2_you_will",
        "p2_you_will_not",
        "p2_modal_negated",
        "p2_adverb_always",
        "p2_adverb_every",
        "p2_adverb_only",
        "p3_spacy_vb",
        "p3_spacy_vbp_det",
        "p3_spacy_nn_verb0",
    }
)

_MEDIUM_CONFIDENCE_RULES = frozenset(
    {
        "p2_hedged_should",
        "p2_hedged_could",
        "p2_hedged_might",
        "p2_hedged_should_negated",
        "p3_spacy_verb0_rescue",
        "p3_spacy_nn_verb0_rescue",
        "p3_spacy_vb_advcl_rescue",
        "p3_spacy_nn_postcolon_verb",
        "p3b_bold_label",
        "p3c_verb0_use",
        "p3c_verb0_run",
        "p3c_verb0_add",
        "p3d_context_use",
        "p3d_context_run",
        "p3e_break_use",
        "p3e_break_run",
    }
)


def _rule_confidence(rule: str, charge: str) -> float:
    """Assign confidence score based on which classification rule fired."""
    if charge == "NEUTRAL":
        # Neutral from explicit rules: high confidence.
        # Fallthrough neutrals: slightly lower (nothing matched).
        return 0.85 if rule == "fallthrough" else 0.95

    if rule in _HIGH_CONFIDENCE_RULES:
        return 0.95
    if rule in _MEDIUM_CONFIDENCE_RULES:
        return 0.80
    if rule.endswith("!amb"):
        return 0.60
    if "cond" in rule or "3f_" in rule or "3g_" in rule:
        return 0.70
    return 0.75


# ──────────────────────────────────────────────────────────────────
# NEUTRAL ATOM SCANNER — detect embedded charge markers
# ──────────────────────────────────────────────────────────────────

# Patterns that indicate charge language in text classified as neutral.
# These are the "prohibited words" — if they appear in neutral atoms,
# the atom is flagged for review.
_EMBEDDED_CONSTRAINT_RE = re.compile(
    r"\b("
    r"never|don'?t|do\s+not|must\s+not|should\s+not|cannot|can'?t"
    r"|avoid\b|refrain|prohibit"
    r")\b",
    re.IGNORECASE,
)
_EMBEDDED_DIRECTIVE_RE = re.compile(
    r"\b("
    r"must|shall|always|ensure that|require that"
    r")\b",
    re.IGNORECASE,
)
_EMBEDDED_IMPERATIVE_RE = re.compile(
    r"(?:^|[.!?]\s+)("
    # Only non-ambiguous verbs — words that are almost always imperative
    # at sentence start. Excludes verb-noun words (test, build, set, check,
    # run, read, trace, etc.) that produce false positives on descriptions.
    r"use|add|create|install|configure|make"
    r"|update|follow|keep|write|verify|ensure"
    r"|remove|delete|include|exclude|specify|define|implement"
    r")\b",
    re.IGNORECASE,
)


def _scan_neutral_for_embedded_markers(atoms: list[Atom]) -> None:
    """Scan neutral atoms for embedded charge markers.

    Reclassifies to AMBIGUOUS when charge language appears in text that
    the classifier couldn't resolve. AMBIGUOUS atoms are excluded from
    diagnostics until the user rephrases them. The map records what
    markers were found so diagnostics can suggest specific fixes.

    This enforces Path A: unambiguous instruction language is required
    for accurate analysis. The tool refuses to score what it can't classify.
    """
    # Rules that produce correct neutralizations — don't second-guess these.
    # Backtick filter: ROOT verb inside code markup (not an instruction).
    # Third person: "The system processes..." (description, not instruction).
    # Structural: tables, file listings, pipe references.
    _TRUSTED_NEUTRAL_RULES = frozenset(
        {
            "third_person",
            "short_text",
            "no_words",
        }
    )

    for atom in atoms:
        if atom.charge != "NEUTRAL" or atom.kind == "heading":
            continue
        if atom.rule in _TRUSTED_NEUTRAL_RULES:
            continue
        text = atom.text
        markers: list[str] = []
        for m in _EMBEDDED_CONSTRAINT_RE.finditer(text):
            markers.append(f"constraint:{m.group().strip()}")
        for m in _EMBEDDED_DIRECTIVE_RE.finditer(text):
            markers.append(f"directive:{m.group().strip()}")
        for m in _EMBEDDED_IMPERATIVE_RE.finditer(text):
            markers.append(f"imperative:{m.group(1).strip()}")
        if markers:
            atom.embedded_charge_markers = markers
            atom.charge = "AMBIGUOUS"
            atom.charge_confidence = 0.0


def _scan_charged_for_compound_markers(atoms: list[Atom]) -> None:
    """Detect opposite-direction markers in charged atoms.

    A directive like "mention it — don't delete it" contains both a
    directive verb and a constraint negation.  The classifier picks one
    charge; this scanner records the opposite-direction signal so the
    equation can skip false-positive conflict detection between the
    compound instruction and an aligned constraint.

    Does NOT change the atom's charge.
    """
    for atom in atoms:
        if atom.charge_value == 0 or atom.kind == "heading":
            continue
        text = atom.text
        opposite: list[str] = []
        if atom.charge_value == 1:
            for m in _EMBEDDED_CONSTRAINT_RE.finditer(text):
                opposite.append(f"constraint:{m.group().strip()}")
        else:
            for m in _EMBEDDED_DIRECTIVE_RE.finditer(text):
                opposite.append(f"directive:{m.group().strip()}")
            for m in _EMBEDDED_IMPERATIVE_RE.finditer(text):
                opposite.append(f"imperative:{m.group(1).strip()}")
        if opposite:
            atom.embedded_charge_markers = opposite
