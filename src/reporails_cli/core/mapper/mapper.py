# pylint: disable=C0302
# ruff: noqa: C901, SIM102, N806, PERF401, RUF034
"""Mapper — client-side spectrograph for instruction file analysis.

Classifies instruction files into atoms, embeds them, clusters by topic,
and produces a compact RulesetMap. This module is the client-side component
of the reporails architecture — classification, embedding, and clustering.

The RulesetMap is the wire format: ~32KB covering an entire instruction
ruleset, suitable for transmission to the diagnostic API.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from markdown_it import MarkdownIt

from reporails_cli.core.mapper.annotate import (
    _BACKTICK_RE,
    check_specificity,
)
from reporails_cli.core.mapper.classify import (
    _ALL_VERBS,
    _strip_md_for_classify,
    classify_charge,
)
from reporails_cli.core.mapper.imports import expand_imports
from reporails_cli.core.mapper.models import Models, get_models
from reporails_cli.core.platform.dto.ruleset import (
    EMBEDDING_MODEL,
    SCHEMA_VERSION,
    Atom,
    ClusterRecord,
    FileRecord,
    InlineToken,
    RulesetMap,
    RulesetSummary,
    TopicCluster,
)

if TYPE_CHECKING:
    pass  # sentence_transformers types if needed

logger = logging.getLogger(__name__)

# Topic clustering threshold (L2 distance on L2-normalized embeddings).
TOPIC_CLUSTER_THRESHOLD = 1.2


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


def _embed_text(atom: Atom) -> str:
    """Build embedding text for an atom.

    Uses plain_text (AST-stripped) for cleaner embeddings — formatting markers
    (**bold**, *italic*, `backtick`) add noise without semantic content.
    Heading context is NOT prepended — headings are their own atoms.
    Prepending created double-counting and artificial clustering by
    heading rather than by semantic content.
    """
    return atom.plain_text or atom.text


# ──────────────────────────────────────────────────────────────────
# TOPIC CLUSTERING
# ──────────────────────────────────────────────────────────────────


def _compute_centroid(embeddings_norm: Any, member_indices: list[int]) -> tuple[float, ...]:
    """Compute L2-normalized centroid from member vectors."""
    import numpy as np

    member_vecs = embeddings_norm[member_indices]
    mean_vec = member_vecs.mean(axis=0)
    norm = float(np.linalg.norm(mean_vec))
    if norm > 1e-12:
        mean_vec = mean_vec / norm
    return tuple(float(x) for x in mean_vec.tolist())


def _build_topic_clusters(
    clusters: dict[int, list[Atom]],
    indices: dict[int, list[int]],
    embeddings_norm: Any,
) -> list[TopicCluster]:
    """Build TopicCluster list from cluster assignments and normalized embeddings."""
    result: list[TopicCluster] = []
    for tid in sorted(clusters):
        cluster_atoms = clusters[tid]
        charged = [a for a in cluster_atoms if a.charge_value != 0]
        n_total = len(cluster_atoms)
        j = len(charged) / n_total if n_total else 0.0
        centroid = _compute_centroid(embeddings_norm, indices[tid])
        result.append(TopicCluster(topic_id=tid, atoms=cluster_atoms, charged=charged, j=j, centroid=centroid))
    return result


def _run_agglomerative_clustering(
    embedded: list[Atom],
) -> tuple[Any, Any]:
    """Run AgglomerativeClustering on embedded atoms. Returns (embeddings_norm, labels)."""
    import numpy as np
    from sklearn.cluster import AgglomerativeClustering
    from sklearn.preprocessing import normalize

    vecs = np.array(
        [list(a.embedding_int8) for a in embedded if a.embedding_int8 is not None],
        dtype=np.float32,
    )
    embeddings_norm = normalize(vecs, norm="l2")
    clustering = AgglomerativeClustering(
        n_clusters=None,
        distance_threshold=TOPIC_CLUSTER_THRESHOLD,
        metric="euclidean",
        linkage="average",
    )
    return embeddings_norm, clustering.fit_predict(embeddings_norm)


def cluster_topics(
    atoms: list[Atom],
) -> list[TopicCluster]:
    """Cluster atoms into topic groups using pre-computed embeddings.

    Uses AgglomerativeClustering with distance_threshold on the already-embedded
    int8 vectors from map_ruleset(). Does NOT re-encode — uses embedding_int8
    directly, dequantized to float32 for clustering.

    Falls back to single cluster when embeddings are missing.
    """
    exc = [a for a in atoms if a.kind != "heading"]
    if not exc:
        return []

    embedded = [a for a in exc if a.embedding_int8 is not None]
    if len(embedded) < 2:
        charged = [a for a in exc if a.charge_value != 0]
        j = len(charged) / len(exc) if exc else 0.0
        for a in exc:
            a.cluster_id = 0
        return [TopicCluster(topic_id=0, atoms=exc, charged=charged, j=j)]

    embeddings_norm, labels = _run_agglomerative_clustering(embedded)

    clusters: dict[int, list[Atom]] = {}
    indices: dict[int, list[int]] = {}
    for i, (atom, label) in enumerate(zip(embedded, labels, strict=True)):
        lbl = int(label)
        atom.cluster_id = lbl
        clusters.setdefault(lbl, []).append(atom)
        indices.setdefault(lbl, []).append(i)

    for a in exc:
        if a.embedding_int8 is None:
            a.cluster_id = -1

    return _build_topic_clusters(clusters, indices, embeddings_norm)


# ──────────────────────────────────────────────────────────────────
# RULESET MAP CONSTRUCTION
# ──────────────────────────────────────────────────────────────────


def _quantize_int8(vec: Any) -> tuple[int, ...]:
    """Quantize a float32 embedding vector to int8 (-128..127).

    Preserves cosine similarity with < 1% error for all-MiniLM-L6-v2 vectors.
    """
    import numpy as np

    arr = np.asarray(vec, dtype=np.float32)
    # Scale to [-127, 127] range based on max absolute value
    scale = max(float(np.abs(arr).max()), 1e-10)
    quantized = np.clip(np.round(arr * 127.0 / scale), -128, 127).astype(np.int8)
    return tuple(int(v) for v in quantized)


def content_hash(text: str) -> str:
    """Compute SHA-256 hash of text with sha256: prefix."""
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return f"sha256:{h}"


def map_file(path: Path) -> tuple[list[Atom], str]:
    """Classify a single instruction file into atoms.

    Returns:
        (atoms, content_hash)
    """
    content = path.read_text(encoding="utf-8", errors="replace")
    atoms = tokenize(content)
    for a in atoms:
        a.file_path = str(path)
    return atoms, content_hash(content)


def _extract_frontmatter_yaml(path: Path) -> str:
    """Read a file and return the raw YAML frontmatter block, or empty string."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    return text[3:end] if end != -1 else ""


def _parse_frontmatter_description(path: Path) -> str:
    """Extract name + description from YAML frontmatter.

    These fields are surfaced into the model's base context by all agents
    (Agent Skills standard) for skill/agent discoverability. The combined
    string is what competes for attention even when the file isn't invoked.
    """
    raw = _extract_frontmatter_yaml(path)
    if not raw:
        return ""
    try:
        import yaml

        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            return ""
        name = str(data.get("name", ""))
        desc = str(data.get("description", ""))
        return f"{name}: {desc}" if name and desc else (name or desc)
    except Exception:  # yaml.YAMLError; yaml imported in try scope
        return ""


def _parse_frontmatter_globs(path: Path) -> tuple[str, ...]:
    """Extract globs from YAML frontmatter of a rule/skill file."""
    raw = _extract_frontmatter_yaml(path)
    if not raw:
        return ()
    try:
        import yaml

        data = yaml.safe_load(raw)
        if not isinstance(data, dict) or "globs" not in data:
            return ()
        globs = data["globs"]
        if isinstance(globs, list):
            return tuple(str(g) for g in globs)
        if isinstance(globs, str):
            return (globs,)
    except Exception:  # yaml.YAMLError; yaml imported in try scope
        pass
    return ()


def _load_registry() -> dict[str, dict[str, Any]]:
    """Load all agent registry configs. Returns {agent: config_dict}."""
    try:
        from reporails_cli.core.platform.config.bootstrap import get_rules_path

        registry_dir = get_rules_path()
    except ImportError:
        registry_dir = Path(__file__).parent.parent / "data" / "registry"
    configs: dict[str, dict[str, Any]] = {}
    if not registry_dir.is_dir():
        return configs
    try:
        import yaml
    except ImportError:
        return configs
    for config_path in sorted(registry_dir.glob("*/config.yml")):
        try:
            data = yaml.safe_load(config_path.read_text())
            agent = data.get("agent", config_path.parent.name)
            configs[agent] = data
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Failed to load agent config %s: %s", config_path, exc)
            continue
    return configs


def _find_best_registry_match(
    rel_lower: str,
    registry: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]] | None:
    """Find the most specific registry pattern match for a file path.

    Returns (agent_id, properties) or None if no match.
    """
    import fnmatch

    from reporails_cli.core.discovery.agents import _extract_patterns, _extract_properties

    best: tuple[int, str, dict[str, Any]] | None = None  # (specificity, agent, props)

    for agent_id, config in registry.items():
        for ft in (config.get("file_types") or {}).values():
            patterns = _extract_patterns(ft) if isinstance(ft, dict) else []
            props = ft.get("properties", {}) if isinstance(ft, dict) else {}
            if not props:
                props = _extract_properties(ft) if isinstance(ft, dict) else {}
            for pat in patterns:
                pat_lower = pat.lower()
                candidates = [pat_lower]
                if "**/" in pat_lower:
                    candidates.append(pat_lower.replace("**/", ""))
                    candidates.append(pat_lower.replace("**/", "*/"))
                if any(fnmatch.fnmatch(rel_lower, c) for c in candidates):
                    specificity = len(pat_lower.split("*")[0])
                    if best is None or specificity > best[0]:
                        best = (specificity, agent_id, props)

    if best is None:
        return None
    return best[1], best[2]


def _detect_file_loading(
    path: Path,
    root: Path,
    registry: dict[str, dict[str, Any]],
) -> tuple[str, str, tuple[str, ...], str]:
    """Determine loading/scope/globs/agent for an instruction file.

    Matches the file against all agent registry patterns.
    Falls back to session_start/global/generic if no match.

    Returns:
        (loading, scope, globs, agent)
    """
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    match = _find_best_registry_match(rel.lower(), registry)
    if match is None:
        return "session_start", "global", (), "generic"

    agent_id, props = match
    loading = props.get("loading", "session_start")
    scope = props.get("scope", "global")
    globs: tuple[str, ...] = ()
    if loading in ("on_demand", "on_invocation"):
        globs = _parse_frontmatter_globs(path)
    if loading == "on_demand" and not globs:
        loading = "session_start"
        scope = "global"
    return loading, scope, globs, agent_id


def _embed_atoms_deduped(atoms: list[Atom], encoder: Any) -> None:
    """Embed atoms with deduplication. Atoms with identical text share embeddings."""
    texts = [_embed_text(a) for a in atoms]
    unique_texts: list[str] = []
    text_index: dict[str, int] = {}
    atom_to_unique: list[int] = []
    for t in texts:
        idx = text_index.get(t)
        if idx is None:
            idx = len(unique_texts)
            text_index[t] = idx
            unique_texts.append(t)
        atom_to_unique.append(idx)
    unique_embeddings = encoder.encode(unique_texts)
    for atom, u_idx in zip(atoms, atom_to_unique, strict=True):
        atom.embedding_int8 = _quantize_int8(unique_embeddings[u_idx])


def _classify_file(
    path: Path,
    map_cache: Any,
    all_atoms: list[Atom],
    atoms_needing_embed: list[Atom],
) -> str:
    """Classify a single file: tokenize or use cache. Returns content hash."""
    from reporails_cli.core.cache.map_cache import (
        CachedFileEntry,
        atoms_to_dicts,
        dicts_to_atoms,
    )

    raw_content = path.read_text(encoding="utf-8", errors="replace")
    content = expand_imports(raw_content, path)
    chash = content_hash(content)

    cached = map_cache.get(chash) if map_cache else None
    if cached is not None:
        atoms = dicts_to_atoms(cached.atoms)
        for a in atoms:
            a.file_path = str(path)
        all_atoms.extend(atoms)
    else:
        atoms = tokenize(content)
        for a in atoms:
            a.file_path = str(path)
        all_atoms.extend(atoms)
        atoms_needing_embed.extend(atoms)
        if map_cache is not None:
            map_cache.put(chash, CachedFileEntry(chash, atoms_to_dicts(atoms)))

    return chash


def _update_cache_after_embedding(
    map_cache: Any,
    all_atoms: list[Atom],
    atoms_needing_embed: list[Atom],
    file_records: list[FileRecord],
) -> None:
    """Update cache entries with embeddings for newly-embedded atoms."""
    from reporails_cli.core.cache.map_cache import CachedFileEntry, atoms_to_dicts

    by_file: dict[str, list[Atom]] = {}
    for a in all_atoms:
        by_file.setdefault(a.file_path, []).append(a)
    embed_set = {id(a) for a in atoms_needing_embed}
    for frec in file_records:
        file_atoms = by_file.get(frec.path, [])
        if any(id(a) in embed_set for a in file_atoms):
            map_cache.put(frec.content_hash, CachedFileEntry(frec.content_hash, atoms_to_dicts(file_atoms)))


def _embed_file_descriptions(file_records: list[FileRecord], encoder: Any) -> None:
    """Embed frontmatter descriptions for on_invocation files."""
    desc_texts = [fr.description for fr in file_records if fr.description]
    if not desc_texts:
        return
    desc_embeddings = encoder.encode(desc_texts)
    desc_idx = 0
    for fr in file_records:
        if fr.description:
            fr.description_embedding = _quantize_int8(desc_embeddings[desc_idx])
            desc_idx += 1


def _build_ruleset_map(
    file_records: list[FileRecord],
    all_atoms: list[Atom],
    topics: list[TopicCluster],
) -> RulesetMap:
    """Assemble the final RulesetMap from classified and clustered data."""
    cluster_records = [
        ClusterRecord(
            id=tc.topic_id,
            n_atoms=len(tc.atoms),
            n_charged=len(tc.charged),
            n_neutral=len(tc.atoms) - len(tc.charged),
            centroid=tc.centroid,
        )
        for tc in topics
    ]

    n_charged = sum(1 for a in all_atoms if a.charge_value != 0)
    summary = RulesetSummary(
        n_atoms=len(all_atoms),
        n_charged=n_charged,
        n_neutral=len(all_atoms) - n_charged,
        n_topics=len(topics),
        n_topics_charged=sum(1 for tc in topics if tc.charged),
    )

    return RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at=datetime.now(UTC).isoformat(),
        files=tuple(file_records),
        atoms=tuple(all_atoms),
        clusters=tuple(cluster_records),
        summary=summary,
    )


def _validate_and_log(ruleset: RulesetMap) -> None:
    """Validate atoms, log findings, raise on errors."""
    findings = validate_atoms(ruleset.atoms)
    for f in findings:
        if f.severity == "error":
            logger.error("Map validation: [%s] L%d: %s — %s", f.rule, f.line, f.message, f.text)
        elif f.severity == "warn":
            logger.warning("Map validation: [%s] L%d: %s — %s", f.rule, f.line, f.message, f.text)
    errors = [f for f in findings if f.severity == "error"]
    if errors:
        raise ValueError(
            f"Map validation failed with {len(errors)} error(s). First: [{errors[0].rule}] {errors[0].message}"
        )


def _classify_all_files(
    paths: list[Path],
    root: Path,
    map_cache: Any,
    registry: dict[str, dict[str, Any]],
) -> tuple[list[FileRecord], list[Atom], list[Atom]]:
    """Classify all instruction files. Returns (file_records, all_atoms, atoms_needing_embed)."""
    file_records: list[FileRecord] = []
    all_atoms: list[Atom] = []
    atoms_needing_embed: list[Atom] = []

    for path in paths:
        chash = _classify_file(path, map_cache, all_atoms, atoms_needing_embed)
        loading, scope, globs, agent = _detect_file_loading(path, root, registry)
        desc = _parse_frontmatter_description(path) if loading == "on_invocation" else ""
        file_records.append(
            FileRecord(
                path=str(path),
                content_hash=chash,
                loading=loading,
                scope=scope,
                globs=globs,
                agent=agent,
                description=desc,
            )
        )

    return file_records, all_atoms, atoms_needing_embed


def map_ruleset(
    paths: list[Path],
    *,
    models: Models | None = None,
    root: Path | None = None,
    cache_dir: Path | None = None,
) -> RulesetMap:
    """Build a compact ruleset map from instruction files.

    This is the main client-side entry point. Classifies all files,
    embeds atoms, clusters by topic, and produces the wire format.

    When cache_dir is provided, uses incremental caching: unchanged files
    (by content hash) reuse cached atoms and embeddings. Only changed
    files are re-tokenized and re-embedded. Clustering always re-runs.
    """
    from reporails_cli.core.cache.map_cache import MapCache

    if models is None:
        models = get_models()
    if root is None:
        root = paths[0].parent if paths else Path(".")

    map_cache: MapCache | None = None
    if cache_dir is not None:
        map_cache = MapCache(cache_dir)
        map_cache.load()

    file_records, all_atoms, atoms_needing_embed = _classify_all_files(
        paths,
        root,
        map_cache,
        _load_registry(),
    )

    # Embed uncached atoms
    if atoms_needing_embed:
        _embed_atoms_deduped(atoms_needing_embed, models.st)
        if map_cache is not None:
            _update_cache_after_embedding(map_cache, all_atoms, atoms_needing_embed, file_records)

    # Enforce cache cap (LRU eviction) and save
    if map_cache is not None:
        map_cache.enforce_cap()
        map_cache.save()

    # Ensure ALL atoms have embeddings (cached atoms may lack them)
    unembedded = [a for a in all_atoms if a.embedding_int8 is None]
    if unembedded:
        _embed_atoms_deduped(unembedded, models.st)

    _embed_file_descriptions(file_records, models.st)

    ruleset = _build_ruleset_map(file_records, all_atoms, cluster_topics(all_atoms))
    _validate_and_log(ruleset)

    return ruleset


# ──────────────────────────────────────────────────────────────────
# SERIALIZATION
# ──────────────────────────────────────────────────────────────────


def _atom_to_dict(atom: Atom) -> dict[str, Any]:
    """Serialize an Atom to a JSON-compatible dict."""
    d: dict[str, Any] = {
        "line": atom.line,
        "text": atom.text,
        "kind": atom.kind,
        "charge": atom.charge,
        "charge_value": atom.charge_value,
        "modality": atom.modality,
        "specificity": atom.specificity,
        "scope_conditional": atom.scope_conditional,
        "format": atom.format,
        "position_index": atom.position_index,
        "token_count": atom.token_count,
        "file_path": atom.file_path,
        "cluster_id": atom.cluster_id,
        "plain_text": atom.plain_text,
    }
    # Inline formatting — converged format
    inline: list[dict[str, str]] = []
    for tok in atom.named_tokens:
        inline.append({"term": tok, "style": "backtick"})
    for tok in atom.italic_tokens:
        inline.append({"term": tok, "style": "italic"})
    for tok in atom.bold_tokens:
        inline.append({"term": tok, "style": "bold"})
    for tok in atom.unformatted_code:
        inline.append({"term": tok, "style": "none"})
    if inline:
        d["inline"] = inline
    if atom.embedding_int8 is not None:
        raw = bytes(v & 0xFF for v in atom.embedding_int8)
        d["embedding_b64"] = base64.b64encode(raw).decode("ascii")
    # Optional topographer fields
    if atom.topics:
        d["topics"] = list(atom.topics)
    if atom.role:
        d["role"] = atom.role
    if atom.heading_context:
        d["heading_context"] = atom.heading_context
    if atom.depth is not None:
        d["depth"] = atom.depth
    if atom.rule:
        d["rule"] = atom.rule
    if atom.ambiguous:
        d["ambiguous"] = True
    if atom.embedded_charge_markers:
        d["embedded_charge_markers"] = list(atom.embedded_charge_markers)
    return d


def _decode_embedding_b64(b64: str | None) -> tuple[int, ...] | None:
    """Decode a base64-encoded int8 embedding vector."""
    if b64 is None:
        return None
    raw = base64.b64decode(b64)
    # Convert unsigned bytes back to signed int8 (-128..127)
    return tuple(v if v < 128 else v - 256 for v in raw)


def _atom_from_dict(d: dict[str, Any]) -> Atom:
    """Deserialize an Atom from a dict."""
    # Parse converged inline format back to separate lists
    named_tokens: list[str] = []
    italic_tokens: list[str] = []
    bold_tokens: list[str] = []
    unformatted_code: list[str] = []
    for span in d.get("inline", []):
        style = span.get("style", "none")
        term = span["term"]
        if style == "backtick":
            named_tokens.append(term)
        elif style == "italic":
            italic_tokens.append(term)
        elif style == "bold":
            bold_tokens.append(term)
        elif style == "none":
            unformatted_code.append(term)

    return Atom(
        line=d["line"],
        text=d["text"],
        kind=d.get("kind", "excitation"),
        charge=d["charge"],
        charge_value=d["charge_value"],
        modality=d["modality"],
        specificity=d.get("specificity", "abstract"),
        scope_conditional=d.get("scope_conditional", False),
        format=d.get("format", d.get("format_type", "prose")),
        named_tokens=named_tokens,
        italic_tokens=italic_tokens,
        bold_tokens=bold_tokens,
        unformatted_code=unformatted_code,
        position_index=d.get("position_index", 0),
        token_count=d.get("token_count", 0),
        file_path=d.get("file_path", ""),
        cluster_id=d.get("cluster_id", -1),
        embedding_int8=_decode_embedding_b64(d.get("embedding_b64")),
        plain_text=d.get("plain_text", ""),
        heading_context=d.get("heading_context", ""),
        depth=d.get("depth"),
        rule=d.get("rule", ""),
        ambiguous=d.get("ambiguous", False),
        embedded_charge_markers=d.get("embedded_charge_markers", []),
        topics=tuple(d.get("topics", [])),
        role=d.get("role", ""),
    )


def save_ruleset_map(ruleset_map: RulesetMap, path: Path) -> None:
    """Serialize a RulesetMap to JSON."""
    import numpy as np

    path.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": ruleset_map.schema_version,
        "embedding_model": ruleset_map.embedding_model,
        "generated_at": ruleset_map.generated_at,
        "files": [
            {
                "path": f.path,
                "content_hash": f.content_hash,
                "loading": f.loading,
                "scope": f.scope,
                "agent": f.agent,
                **({"globs": list(f.globs)} if f.globs else {}),
                **({"description": f.description} if f.description else {}),
                **(
                    {
                        "description_embedding_b64": base64.b64encode(
                            np.asarray(f.description_embedding, dtype=np.int8).tobytes()
                        ).decode("ascii")
                    }
                    if f.description_embedding
                    else {}
                ),
            }
            for f in ruleset_map.files
        ],
        "atoms": [_atom_to_dict(a) for a in ruleset_map.atoms],
        "clusters": [
            {
                "id": c.id,
                "n_atoms": c.n_atoms,
                "n_charged": c.n_charged,
                "n_neutral": c.n_neutral,
                **(
                    {
                        "centroid_b64": base64.b64encode(np.asarray(c.centroid, dtype=np.float32).tobytes()).decode(
                            "ascii"
                        )
                    }
                    if c.centroid
                    else {}
                ),
            }
            for c in ruleset_map.clusters
        ],
        "summary": {
            "n_atoms": ruleset_map.summary.n_atoms,
            "n_charged": ruleset_map.summary.n_charged,
            "n_neutral": ruleset_map.summary.n_neutral,
            "n_topics": ruleset_map.summary.n_topics,
            "n_topics_charged": ruleset_map.summary.n_topics_charged,
        },
    }
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def load_ruleset_map(path: Path) -> RulesetMap:
    """Deserialize a RulesetMap from JSON."""
    import numpy as np

    data = json.loads(path.read_text(encoding="utf-8"))

    files = tuple(
        FileRecord(
            path=f["path"],
            content_hash=f["content_hash"],
            loading=f.get("loading", "session_start"),
            scope=f.get("scope", "global"),
            globs=tuple(f.get("globs", [])),
            agent=f.get("agent", "generic"),
            description=f.get("description", ""),
            description_embedding=_decode_embedding_b64(f.get("description_embedding_b64")),
        )
        for f in data["files"]
    )
    atoms = tuple(_atom_from_dict(a) for a in data["atoms"])
    clusters = tuple(
        ClusterRecord(
            id=c["id"],
            n_atoms=c["n_atoms"],
            n_charged=c["n_charged"],
            n_neutral=c["n_neutral"],
            centroid=(
                tuple(np.frombuffer(base64.b64decode(c["centroid_b64"]), dtype=np.float32).tolist())
                if c.get("centroid_b64")
                else ()
            ),
        )
        for c in data.get("clusters", [])
    )
    s = data["summary"]
    summary = RulesetSummary(
        n_atoms=s["n_atoms"],
        n_charged=s["n_charged"],
        n_neutral=s["n_neutral"],
        n_topics=s.get("n_topics", 0),
        n_topics_charged=s.get("n_topics_charged", 0),
    )

    return RulesetMap(
        schema_version=data["schema_version"],
        embedding_model=data["embedding_model"],
        generated_at=data["generated_at"],
        files=files,
        atoms=atoms,
        clusters=clusters,
        summary=summary,
    )


# ──────────────────────────────────────────────────────────────────
# MAP VALIDATION
# ──────────────────────────────────────────────────────────────────


@dataclass
class MapFinding:
    """A validation finding from map inspection."""

    severity: str  # error | warn | info
    rule: str
    message: str
    line: int = 0
    text: str = ""
    charge: str = ""


# Deterministic: negation at start MUST be constraint
_MUST_CONSTRAINT_RE = re.compile(
    r"^(never|do not|don't|must not|shall not|cannot|can't|avoid|NO |NOT )\b",
    re.IGNORECASE,
)
# Strong charge words that should not appear in NEUTRAL atoms (unless quoted)
_STRONG_CHARGE_RE = re.compile(
    r"\b(MUST|SHALL|NEVER|ALWAYS|FORBIDDEN|PROHIBITED)\b",
)
_QUOTED_ATOM_RE = re.compile(r'^["\u201c\u201e]')


_VALID_CHARGES = frozenset({"CONSTRAINT", "DIRECTIVE", "IMPERATIVE", "NEUTRAL", "AMBIGUOUS"})
_VALID_MODS = frozenset({"imperative", "direct", "absolute", "hedged", "none"})


def _validate_atom_schema(a: Atom, findings: list[MapFinding]) -> None:
    """Check schema and consistency invariants for a single atom."""
    cv, chg, mod = a.charge_value, a.charge, a.modality
    _checks: list[tuple[bool, str, str]] = [
        (chg not in _VALID_CHARGES, "schema", f"Invalid charge: {chg}"),
        (mod not in _VALID_MODS, "schema", f"Invalid modality: {mod}"),
        (cv not in (-1, 0, 1), "schema", f"Invalid charge_value: {cv}"),
        (cv == 0 and chg not in ("NEUTRAL", "AMBIGUOUS"), "consistency", f"charge_value=0 but charge={chg}"),
        (cv != 0 and chg == "NEUTRAL", "consistency", "charge_value!=0 but charge=NEUTRAL"),
        (cv == 0 and mod != "none", "consistency", f"NEUTRAL with modality={mod}"),
        (cv != 0 and mod == "none", "consistency", "Charged with modality=none"),
    ]
    for condition, rule, message in _checks:
        if condition:
            findings.append(MapFinding("error", rule, message, a.line, a.text[:80], chg))


def validate_atoms(atoms: tuple[Atom, ...] | list[Atom]) -> list[MapFinding]:
    """Validate atoms against deterministic invariants.

    Three layers:
      1. Schema — charge/modality/value consistency (hard errors)
      2. Deterministic charge — negation→constraint, heading→neutral (must hold)
      3. Statistical + suspicious — distribution anomalies, charge words in neutral

    Works on raw atom lists (from map_file) or RulesetMap.atoms.
    Returns list of findings. Empty list = clean.
    """
    findings: list[MapFinding] = []
    exc: list[Atom] = []

    for a in atoms:
        _validate_atom_schema(a, findings)
        if a.kind == "excitation":
            exc.append(a)

    # Deterministic charge invariants
    for a in exc:
        clean = _strip_md_for_classify(a.text)
        if _MUST_CONSTRAINT_RE.match(clean) and a.charge_value != -1:
            msg = f"Negation at start but charge={a.charge}"
            findings.append(MapFinding("warn", "must_constraint", msg, a.line, a.text[:80], a.charge))
        is_unquoted_neutral = (
            a.charge_value == 0 and not _QUOTED_ATOM_RE.match(a.text.strip()) and _STRONG_CHARGE_RE.search(a.text)
        )
        if is_unquoted_neutral:
            findings.append(
                MapFinding(
                    "info",
                    "suspicious_neutral",
                    "NEUTRAL atom contains strong charge word",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )

    # Statistical checks
    n_exc = len(exc)
    if n_exc > 0:
        n_charged = sum(1 for a in exc if a.charge_value != 0)
        ratio = n_charged / n_exc
        if ratio > 0.90:
            msg = f"Charge ratio {ratio:.0%} ({n_charged}/{n_exc}) — unusually high"
            findings.append(MapFinding("warn", "distribution", msg))
        if ratio < 0.05 and n_exc > 10:
            msg = f"Charge ratio {ratio:.0%} ({n_charged}/{n_exc}) — unusually low"
            findings.append(MapFinding("warn", "distribution", msg))

    return findings


def validate_map(ruleset_map: RulesetMap) -> list[MapFinding]:
    """Validate a RulesetMap. Delegates to validate_atoms."""
    return validate_atoms(ruleset_map.atoms)
