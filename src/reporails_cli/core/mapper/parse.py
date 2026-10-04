# ruff: noqa: N806, PERF401
"""Markdown-it AST walk + per-atom text extraction.

Parses the markdown source into an AST and walks it, tracking block nesting
(lists, blockquotes, tables, code fences) to populate each atom's `format` and
`position_index`. Extracts two parallel text streams from each inline segment:
`md_text` (formatting markers preserved, fed to annotate) and `plain_text`
(markers stripped, fed to classify and embed). The walker also runs
post-classify hooks — mixed-charge splitting, confidence scoring, neutral-atom
scanning — so the returned atom list is ready for embedding.

Public entry point: `tokenize(content)`.

Imports `classify_charge` + `_ALL_VERBS` + `_strip_md_for_classify` from classify
and `check_specificity` from annotate so tokenize can produce
fully-classified atoms in a single pass.
"""

from __future__ import annotations

import ast
import json
import logging
import re
import tomllib
from collections.abc import Callable
from functools import lru_cache
from typing import Any

from reporails_cli.core.mapper.annotate import check_specificity
from reporails_cli.core.mapper.classify import (
    _ALL_VERBS,
    _CLASSIFY_WORD_RE,
    classify_charge,
    hedges_with_lead,
    hedges_with_should,
    is_terse_no_prohibition,
    starts_bare_no_status,
)
from reporails_cli.core.mapper.lexicon import load_markdown_tokens
from reporails_cli.core.mapper.markdown_extract import (
    _determine_format,
    _extract_texts,
    _split_at_softbreaks,
    _strip_decoration,
    _strip_frontmatter,
)

# The inline-marker regexes and the structural strip live in `markers`, shared with
# the span-rebuilding stages.
from reporails_cli.core.mapper.markers import (
    strip_markdown_inline,
)
from reporails_cli.core.mapper.md_parser import (
    code_spans,
    file_lines,
    leading_bold_run,
    link_spans,
    md_parser,
    replace_code_spans,
    replace_spans,
)
from reporails_cli.core.mapper.prose_split import SEGMENTATION_STRUCTURE_AWARE, split_prose_sentences
from reporails_cli.core.platform.dto.ruleset import LIST_OBJECT_ROLE, Atom
from reporails_cli.core.platform.policy.negative_headings import in_negative_section

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────
# TOKENIZER (markdown-it AST)
# ──────────────────────────────────────────────────────────────────

# A line that IS a quotation: opens with a quote mark and the matching close mark ends
# it (trailing punctuation allowed). A line that merely opens with a quoted term and
# goes on — `"Dry run" is a flag; pass it early` — is running text
# and keeps whatever charge it carries.
_QUOTED_LINE_RE = re.compile(r'^["\u201c\u201e][^"\u201c\u201d\u201e]*["\u201c\u201d]\s*[.,;:!?]*\s*$')
# What may follow a bold definition label (`**Term**: …`, `**Term** — …`, `**Term** (…)`, `**Term** / …`).
_DEFN_LABEL_TAIL_RE = re.compile(r"\s*[:\u2014\u2013(/-]\s?")

_THIRD_PERSON_RE = re.compile(
    r"^(Triggers|Sends|Supports|Handles|Manages|Contains"
    r"|Provides|Returns|Creates|Runs|Fetches|Stores"
    r"|Processes|Generates|Validates|Implements"
    r"|Connects|Accepts|Includes|Maintains"
    r"|Represents|Defines|Operates|Applies"
    r"|Describes|Specifies|Determines|Requires)\s",
)

# Past-tense narration recounts what happened; it commands nothing. A date-led
# line or a first-person past-tense opener is a record, not an instruction.
_PAST_NARRATION_RE = re.compile(
    r"^(?:On \d{4}-\d\d-\d\d\b|I \w+ed\b|We \w+ed\b)",
)

# A "No <noun phrase>" line either reports a status (`No regressions.`, `No open
# issues`) or forbids the thing it names (`No console.log`, `No blank lines between
# sections`). The discriminator lives in `classify` (`starts_bare_no_status`) so the
# classifier, the neutral floor and the map validator all read the same one.


def _is_bare_no_status(plain: str) -> bool:
    """True when `plain` is a bare `No <noun phrase>` status line."""
    return starts_bare_no_status([w.lower() for w in _CLASSIFY_WORD_RE.findall(plain)])


def _bare_no_status_floors(plain: str) -> bool:
    """True when a bare status fragment accounts for the whole line.

    `No changes needed.` reports and stops; `No changes needed; run the tests before
    merging.` reports and then commands, so the clause after the break keeps its charge.
    """
    if not _is_bare_no_status(plain):
        return False
    m = _POINTER_CLAUSE_BREAK_RE.search(plain)
    return m is None or _prefix_remainder_charge(plain[m.end() :]) == 0


# "See <ref>" points at a source; it is a cross-reference, not a command. The
# verification forms ("See that ...", "See if ...") stay charged.
_SEE_POINTER_RE = re.compile(r"^see\b(?!\s+(?:that|if|whether|how)\b)", re.IGNORECASE)

# "<Label>: see <ref>" is the same cross-reference behind a label (`Knowledge: see
# docs/runbook.md`, `Design: see docs/architecture.md`). Matching stops before the `see`, so
# what follows the label is judged as its own text — a pointer floors, a genuine
# instruction riding after it keeps its charge.
#
# A LABEL is one token, or two tokens naming a thing. A clause is not a label, and
# a clause in front of a pointer still commands (`Never commit secrets: see
# security.md`, `Always run the linter first: see docs/lint.md`) — hence the token
# limit here plus the verb guard in `_label_see_opener`.
_LABEL_SEE_RE = re.compile(
    r"^[A-Za-z][\w&'/.-]{0,30}(?:[ \t][A-Za-z][\w&'/.-]{0,30})?:[ \t]+(?=see\b(?!\s+(?:that|if|whether|how)\b))",
    re.IGNORECASE,
)


def _label_see_opener(plain: str) -> re.Match[str] | None:
    """Match a `<Label>: see <ref>` opener whose label is a bare noun label.

    A single token is a label whatever its part of speech (`Design:`, `Reference:`);
    a two-token label has to name a thing, so a verb in it means the colon fronts a
    clause, not a label — and a clause keeps its own charge.
    """
    m = _LABEL_SEE_RE.match(plain)
    if m is None:
        return None
    label_words = re.findall(r"[A-Za-z']+", m.group(0))
    if len(label_words) > 1 and any(w.lower() in _ALL_VERBS for w in label_words):
        return None
    return m


# What follows a leading code span in a command reference (`` `make test` - run it ``) and in a
# pipe-shaped reference (`` `make test` | run it ``).
_CMD_REF_TAIL_RE = re.compile(r"\s*[-\u2013\u2014:]\s+")
_PIPE_REF_TAIL_RE = re.compile(r"\s*\|")
# A version constraint opening a line (`>= 3.10`), and the digit a version code span opens with.
_VERSION_OPERATOR_RE = re.compile(r"[><=~!]\s*[\d.]")
_VERSION_DIGIT_RE = re.compile(r"\s*[\d.]")
# Reference/meta labels whose body points at a source rather than commanding.
# Restricted to labels that are non-instructive by construction; labels that can
# front a real instruction (Note, Rationale, Tip) are deliberately excluded.
_META_LABEL_RE = re.compile(
    r"^(?:Knowledge|See also|See|References?|Examples?|Open questions?"
    r"|Overview|Contexts?|Sources?|Primary theory reference)\s*:\s",
    re.IGNORECASE,
)
_LABEL_ONLY_RE = re.compile(r"^[A-Z][a-z\s]{0,30}:\s*$")
_LABEL_ONLY_FIRST_WORD_RE = re.compile(r"^[A-Za-z]+")
_CLAUSE_SPLIT_RE = re.compile(r"\s[\u2014\u2013]\s|:\s*[\"'\u201c]")


def _label_only_opens_command(md_text: str) -> bool:
    """True when a `_LABEL_ONLY_RE`-shaped line opens with a command verb.

    `Audit these files:` and `Focus on:` command something the rest of the line — or a
    list under it — carries; a genuine label (`Overview:`, `Knowledge:`) has nothing of
    its own to say and floors below. Only the line's own first word decides this, the
    same signal `_riding_charge` reads for a clause riding after a pointer.
    """
    m = _LABEL_ONLY_FIRST_WORD_RE.match(md_text)
    return m is not None and m.group(0).lower() in _ALL_VERBS


def _after_leading_code(md_text: str, tail: re.Pattern[str]) -> int | None:
    """Where `tail` ends when it follows a code span that opens `md_text`; None when the text does
    not open with a code span or the tail does not follow it."""
    spans = code_spans(md_text)
    if not spans or spans[0].start:
        return None
    m = tail.match(md_text, spans[0].end)
    return m.end() if m else None


def _opens_with_version(md_text: str) -> bool:
    """Whether `md_text` opens with a version constraint (`>= 3.10`) or a code span that starts on a digit."""
    if _VERSION_OPERATOR_RE.match(md_text):
        return True
    spans = code_spans(md_text)
    return bool(spans) and not spans[0].start and _VERSION_DIGIT_RE.match(spans[0].content) is not None


def _bold_definition_label_end(md_text: str) -> int | None:
    """Where a bold definition label (`**Term** — …`, `**notes.md**: …`) opening `md_text` ends with its
    separator, or None. A one-word label that is a command verb (`**Run**: …`) is an instruction label."""
    run = leading_bold_run(md_text)
    if run is None:
        return None
    term = md_text[run.content_start : run.content_end]
    tail = _DEFN_LABEL_TAIL_RE.match(md_text, run.end)
    if tail is None or any(ch.isspace() for ch in term) or term.lower() in _ALL_VERBS:
        return None
    return tail.end()


def _is_structural(md_text: str, fmt: str = "prose") -> bool:
    """Check if text is structural meta-text that should be forced NEUTRAL.

    Only catches genuinely non-instructive CONTENT patterns — reference
    tables, file listings, version notes. Formatting (bold labels, italic
    emphasis) does NOT override charge — formatting is handled separately,
    not in charge classification.
    """
    # Shapes that are non-instructive by construction: a quotation, a bare label, a version
    # note, a reference/meta label (`Open question: …`, `See also: …`) whose body is a
    # reference or a question however it is phrased. A bare label that opens with a command
    # verb (`Audit these files:`) is not one of these — it commands the list or line after it.
    if (
        _QUOTED_LINE_RE.match(md_text)
        or _opens_with_version(md_text)
        or (_LABEL_ONLY_RE.match(md_text) and not _label_only_opens_command(md_text))
        or _META_LABEL_RE.match(md_text)
    ):
        return True

    # Shapes that FRONT a body: a bold definition label (a term or a file name), a command reference,
    # a prose line shaped like a table row. Each is structural only when the body after
    # it carries no instruction of its own — `**Important** — always run the tests` and
    # `\`make test\` — run it before every commit` command, label or not. The pipe-shaped reference
    # is skipped inside a real table, where that shape is every command-led row.
    end = _bold_definition_label_end(md_text)
    if end is None:
        end = _after_leading_code(md_text, _CMD_REF_TAIL_RE)
    if end is None and fmt != "table":
        end = _after_leading_code(md_text, _PIPE_REF_TAIL_RE)
    return end is not None and _prefix_remainder_charge(md_text[end:]) == 0


def _classify_content(
    md_text: str,
    plain_text: str,
    fmt: str,
) -> tuple[str, int, str, str, bool]:
    """Classify an atom's charge and modality.

    Uses md_text for structural detection and rule-based classification.
    Uses plain_text for 3rd-person description detection.
    Returns: (charge, charge_value, modality, rule_trace, scope_conditional)
    """
    # A non-instruction opener (meta label, `<Label>: see`, third-person description,
    # past narration, bare `See` pointer) floors only when the reference accounts for
    # the whole line — the same remainder read `_apply_structural_neutral_floor` runs
    # after the head. Both paths have to agree, because on the model-less path this
    # verdict is the final one (`See the runbook, and never commit a credential.`
    # commands, pointer or not).
    if _is_structural(md_text, fmt) or _bare_no_status_floors(plain_text):
        return "NEUTRAL", 0, "none", "structural", False
    opener = _neutral_opener(plain_text)
    if opener is not None:
        rest = plain_text[opener.end() :]
        if _prefix_remainder_charge(rest, pointer=_opener_is_pointer(plain_text, opener)) == 0:
            return "NEUTRAL", 0, "none", "third_person", False

    return classify_charge(md_text, plain_text=plain_text)


_WORD_RUN_RE = re.compile(r"[^\W\d_]{2,}", re.UNICODE)


def _carries_word(text: str) -> bool:
    """True when a span holds a word: two adjacent letters, or one non-Latin letter.

    A single CJK character IS a word, so the run-length rule is waived for a
    non-ASCII LETTER — `…` and `»` are non-ASCII without being letters, and
    neither makes a span content.
    """
    return bool(_WORD_RUN_RE.search(text)) or any(ch.isalpha() and ord(ch) > 127 for ch in text)


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
    kept = [a for a in atoms if _carries_word(a.text)]
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


# The plain form a whole fence kept as one block carries in place of its words:
# `code_block`, or `code_block:<lang>` for a tagged fence.
_FENCE_BLOCK_PLAIN = "code_block"


def is_fence_block(atom: Atom) -> bool:
    """Whether an atom is a whole fence kept as one block, rather than a line read out of a fence."""
    return atom.format == "code_block" and (
        atom.plain_text == _FENCE_BLOCK_PLAIN or atom.plain_text.startswith(f"{_FENCE_BLOCK_PLAIN}:")
    )


def _make_fence_atom(tok: Any, line_offset: int) -> Atom:
    """Create a code block atom from a fence (or indented code_block) token."""
    lang = (tok.info or "").strip().lower()
    return Atom(
        line=_tok_line(tok, line_offset),
        text=tok.content[:200],
        kind="excitation",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity="named" if lang else "abstract",
        format="code_block",
        named_tokens=[lang] if lang else [],
        file_path="",
        plain_text=f"{_FENCE_BLOCK_PLAIN}:{lang}" if lang else _FENCE_BLOCK_PLAIN,
    )


# Fence language tags naming text/prose rather than a programming or diagram
# language. A block tagged with one of these is not treated as declared code —
# it falls through to the directive check below.
#
# `markdown`/`md` are deliberately EXCLUDED: an explicit ```markdown / ```md tag
# marks a markup-DEMONSTRATION surface (idiomatic in rule/doc files that show an
# instruction anti-pattern — "Never commit secrets" — inside a fence), not a live
# directive. Scoring it produced a false CONSTRAINT/DIRECTIVE. The dominant real
# case — an UNTAGGED ``` fence carrying a real directive — is preserved via the
# empty tag; a `text`/`txt`-tagged directive is preserved too.
_FENCE_PROSE_TAGS = frozenset({"", "text", "txt", "plaintext", "plain", "prose", "quote", "none"})

# A fence line shorter than this carries no classifiable instruction.
_FENCE_MIN_LINE = 5

# A fenced line that opens with a box-drawing glyph (`├── file.md`, `│`, `└─`) is a
# row of a tree / layout diagram, never an instruction — its bare file name would
# otherwise charge as a verb-first imperative (`test-procedure.md` → "test"). So is a
# flow row whose parts an arrow joins (`Research Analyst -> discovers components`).
_DIAGRAM_LINE_RE = re.compile(r"^[\u2500-\u257f]|\s(?:-+>|=+>|<-+|\u2192|\u27f6)\s")


def _fence_declares_code(lang: str) -> bool:
    """Return True when a fence's language tag names a programming or diagram
    language (`python`, `json`, `mermaid`, …), which the caller keeps as a single
    neutral block rather than reading its lines. A bare or text/prose tag is not
    a code declaration."""
    return bool(lang) and lang not in _FENCE_PROSE_TAGS


# Shell-shaped line openers and operators: an UNTAGGED fence whose lines are mostly
# these is a shell snippet (a `for` loop, a `curl | jq` pipeline), not prose — its
# `echo`/`for` lines must not be read as imperatives. `#` is deliberately absent: a
# markdown heading inside a text fence starts the same way.
_SHELL_LINE_RE = re.compile(
    # Unambiguous shell keywords/commands — safe as bare line openers.
    r"^(?:\$ |\$\(|\$\{|(?:for|while|if|then|else|elif|fi|done|case|esac|echo|export|cd|ls|cat|grep|sed|awk|"
    r"uv|uvx|npm|npx|pnpm|yarn|pip|python3?|git|curl|wget|docker|chmod|mkdir|rm|cp|mv|sudo)\b"
    # Words that are also plain English imperatives (`do not …`, `make sure …`, `set the …`):
    # count as shell ONLY with a shell co-signal — a flag/path/var arg, an assignment, or
    # the bare loop keyword at end of line (`do` / `done`). Otherwise they read as prose.
    r"|(?:do|make|set|source)(?:\s+[-./$~]|\s*$|\s+\w+=))"
    # Operator co-signals for a shell line without a leading command word. ` | ` (a single
    # spaced pipe) is deliberately EXCLUDED: it matches every markdown table row and any prose
    # containing " | ", silencing the whole fence. A real piped command already matches via its
    # leading command word (`cat … | grep …`); `$(`, `${`, `&&`, `||` stay. Trade-off: a fence
    # of custom-script pipes with no recognized command (`render | verify`) now reads as prose
    # and its lines are scored — the safer error than silencing every table/prose directive.
    r"|.*(?:\$\(|\$\{|&&|\|\|)"
)


# A fence whose body carries a markdown heading (`## Audit: {agent}`) is a markdown document
# sample - a report template the agent prints, a file body shown to the reader - the same
# demonstration surface a ```markdown fence is, so its lines are not read as instructions.
def _fence_is_markdown_sample(content: str) -> bool:
    """Return True when a fence's body, read as markdown, carries a `#` heading."""
    return any(tok.type == "heading_open" and tok.markup.startswith("#") for tok in md_parser.parse(content))


def _fence_looks_like_shell(content: str) -> bool:
    """Return True when at least half of a fence's non-empty lines are shell-shaped."""
    lines = [ln.strip() for ln in content.splitlines() if ln.strip()]
    if not lines:
        return False
    return sum(1 for ln in lines if _SHELL_LINE_RE.match(ln)) * 2 >= len(lines)


def _ast_is_trivial(tree: ast.Module) -> bool:
    """Return True when a parsed module is only bare names, constants, or dotted
    attribute references — the shape a one- or two-word text line takes when it
    happens to parse (`Read`, `config.yaml`), which must NOT count as code."""
    if not tree.body:
        return True
    for node in tree.body:
        if not isinstance(node, ast.Expr):
            return False
        if not isinstance(node.value, (ast.Name, ast.Constant, ast.Attribute)):
            return False
    return True


def _fence_parses_as_code(content: str) -> bool:
    """Return True when an untagged block's body is valid JSON, TOML, or
    non-trivial Python — a strict, dependency-free parse. Conservative by
    construction: a bare word or single name parses as Python but is rejected as
    trivial, so a one-line instruction is never mistaken for code."""
    text = content.strip()
    if not text:
        return False
    try:
        json.loads(text)
        return True
    except (ValueError, RecursionError):
        pass
    try:
        tomllib.loads(text)
        return True
    except (tomllib.TOMLDecodeError, ValueError):
        pass
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return False
    return not _ast_is_trivial(tree)


def _fence_directive_atoms(
    tok: Any,
    line_offset: int,
    pos_idx: int,
    current_heading: str,
    atoms: list[Atom],
) -> int | None:
    """Read a fence's lines and, when any line is a charged instruction, append
    one atom per content line (each keeping the `code_block` format) and return
    the advanced `pos_idx`. Return None when no line carries an instruction, so
    the caller falls back to a single neutral block atom."""
    # `_tok_line` gives the opening-fence line; content starts on the next line.
    content_line = _tok_line(tok, line_offset) + 1
    entries = [
        (idx, stripped)
        for idx, raw in enumerate(file_lines(tok.content))
        if len(stripped := raw.strip()) >= _FENCE_MIN_LINE and not _DIAGRAM_LINE_RE.search(stripped)
    ]
    # Classify each line ONCE (the gate below reuses the same verdict the atom
    # carries — a second classify in atom-build would let the two disagree),
    # off a markdown-STRIPPED plain form. A fenced line's markdown is literal, so
    # `**never**` / `` `never` `` must be stripped before charge classification or
    # the prohibition reads NEUTRAL and is lost on every emphasis-wrapped fenced
    # directive. The raw line stays the atom's display `text`.
    classified = [(idx, line, strip_markdown_inline(line)) for idx, line in entries]
    scored = [(idx, line, plain, _classify_content(line, plain, "code_block")) for idx, line, plain in classified]
    if not scored or not any(verdict[0] != "NEUTRAL" for _idx, _line, _plain, verdict in scored):
        return None
    for idx, line, plain, verdict in scored:
        atoms.append(
            _make_inline_atom(
                line, plain, "code_block", content_line + idx, pos_idx, current_heading, precomputed=verdict
            )
        )
        pos_idx += 1
    return pos_idx


def _process_fence(
    tok: Any,
    line_offset: int,
    pos_idx: int,
    current_heading: str,
    atoms: list[Atom],
) -> int:
    """Decide how one fence contributes atoms. A block whose tag declares code, or
    whose untagged body parses as code, reads as shell, or is a markdown document
    sample, stays a single neutral block atom. Any other block whose lines carry an
    instruction is read line-by-line so the instruction is scored; a text block with
    no instruction stays neutral."""
    lang = (tok.info or "").strip().lower()
    content = tok.content
    if (
        not _fence_declares_code(lang)
        and not _fence_parses_as_code(content)
        and not _fence_looks_like_shell(content)
        and not _fence_is_markdown_sample(content)
    ):
        advanced = _fence_directive_atoms(tok, line_offset, pos_idx, current_heading, atoms)
        if advanced is not None:
            return advanced
    atoms.append(_make_fence_atom(tok, line_offset))
    return pos_idx


def _strip_backtick_delims(text: str) -> str:
    """`text` with each backtick span's delimiters dropped, its interior words kept.

    A named span's own words are still length, not a single placeholder — `` `pytest
    tests/unit` `` reads several tokens long, not one.
    """
    return replace_code_spans(text, lambda span: span.content)


@lru_cache(maxsize=1)
def _subword_tokenizer() -> Any | None:
    """The bundled subword tokenizer, loaded once, or `None` when it is not on disk yet.

    Token counting needs only the fast tokenizer file, not the ONNX charge graphs, so
    it loads independently of encoder availability — a fresh install or an offline run
    with a partial model cache still counts correctly once the tokenizer itself has
    been fetched. Padding and truncation are disabled so a count is never clipped.
    """
    try:
        from tokenizers import Tokenizer
    except ImportError:
        return None
    from reporails_cli.bundled import get_models_path

    path = get_models_path() / "minilm-l6-v2" / "tokenizer.json"
    if not path.is_file():
        return None
    try:
        tok = Tokenizer.from_file(str(path))
    except Exception as exc:  # the tokenizers binding raises a bare Exception for any unreadable file
        logger.warning("Tokenizer file %s could not be loaded: %s", path, exc)
        return None
    tok.no_padding()
    tok.no_truncation()
    return tok


def _count_tokens(text: str) -> int:
    """The subword-token length of `text` — a backticked span counts its own tokens, not one.

    `text` is the instruction without its formatting (the parse's plain text), so an
    emphasis or bold wrap never adds tokens; a fenced line keeps its literal text and
    only loses its backtick delimiters here.

    Falls back to a whitespace word count when the bundled tokenizer is not yet on disk
    (a lean wheel before its first model fetch), so counting a length never fails.
    """
    stripped = _strip_backtick_delims(text)
    tok = _subword_tokenizer()
    if tok is None:
        return len(stripped.split())
    enc = tok.encode(stripped)
    mask = enc.special_tokens_mask
    return len(enc.ids) - sum(mask) if mask else len(enc.ids)


def _specificity_fields(text: str, counted: str | None = None) -> dict[str, Any]:
    """Build specificity-related Atom fields from text.

    The length is counted on `counted` (the text without inline formatting) when given.
    """
    spec, named, unformatted, italic, bold = check_specificity(text)
    return {
        "specificity": spec,
        "named_tokens": named,
        "unformatted_code": unformatted,
        "italic_tokens": italic,
        "bold_tokens": bold,
        "token_count": _count_tokens(text if counted is None else counted),
    }


def _tok_line(tok: Any, line_offset: int) -> int:
    """Extract line number from a markdown-it token."""
    return (tok.map[0] if tok.map else 0) + line_offset + 1


def inline_line(tok: Any, line_offset: int, pos: int) -> int:
    """The file line that offset `pos` of the inline token `tok`'s source text falls on."""
    content: str = tok.content
    return _tok_line(tok, line_offset) + content.count("\n", 0, pos)


def _segment_lines(tok: Any, line_offset: int) -> list[int]:
    """The file line each line segment of the inline token `tok` starts on, in the order
    `_split_at_softbreaks` returns them: a line break ends a line, and any inline construct whose
    recorded source span runs onto the next line (code span, inline HTML tag, image, link) moves every
    later segment down with it."""
    line = _tok_line(tok, line_offset)
    starts: list[int] = []
    open_segment = False
    link_end_line: list[int] = []
    for child in tok.children or []:
        if child.type in ("softbreak", "hardbreak"):
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
    tok: Any,
    tokens: list[Any],
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


# Rule trace of a table header row: a column-label row, kept neutral.
TABLE_HEADER_RULE = "table_header"


def _collect_table_cells(tokens: list[Any], start: int) -> tuple[str, str, int]:
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
            md_cell, plain_cell, _toks = _extract_texts(tokens[j].children or [])
            md_cells.append(md_cell.strip())
            plain_cells.append(plain_cell.strip())
        j += 1
    return " | ".join(md_cells), " | ".join(plain_cells), j + 1


def _make_table_row_atom(
    tok: Any,
    tokens: list[Any],
    i: int,
    line_offset: int,
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
        _tok_line(tok, line_offset),
        pos_idx,
        current_heading,
        precomputed=("NEUTRAL", 0, "none", TABLE_HEADER_RULE, False) if header else None,
    )
    return atom, next_i


def _make_inline_atom(
    md_text: str,
    plain_text: str,
    fmt: str,
    line: int,
    pos_idx: int,
    current_heading: str,
    *,
    precomputed: tuple[str, int, str, str, bool] | None = None,
) -> Atom:
    """Create an inline content atom with charge classification.

    `precomputed` supplies an already-computed `_classify_content` verdict so a
    caller that must gate on the charge (the fence cascade) classifies once and
    reuses it here rather than re-running the classifier per atom.
    """
    charge, cv, mod, rule_trace, scope_cond = (
        precomputed
        if precomputed is not None
        else _classify_content(
            md_text,
            plain_text,
            fmt,
        )
    )
    # A fenced line is counted as typed; every other line is counted without its formatting.
    sf = _specificity_fields(md_text, md_text if fmt == "code_block" else plain_text)
    # A fenced line's markdown is LITERAL, not rendered: a `**`/`*`/bare code token
    # is text the author typed INSIDE a code fence, so the rendered-appearance
    # fields (bold / italic / unformatted-code) must stay empty — else a fenced
    # `Never use **mock**` trips bold-on-constraint and italic-constraints as if
    # the `**` were emphasis. The charge/count/specificity
    # signals still carry, so counting fenced directives is unaffected.
    literal_markdown = fmt == "code_block"
    return Atom(
        line=line,
        text=md_text,
        kind="excitation",
        charge=charge,
        charge_value=cv,
        modality=mod,
        scope_conditional=scope_cond,
        specificity=sf["specificity"],
        format=fmt,
        named_tokens=sf["named_tokens"],
        italic_tokens=[] if literal_markdown else sf["italic_tokens"],
        bold_tokens=[] if literal_markdown else sf["bold_tokens"],
        unformatted_code=[] if literal_markdown else sf["unformatted_code"],
        position_index=pos_idx,
        token_count=sf["token_count"],
        heading_context=current_heading,
        plain_text=plain_text,
        rule=rule_trace,
        ambiguous=rule_trace.endswith("!amb"),
    )


def _update_block_stack(tok: Any, block_stack: list[str]) -> None:
    """Push/pop the block-nesting stack per a markdown-it block open/close token."""
    md_tokens = load_markdown_tokens()
    if tok.type in md_tokens.block_types:
        block_stack.append(md_tokens.block_types[tok.type])
    elif tok.type in md_tokens.block_close and block_stack:
        block_stack.pop()


_TASK_BOX_RE = re.compile(r"^\[[ xX]\]\s+")

# The blocks a paragraph can introduce: a list, a code block or a table.
_LEAD_IN_BLOCKS = frozenset({"bullet_list_open", "ordered_list_open", "fence", "code_block", "table_open"})


def _ends_with_colon(plain_text: str) -> bool:
    """True when the text's last character is a colon."""
    return plain_text.rstrip().endswith(":")


def _block_follows_paragraph(tokens: list[Any], i: int) -> bool:
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
    segment: list[Any], fmt: str, line: int, pos_idx: int, current_heading: str, *, task_box: bool
) -> Atom | None:
    """The atom of one line segment of an inline token, or None when the line is too short to read."""
    md_text, plain_text = _extract_texts(segment)[:2]
    if task_box:
        md_text, plain_text = _TASK_BOX_RE.sub("", md_text), _TASK_BOX_RE.sub("", plain_text)
    if len(md_text) < 5:
        return None
    return _make_inline_atom(md_text, plain_text, fmt, line, pos_idx, current_heading)


def _process_inline_segments(
    tok: Any,
    line_offset: int,
    block_stack: list[str],
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
    segments = _split_at_softbreaks(tok.children)
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


def parse_blocks(content: str, env: dict[str, Any] | None = None) -> tuple[list[Any], int]:
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
                _block_follows_paragraph(tokens, i),
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


def _atom_from_sentence(
    sent: str,
    atom: Atom,
    charge: str,
    cv: int,
    mod: str,
    rule: str,
    scope: bool,
    *,
    plain_sent: str,
) -> Atom:
    """Create an atom from a sub-sentence of a split atom.

    `plain_sent` is the AST-clean form of THIS sentence — pass `sent` itself when
    the caller already fed AST-extracted text. A regex strip of the markers is
    blunt — it deletes every `*` and `_` in the run, not just paired emphasis
    delimiters — so applying it to AST-clean text destroys the identifiers instruction
    files are made of (`fetch_bundled_model`, `*.pem`, `AILS_SERVER_URL`). AST
    extraction drops markers structurally and keeps code-span content verbatim,
    so its output needs no second pass.

    Supplying it also settles the case no in-sentence matcher can: an emphasis
    span wrapping two sentences (`*Do not do X. Do not do Y.*`) leaves each half
    with an unpaired marker, while the AST removed the pair before either half
    existed.

    A part of a fenced line keeps the fenced line's literal markdown: its `**`, `*`
    and bare code tokens are typed text, not emphasis, as in :func:`_make_inline_atom`.
    """
    spec, named, unformatted, italic, bold = check_specificity(sent)
    literal_markdown = atom.format == "code_block"
    plain = plain_sent.strip()
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
        italic_tokens=[] if literal_markdown else italic,
        bold_tokens=[] if literal_markdown else bold,
        unformatted_code=[] if literal_markdown else unformatted,
        position_index=atom.position_index,
        token_count=_count_tokens(sent if literal_markdown else plain),
        heading_context=atom.heading_context,
        list_depth=atom.list_depth,
        lead_in=atom.lead_in and _ends_with_colon(plain),
        plain_text=plain,
        rule=rule,
        ambiguous=rule.endswith("!amb"),
        imported_from=atom.imported_from,
        imported_line=atom.imported_line,
    )


def build_split_atom(clause: str, parent: Atom, *, plain_sent: str) -> Atom:
    """Build a sub-atom from one clause of an over-merged parent atom.

    Re-classifies the clause's charge independently — one charge per topic, and
    a clause is a fine-grained enough unit for that — and carries the parent's
    file/format/heading context. The resulting sub-atoms are emitted as
    separate atoms; this function does not decide how they relate to one
    another.
    """
    plain = re.sub(r"[*_]+", "", replace_code_spans(clause, "x")).strip()
    charge, cv, mod, rule, scope = _classify_content(clause, plain, parent.format)
    atom = _atom_from_sentence(clause, parent, charge, cv, mod, rule, scope, plain_sent=plain_sent)
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
        charge, cv, mod, rule, scope = _classify_content(sent, plain, atom.format)
        sub = _atom_from_sentence(sent, atom, charge, cv, mod, rule, scope, plain_sent=plains[idx])
        sub.file_path = atom.file_path
        subs.append(sub)
    keep_lead_in_on_last(subs)
    return subs


# Formats whose unit is a running line, so the sentence rule decides its edges.
_SENTENCE_SPLIT_FORMATS = frozenset({"prose", "table"})


def _apply_deontic_floor(atoms: list[Atom]) -> None:
    """Impose a one-way prohibition floor from a bare negative deontic heading.

    Forces a list item under `## Don'ts` / `## Must Not` to `CONSTRAINT` charge
    regardless of the item's own sign — the heading suppresses the behaviour, so
    a double-negation (`## Don'ts` + "do not X") stays prohibited rather than
    composing to permission. Charge-level only: the text is never mutated, so
    every other field the atom carries is untouched — only its charge changes.
    Positive headings carry no floor. Runs AFTER charge assignment.
    """
    for atom in atoms:
        if not in_negative_section(atom.kind, atom.format, atom.heading_context):
            continue
        atom.charge, atom.charge_value = "CONSTRAINT", -1
        if atom.modality == "none":
            # A charged atom must carry a modality (schema: charged ⇒ not `none`);
            # the floor sets the sign, so fall back to the neutral-imperative default.
            atom.modality = "direct"


# A pointer that runs on into a second clause is not only a pointer: the inner
# strip below covers a bare reference object only, so `Knowledge: see the runbook,
# and never commit a credential.` keeps the prohibition riding after the comma.
# A clause break is punctuation: a bare `and` / `but` joins words as readily as
# clauses, and inside a reference title (`see the build and deploy guide`) it opens
# no second clause at all.
_POINTER_CLAUSE_BREAK_RE = re.compile(r"[,;]\s|\s[\u2014\u2013]\s")
# What a remainder may open with once its opener is stripped: the clause break itself
# and a coordinating conjunction (`, and never skip …` → `never skip …`), so the
# instruction riding after a pointer or label is read as the clause it is.
_REMAINDER_LEAD_RE = re.compile(r"^(?:[,;:]\s*|[\u2014\u2013|]\s*)?(?:(?:and|but|then|so)\s+)?", re.IGNORECASE)


def _prefix_remainder_charge(remainder: str, *, pointer: bool = False) -> int:
    """Classify what is left after stripping a label/narration opener.

    Returns the remainder's own `charge_value` — `0` when it carries no independent
    instruction (the opener accounted for the whole atom), nonzero when a genuine
    instruction rides along after it (the opener was riding a real directive/
    prohibition, not fronting a bare reference).

    What follows a pointer (`See …`, or a label fronting one — `Knowledge: see …`),
    up to the next clause break, is the pointer's OBJECT: a reference title, never a
    command. So it is not classified at all; a title reads as an instruction whenever
    its first word doubles as a verb (`see the build and deploy guide`). The same
    holds for a third-person opener's object (`Triggers a rebuild`). A real instruction
    riding behind the object sits after a clause break (`See the runbook, and never
    commit a credential.`; `Triggers a rebuild; always run the linter.`) and is read as
    the clause it is (:func:`_riding_charge`).
    """
    remainder = _REMAINDER_LEAD_RE.sub("", remainder.strip(" :\u2014\u2013"))
    if not remainder:
        return 0
    inner = _SEE_POINTER_RE.match(remainder) or _THIRD_PERSON_RE.match(remainder)
    if inner is None and not pointer:
        cv = _riding_charge(remainder)
        if cv:
            return cv
    after = remainder[inner.end() :] if inner is not None else remainder
    m = _POINTER_CLAUSE_BREAK_RE.search(after)
    if m is None:
        return 0
    clause = _REMAINDER_LEAD_RE.sub("", after[m.end() :].strip())
    return _riding_charge(clause) if clause else 0


# A clause that rides after a label, pointer, or status fragment counts as an instruction
# only when it OPENS as one — a deontic, or an imperative verb, optionally addressed
# (`you must …`, `please …`). A noun phrase whose first word doubles as a verb (`the build
# command`) is a description, whatever the lexical classifier makes of it.
_RIDING_ADDRESS_RE = re.compile(r"^(?:you\s+|please\s+)+", re.IGNORECASE)
_RIDING_DEONTICS = frozenset(
    {
        "never",
        "always",
        "must",
        "shall",
        "should",
        "no",
        "do",
        "don't",
        "dont",
        "avoid",
        "only",
        "ensure",
        "require",
        "prefer",
    }
)
_FIRST_WORD_RE = re.compile(r"[A-Za-z][\w'-]*")


def _riding_charge(remainder: str) -> int:
    """The charge of a clause riding after an opener, or 0 when it does not open as an instruction."""
    head = _RIDING_ADDRESS_RE.sub("", remainder)
    first = _FIRST_WORD_RE.match(head)
    if first is None:
        return 0
    word = first.group(0).lower()
    if word not in _RIDING_DEONTICS and word not in _ALL_VERBS:
        return 0
    _, cv, _, _, _ = classify_charge(remainder, plain_text=remainder)
    return cv


def _opener_is_pointer(plain: str, opener: re.Match[str]) -> bool:
    """True when `opener` is the bare `See …` pointer (its remainder opens with the object)."""
    m = _SEE_POINTER_RE.match(plain)
    return m is not None and m.end() == opener.end()


# Deterministic non-instruction OPENERS. Each floors its atom only when nothing
# charged rides along after it (:func:`_prefix_remainder_charge`); the longest
# match wins, so `Knowledge: see ...` is read as a pointer rather than as a label
# fronting the imperative `see`.
_NEUTRAL_OPENERS: tuple[Callable[[str], re.Match[str] | None], ...] = (
    _label_see_opener,
    _META_LABEL_RE.match,
    _THIRD_PERSON_RE.match,
    _PAST_NARRATION_RE.match,
    _SEE_POINTER_RE.match,
)


def _neutral_opener(plain: str) -> re.Match[str] | None:
    """The longest deterministic non-instruction opener `plain` carries, if any."""
    best: re.Match[str] | None = None
    for matcher in _NEUTRAL_OPENERS:
        m = matcher(plain)
        if m is not None and (best is None or m.end() > best.end()):
            best = m
    return best


def _apply_negation_constraint_floor(atoms: list[Atom]) -> None:
    """Impose a CONSTRAINT floor on a terse prohibition the running-text head left NEUTRAL.

    `No console.log` / `No hardcoded secrets in code` are prohibitions by shape — the
    deterministic classifier reads them as such
    (:func:`~reporails_cli.core.mapper.classify.is_terse_no_prohibition`) and the map
    validator reports a NEUTRAL one as a defect. The running-text head scores the
    verbless form as a plain statement, so the determination is re-imposed after it —
    the mirror of :func:`_apply_structural_neutral_floor`. Excluded: a status line
    (`No open issues.`), a descriptive `No X is Y`, a described absence (`No support
    for Windows`, `No data in this table yet`), and any `No ...` line the head found a
    predicate or a subject in (that line reports, it does not prohibit). Charge-level
    only: text and every other field are untouched. Runs BEFORE the structural floor, so
    a quoted or otherwise structural line promoted here is zeroed again there. A table's
    header row is a column label (`No. | Rule | Owner`), never a prohibition.
    """
    for atom in atoms:
        if atom.kind == "heading" or atom.charge_value != 0 or atom.rule == TABLE_HEADER_RULE:
            continue
        plain = (atom.plain_text or atom.text).strip()
        if not is_terse_no_prohibition([w.lower() for w in _CLASSIFY_WORD_RE.findall(plain)]):
            continue
        slots = atom.slots
        if slots is not None and (slots.predicate or slots.subject):
            continue
        atom.charge, atom.charge_value, atom.modality = "CONSTRAINT", -1, "direct"


def _apply_structural_neutral_floor(atoms: list[Atom]) -> None:
    """Re-impose the deterministic structural-NEUTRAL determination after the running-text head.

    The tokenize-time guards (`_is_structural` / `starts_bare_no_status` / third-person / past-narration
    / `See:` pointer) mark a non-instruction NEUTRAL, but the running-text head re-charges every
    eligible atom from its own confidence scores and can override that determined NEUTRAL with a
    `+1`/`-1` sign it should not carry. A determined NEUTRAL is ground truth at the shape/regex
    level, so it floors the probabilistic head, mirroring `_apply_deontic_floor`. Charge-level
    only: text and every other field are untouched — only the atom's charge is reset to NEUTRAL.

    A label/narration OPENER (`_NEUTRAL_OPENERS` — a meta label, a `<Label>: see ...`
    cross-reference, a third-person or past-tense narration, a bare `See ...`) floors the whole
    atom only when it accounts for the whole atom: the text left after stripping the opener
    carries no independent charge of its own (:func:`_prefix_remainder_charge`). When a genuine
    instruction rides along after the opener (`Reference: never delete the cache directory.`),
    the head's own charge is kept rather than zeroed. The label-fronted shapes (definition label,
    command reference, pipe reference, file listing) and the bare-status fragment get the same
    remainder read; only the whole-line shapes (a quotation, a bare label, a version note) floor
    unconditionally, having no body to carry an instruction.
    """
    for atom in atoms:
        if atom.kind == "heading" or atom.charge_value == 0:
            continue
        plain = atom.plain_text or ""
        opener = _neutral_opener(plain)
        if opener is not None:
            floor = _prefix_remainder_charge(plain[opener.end() :], pointer=_opener_is_pointer(plain, opener)) == 0
        else:
            floor = _is_structural(atom.text, atom.format) or _bare_no_status_floors(plain)
        if floor:
            atom.charge, atom.charge_value, atom.modality = "NEUTRAL", 0, "none"


def _apply_hedged_should_floor(atoms: list[Atom]) -> None:
    """Read an instruction given with `should`, or opening with a hedge word (`Prefer …`, `Try
    to …`, `Perhaps …`), as hedged.

    `You should run the linter first` recommends rather than requires, and the lexical
    classifier reads its `should` that way (:func:`~reporails_cli.core.mapper.classify.hedges_with_should`);
    the span decoder reads the same line as a direct instruction, so the hedge is re-imposed
    after it. Only an atom that already carries a charge is touched, and only its modality —
    never its charge or text. `might` and `could` keep the modality the span decoder gives them.
    """
    for atom in atoms:
        text = atom.plain_text or atom.text
        if atom.charge_value != 0 and (hedges_with_should(text) or hedges_with_lead(text)):
            atom.modality = "hedged"


def _segment_structure_aware(atoms: list[Atom]) -> list[Atom]:
    """Format-aware segmentation — the structure-aware alternative to the split.

    Reads each atom's `format` (never overwriting it) and routes by structural
    unit: prose and table rows split into whole sentences (rule-based, no
    clause/comma/colon fragments); list/numbered/code/blockquote items and
    headings stay whole. Positions are re-indexed in document order
    (:func:`reindex_positions`).

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
        if atom.kind != "heading" and atom.format in _SENTENCE_SPLIT_FORMATS and atom.rule != TABLE_HEADER_RULE:
            result.extend(_split_prose_atom(atom))
        else:
            result.append(atom)

    reindex_positions(result)
    return result


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


def _strip_refs_for_marker_scan(text: str) -> str:
    """Drop link labels and targets and code spans before marker detection.

    A charge word inside a link label or a code span is referential, not
    instructional, so it must not promote a neutral atom to AMBIGUOUS.
    """
    return replace_spans(text, (*code_spans(text), *link_spans(text)), lambda _span: " ")


def _scan_neutral_for_embedded_markers(atoms: list[Atom]) -> None:
    """Scan neutral atoms for embedded charge markers.

    Reclassifies to AMBIGUOUS when charge language appears in text that
    the classifier couldn't resolve. AMBIGUOUS atoms are excluded from
    diagnostics until the user rephrases them. The map records what
    markers were found so diagnostics can suggest specific fixes.

    Unambiguous instruction language is required: what cannot be classified
    is not scored.
    """
    # Rules that produce correct neutralizations — don't second-guess these.
    # Backtick filter: ROOT verb inside code markup (not an instruction).
    # Third person: "The system processes..." (description, not instruction).
    # Structural: tables, file listings, pipe references.
    # Table header: a column label (`Don't | Do`) whose charge words name columns.
    _TRUSTED_NEUTRAL_RULES = frozenset(
        {
            "third_person",
            "short_text",
            "no_words",
            TABLE_HEADER_RULE,
        }
    )

    for atom in atoms:
        if atom.charge != "NEUTRAL" or atom.kind == "heading":
            continue
        # A neutral whole-fence BLOCK is literal code/diagram text, never scanned for
        # embedded charge language — mirrors the same guard in `_split_mixed_charge_atoms`
        # and `_split_charge_boundaries`.
        if is_fence_block(atom):
            continue
        if atom.rule in _TRUSTED_NEUTRAL_RULES:
            continue
        text = _strip_refs_for_marker_scan(atom.text)
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


def _scan_charged_for_compound_markers(atoms: list[Atom]) -> None:
    """Detect opposite-direction markers in charged atoms.

    A directive like "mention it — don't delete it" contains both a
    directive verb and a constraint negation. The classifier picks one
    charge; this scanner records the opposite-direction signal on the atom
    so a later consumer can recognize it as a compound instruction rather
    than treat it as a plain one-sided directive or constraint.

    Does NOT change the atom's charge.
    """
    for atom in atoms:
        if atom.charge_value == 0 or atom.kind == "heading":
            continue
        text = _strip_refs_for_marker_scan(atom.text)
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
