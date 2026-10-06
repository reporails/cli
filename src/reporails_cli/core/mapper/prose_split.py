"""Deterministic rule-based prose sentence splitter.

Splits a prose run into whole sentences at sentence boundaries only — never at
inline commas, colons, or dashes. Pure python, no model, no network, no torch.

The splitter is protect-then-split. Markdown instruction text is dense with
identifiers whose periods are not sentence terminators — dotfiles
(`.claude/rules/`), paths (`src/a/b.py`), attribute chains (`yaml.YAMLError`),
globs (`*.pem`), call notation (`f(x)`) and versions (`1.2.3`). Those shapes are
masked first; a boundary is then taken only at terminal punctuation followed by
whitespace and a plausible sentence opener, minus an abbreviation veto.

Public entry point: `split_prose_sentences(text)`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# Segmentation modes (config flag `.ails/config.yml` `segmentation:`).
SEGMENTATION_LEGACY = "legacy"
SEGMENTATION_STRUCTURE_AWARE = "structure-aware"

# Tokens whose trailing period binds the token and never ends a sentence — the
# following word continues the same clause.
_ABBREV = frozenset(
    [
        # latin + editorial
        "e.g.",
        "i.e.",
        "cf.",
        "al.",
        "ca.",
        "approx.",
        "resp.",
        "incl.",
        "excl.",
        "esp.",
        "est.",
        "dept.",
        "pp.",
        "ed.",
        "eds.",
        "rev.",
        "vs.",
        "vs",
        "Inc.",
        "Ltd.",
        "Co.",
        "Corp.",
        "LLC.",
        # titles + reference labels
        "Dr.",
        "Mr.",
        "Mrs.",
        "Ms.",
        "Prof.",
        "Sr.",
        "Jr.",
        "St.",
        "Mt.",
        "Fig.",
        "Figs.",
        "Eq.",
        "Ref.",
        "Refs.",
        "Sec.",
        "Ch.",
        "Vol.",
        # calendar
        "Jan.",
        "Feb.",
        "Mar.",
        "Apr.",
        "Jun.",
        "Jul.",
        "Aug.",
        "Sep.",
        "Sept.",
        "Oct.",
        "Nov.",
        "Dec.",
        "Mon.",
        "Tue.",
        "Wed.",
        "Thu.",
        "Fri.",
        "Sat.",
        "Sun.",
        # dotted acronyms
        "U.S.",
        "U.K.",
        "E.U.",
        "a.m.",
        "p.m.",
    ]
)

# Abbreviations that routinely END a sentence (`…, rules, agents, etc. The next
# key …`). Their period terminates when a fresh sentence plainly follows.
# `Co.` / `Jr.` / `LLC.` bind a name but routinely END a sentence when a fresh
# capitalised one follows (`... at Lazard Freres & Co. He sat on the boards ...`).
_ABBREV_MAY_END = frozenset(["etc.", "al.", "seq.", "ff.", "Co.", "Corp.", "Inc.", "Ltd.", "LLC.", "Jr.", "Sr."])

# Reference labels that bind only when a figure follows (`No. 1`, `Fig. 3`) and
# otherwise end the sentence (`No. The opposite is happening.`).
_ABBREV_BEFORE_DIGIT = frozenset(
    [
        "No.",
        "Nos.",
        "no.",
        "nos.",
        "Fig.",
        "Figs.",
        "Eq.",
        "Ch.",
        "Vol.",
        "Sec.",
        "p.",
        "pp.",
        "v.",
        "min.",
        "max.",
        "avg.",
    ]
)
_DIGIT_FOLLOWS_RE = re.compile(r"\s*\d")

# A leading ordinal is an ordered-list MARKER, not a sentence terminator:
# splitting on it emits a bare `1.` carrying no instruction, which survives as an
# atom downstream. The marker stays attached to the item it numbers. Authors
# space the marker off the number often enough (`9 . Click …`) to allow for it.
_LEADING_ORDINAL_RE = re.compile(r"(?:^|[\u2192\u2022\]])\s*\d+\s*\.$")

# Token shapes that must never be cut, read from the text itself. This is what
# lets the splitter work without a code-span mask from the caller.
_PROTECT_RE = re.compile(
    r"""(?x)
      (?:^|(?<=[\s(\[{"'\u2014\u2013]))                         # at a token start
      (?:
          \.[A-Za-z0-9_-]+                            # .claude  .ails  .env
        | [~./]?[\w.-]*/[\w./-]*                      # src/a/b.py   ./x   path/
        | [A-Za-z_][\w-]*(?:\.[A-Za-z_][\w-]*)+       # module.attr  file.py  a.b.c
        | \w+\([^)\s]*\)                              # f(x)  g(x,y)
        | v?\d+(?:\.\d+)+                             # 1.2.3  v0.6.0
        | \d+\.\d+                                    # 0.383
        | https?://\S+                                # urls
      )
    """
)

_TERM_RE = re.compile(r"[.!?\u2026]+[\"'\u201d\u2019)\]]*")

# A word — two adjacent letters. A lone letter is a list label (`A.`), not
# content. `…` and `»` are non-ASCII but not letters, so neither qualifies.
_WORD_RUN_RE = re.compile(r"[^\W\d_]{2,}", re.UNICODE)


def _carries_word(text: str) -> bool:
    """True when a span holds a word: two adjacent letters, or one non-Latin letter."""
    return bool(_WORD_RUN_RE.search(text)) or any(ch.isalpha() and ord(ch) > 127 for ch in text)


# A boundary needs whitespace then something that can open a sentence: a capital
# or digit, an opening delimiter, a CLI flag (`--no-examples`), a slash-command
# (`/orient`), an arrow/dash item, a lower-then-upper identifier (`macOS`), or
# any non-ASCII letter or symbol.
_AFTER_RE = re.compile(
    r"\s+(?=[\"'\u201c(\[{*_`A-Z0-9]"  # capital, digit, or opening delimiter
    r"|--?[a-zA-Z]"  # CLI flag
    r"|/+[a-zA-Z]"  # slash-command
    r"|[\u2192\u2022]|-{1,2}\s"  # arrow / bullet / dash item
    r"|\+\s"  # plus-marked list item
    r"|~[\d/]"  # approximate quantity or home path (`~90 min`, `~/.kube`)
    r"|\\[A-Za-z_]"  # namespaced class reference (`\Drupal::service(...)`)
    r"|[a-z]+[A-Z]"  # lower-then-upper identifier
    r"|[a-z][\w-]{2,}[._/][\w.-]"  # separator-carrying identifier (`page.html.twig:9`)
    r"|[<>]=?\s*[.\w]"  # comparison, block marker, or component tag (`<.input>`)
    r"|(?<=[A-Z]!)\s*[a-z]"  # lowercase sentence after a shouted `!`
    r"|\.[A-Za-z_\\/]"  # dot-method, dotfile, or relative path (`./install.sh`)
    r"|:\s"  # legend row whose subject is the colon itself (`: on Unix, ; on Windows`)
    r"|![A-Za-z]"  # shell-bang command (`!ls`, `!git status`)
    r"|&[A-Z]"  # ampersand-led reference; a capital rules out `&amp;`
    r"|#+\s*\S"  # issue ref, attribute, heading, or comment (`#1160`, `## Outputs`)
    r"|%\w"  # batch/template variable (`%var% immediate`)
    r"|/{2,}\s*\S"  # code comment opener (`// This satisfies ...`)
    r"|@[A-Za-z_]"  # at-rule or annotation opener (`@import`, `@FieldFormatter`)
    r"|\$[A-Za-z0-9_]"  # shell or template variable (`$1 = --here`, `$xmlns`)
    r"|<!--"  # HTML comment opener
    r"|[^\x00-\x7f])"  # any non-ASCII letter or symbol
)

# A closing bracket immediately before the terminator ends a sentence decisively
# (`… (stricter score wins). >20pt divergence …`), so any opener may follow —
# including a lowercase identifier or a bare symbol.
_CLOSED_BEFORE_TERM_RE = re.compile(r"[)\]}][\"'\u201d\u2019]?$")
_AFTER_ANY_RE = re.compile(r"\s+(?=\S)")

# A lowercase run may open a sentence when it is a code identifier. Only the
# caller's code-token set tells that apart from a mid-sentence continuation, so
# this fires only when that set is supplied.
_AFTER_LOWER_RE = re.compile(r"\s+(?=[a-z])")
# The identifier-shaped head of the run following a candidate boundary.
_NEXT_TOKEN_RE = re.compile(r"[A-Za-z0-9_./-]+")

_INITIAL_RE = re.compile(r"(?:^|\s)[A-Z]\.$")
# The trailing word itself, without any opening delimiter glued to it — `(e.g.`
# must look up as `e.g.` or the abbreviation veto misses every parenthesised one.
_LAST_TOKEN_RE = re.compile(r"[A-Za-z][\w.]*\.$")
_ABBREV_CAP_FOLLOWS_RE = re.compile(r"\s*[\"'\u201c]?[A-Z]")

_QUOTE_PAIRS = (('"', '"'), ("\u201c", "\u201d"))
_QUOTE_OPENS_AFTER = "([{\u2014\u2013>*_"
_QUOTE_CLOSES_BEFORE = ".,;:!?)]}\u2014\u2013"
# A terminator followed by whitespace and a capital, inside a quotation, means
# the quotation holds more than one sentence.
_INTERNAL_BOUNDARY_RE = re.compile(r"(?<!\.)[.!?][\"'\u201d\u2019)\]]?\s+[\"'\u201c]?[A-Z]")

# A space-flanked terminal mark is an operator or a marker, never punctuation:
# an elision (`not cancelled … the job is running`), a ternary `?`, a shell `!`, a
# concatenation dot. Prose never puts whitespace before its own terminator.
_SPACED_TERM_RE = re.compile(r"(?<=\s)[.!?…]+$")
# An ellipsis run — bare or closed by a quote/bracket — elides content rather
# than ending a statement, unless a fresh capitalised sentence follows.
_ELLIPSIS_TERM_RE = re.compile(r"(?:\.{2,}|\u2026)[\"'\u201d\u2019)\]]*$")
# A bare `.` is a path argument (`git add .`), a flag value (`-bench=.`), or an
# escaped regex dot (`\.`) — never a sentence terminator.
_STANDALONE_DOT_RE = re.compile(r"(?:^|\s)\.$|(?:^|\s)-{1,2}[\w-]*=\.$|(?:^|\s)\\\.$")
# An ellipsis glued to `=` stands in for an omitted value, never ends a sentence
# (`AVM_PRIVATE_KEY=... RESOURCE_SERVER_URL=…`).
_PLACEHOLDER_ELLIPSIS_RE = re.compile(r"=\.{2,}$")
_CAPITAL_FOLLOWS_RE = re.compile(r"\s+(?:[\"'\u201c(\[]?[A-Z]|\d+\.\s)")
# The closing quote is optional — the checklist form of this shape is unquoted
# (`Needs a configuration form? — Admin settings page for the API key`).
# A QUESTION closing onto a gloss or list marker continues its sentence
# (`Wrong: "What does this do?" (Everything does SOMETHING)`). A quoted
# STATEMENT (`… delusion." (Also confirmed …`) ends it, so only `?`/`!` qualify.
_QUOTED_TERM_RE = re.compile(r"(?:\?[\"'\u201d\u2019]?[)\]]?|![\"'\u201d\u2019])$")
_GLOSS_FOLLOWS_RE = re.compile(r"\s+[(\[{\u2192\u2022]|\s+-{1,2}\s|\s+[\u2013\u2014]\s|\s+[-=]>\s")

# A quoted or elided fragment followed by an EM-DASH or arrow is glossed by what
# follows (`"…should be 700." — His signature way of framing …`). A plain hyphen
# is a list marker instead, so it is deliberately excluded.
_GLOSSABLE_TERM_RE = re.compile(r"(?:[\"'\u201d\u2019\)\]]|\.{2,})$")
_EMDASH_GLOSS_RE = re.compile(r"\s+(?:[\u2013\u2014\u2192\u2022]|->|=>)\s")

# A question answered by what follows in brackets or quotes is one unit
# (`Does it need 'use client'? (Only if interactive)`), and so is a code operator
# (`??`, `?.`, `(!)`) named inline.
_QUESTION_TERM_RE = re.compile(r"\?[\"'\u201d\u2019\)\]]*$")
_ANSWER_FOLLOWS_RE = re.compile(r"\s+[(\[{]")
# A `?` whose branch is followed by ` : ` is a ternary operator.
_TERNARY_AHEAD_RE = re.compile(r"[^\n]{0,60}?\s:\s")
_CODE_OPERATOR_TERM_RE = re.compile(r"(?:\?\?|\?\.|!\)|\?\)|!!)[\"'\u201d\u2019\)\]]*$")

# A parenthetical that closed is an aside; the clause it interrupts continues.
_CLOSED_PAREN_TERM_RE = re.compile(r"[.!?\u2026]+\)$")

# A terminator sealed inside a string literal, followed by `+`, is string
# concatenation (`filter: 'group_id=eq.' + groupId`). The plus-marked list item
# this would otherwise be read as never carries the dot inside a quote.
_STRING_CLOSE_TERM_RE = re.compile(r"[.!?][\"'\u201d\u2019]$")
_CONCAT_FOLLOWS_RE = re.compile(r"\s+\+")
# `[...]` marks omitted text; it belongs to the sentence whose text was cut,
# never to the one after it (`… her identity. [...]<grok-card …`).
_ELISION_FOLLOWS_RE = re.compile(r"\s+\[\s*(?:\.{2,}|\u2026)\s*\]")

_TRAILING_PUNCT = ".,;:!?"
_OPEN_BRACKETS = "([{"
_CLOSE_BRACKETS = ")]}"


def _opens_quotation(text: str, i: int) -> bool:
    """True when the mark at `i` can open a quotation rather than close one."""
    return i == 0 or text[i - 1].isspace() or text[i - 1] in _QUOTE_OPENS_AFTER


def _closes_quotation(text: str, i: int) -> bool:
    """True when the mark at `i` can close a quotation rather than open one."""
    nxt = text[i + 1 : i + 2]
    return not nxt or nxt.isspace() or nxt in _QUOTE_CLOSES_BEFORE


def _find_span(text: str, open_ch: str, close_ch: str, start_at: int) -> tuple[int, int] | None:
    """The next closed quotation at or after `start_at`, or None."""
    symmetric = open_ch == close_ch
    start = text.find(open_ch, start_at)
    while symmetric and start >= 0 and not _opens_quotation(text, start):
        start = text.find(open_ch, start + 1)
    if start < 0:
        return None
    stop = text.find(close_ch, start + 1)
    while symmetric and stop >= 0 and not _closes_quotation(text, stop):
        stop = text.find(close_ch, stop + 1)
    return None if stop < 0 else (start, stop + 1)


def _quoted_spans(text: str) -> list[tuple[int, int]]:
    """Return `(start, stop)` for each closed quotation, inclusive of its marks.

    A straight `"` is its own closing mark, so pairing them left-to-right without
    checking position mis-reads a sentence-final `instructions."` as an OPENING
    quote and masks the real boundary that follows it. Position decides: an
    opener abuts whitespace or an opening delimiter on its left, a closer abuts
    whitespace or trailing punctuation on its right.
    """
    spans: list[tuple[int, int]] = []
    for open_ch, close_ch in _QUOTE_PAIRS:
        i = 0
        while i < len(text):
            span = _find_span(text, open_ch, close_ch, i)
            if span is None:
                break
            spans.append(span)
            i = span[1]
    return spans


def _mask_protected_shapes(text: str, mask: list[bool]) -> None:
    """Mask identifier-shaped runs, releasing a swallowed sentence terminator."""
    for m in _PROTECT_RE.finditer(text):
        # The greedy shape match eats a trailing terminator: in
        # `scripts/pre-release-check.sh. Do not …` that final period ends the
        # sentence and is not part of the path, so give it back.
        end = m.end()
        while (
            end > m.start() and text[end - 1] in _TRAILING_PUNCT and (end >= len(text) or text[end : end + 1].isspace())
        ):
            end -= 1
        for i in range(m.start(), end):
            mask[i] = True


def _mask_bracketed(text: str, mask: list[bool]) -> None:
    """Mask each bracket pair that closes and holds a single sentence.

    Only closed pairs are considered: an unclosed `(` would otherwise poison the
    remainder of the run and swallow every later boundary. A pair spanning
    several sentences stays cuttable for the same reason a multi-sentence
    quotation does — each sentence inside it carries its own instruction.
    """
    stack: list[int] = []
    for i, ch in enumerate(text):
        if ch in _OPEN_BRACKETS:
            stack.append(i)
        elif ch in _CLOSE_BRACKETS and stack:
            start = stack.pop()
            if _INTERNAL_BOUNDARY_RE.search(text[start : i + 1]):
                continue
            for j in range(start, i + 1):
                mask[j] = True


def _mask_single_sentence_quotes(text: str, mask: list[bool]) -> None:
    """Mask quotations that hold one sentence; leave multi-sentence ones cuttable.

    A short inline quotation is one unit. A quotation spanning several sentences
    carries one instruction per sentence, and merging them would keep only the
    first one's charge.
    """
    for start, stop in _quoted_spans(text):
        if not _INTERNAL_BOUNDARY_RE.search(text[start:stop]):
            for i in range(start, stop):
                mask[i] = True


def _protected_mask(text: str) -> list[bool]:
    """Build a per-character mask: True where no sentence boundary may fall."""
    mask = [False] * len(text)
    _mask_protected_shapes(text, mask)
    _mask_bracketed(text, mask)
    _mask_single_sentence_quotes(text, mask)
    return mask


def _is_abbrev(left: str, right: str) -> bool:
    """True when the trailing token's period binds it rather than ending a sentence."""
    m = _LAST_TOKEN_RE.search(left)
    if not m:
        return False
    tok = m.group()
    # Match case-sensitively, allowing only a sentence-initial capital variant
    # (`Etc.` → `etc.`). Folding the whole token would read `CA.` as `ca.`
    # (circa) and swallow the boundary after any two-letter acronym.
    variant = tok[:1].lower() + tok[1:]
    if tok in _ABBREV_BEFORE_DIGIT:
        return bool(_DIGIT_FOLLOWS_RE.match(right))
    if tok in _ABBREV_MAY_END or variant in _ABBREV_MAY_END:
        return not _ABBREV_CAP_FOLLOWS_RE.match(right)
    return tok in _ABBREV or variant in _ABBREV or bool(_INITIAL_RE.search(left))


def _opens_with_code_token(text: str, at: int, code_tokens: frozenset[str]) -> bool:
    """True when the run starting at `at` is one of the caller's code identifiers."""
    m = _NEXT_TOKEN_RE.match(text, at)
    return m is not None and m.group() in code_tokens


def _is_vetoed(text: str, term: str, end: int) -> bool:
    """True when this terminator is punctuation-in-context, not a sentence end.

    Each clause names one shape whose terminal mark belongs to the token rather
    than to the sentence: an elision, a gloss marker, a code operator, a question
    answered in place, a path/flag dot, or a parenthetical aside.
    """
    left = text[:end]
    if _SPACED_TERM_RE.search(left) or _STANDALONE_DOT_RE.search(left) or _PLACEHOLDER_ELLIPSIS_RE.search(left):
        return True
    if _LEADING_ORDINAL_RE.search(left):
        return True
    # Nothing but the mark itself to its left — a legend cell or a truncation
    # header (`... GENERATED ALWAYS AS (<expr>) STORED`), never a sentence that
    # ended, because no sentence preceded it.
    if not left.strip(" .!?…"):
        return True
    if _CODE_OPERATOR_TERM_RE.search(term) or _CLOSED_PAREN_TERM_RE.search(term):
        return True
    glossed = (
        (_STRING_CLOSE_TERM_RE.search(term) and _CONCAT_FOLLOWS_RE.match(text, end))
        or _ELISION_FOLLOWS_RE.match(text, end)
        or (_QUOTED_TERM_RE.search(term) and _GLOSS_FOLLOWS_RE.match(text, end))
        or (_GLOSSABLE_TERM_RE.search(term) and _EMDASH_GLOSS_RE.match(text, end))
        or (_QUESTION_TERM_RE.search(term) and _ANSWER_FOLLOWS_RE.match(text, end))
        or (term.endswith("?") and _TERNARY_AHEAD_RE.match(text, end))
        # An elision glossed by a parenthetical is one unit whatever the case of
        # what follows (`"Settings..." (Cmd+,)`, `go test -race ./... (Go)`), so
        # this clause runs ahead of the capital test below.
        or (_ELLIPSIS_TERM_RE.search(term) and _ANSWER_FOLLOWS_RE.match(text, end))
    )
    if glossed:
        return True
    return bool(_ELLIPSIS_TERM_RE.search(term)) and not _CAPITAL_FOLLOWS_RE.match(text, end)


def _sentence_start(text: str, m: re.Match[str], end: int, code_tokens: frozenset[str]) -> re.Match[str] | None:
    """The whitespace run opening the next sentence, or None when none does."""
    after = _AFTER_RE.match(text, end)
    if after:
        return after
    if _CLOSED_BEFORE_TERM_RE.search(text[: m.start()]):
        return _AFTER_ANY_RE.match(text, end)
    # An identifier may open a sentence after a full stop, but a `!` followed by
    # a lowercase run is a shell bang or a doc-comment marker (`//! crate doc`,
    # `!git log`) unless the shout ended a real sentence (`READY! now run …`),
    # which `_AFTER_RE` already covers with its capital-before-`!` lookbehind.
    if code_tokens and not m.group().endswith("!"):
        lower = _AFTER_LOWER_RE.match(text, end)
        if lower and _opens_with_code_token(text, lower.end(), code_tokens):
            return lower
    return None


def _cut_offsets(text: str, mask: list[bool], code_tokens: frozenset[str]) -> list[int]:
    """Offsets at which a new sentence starts."""
    cuts: list[int] = []
    for m in _TERM_RE.finditer(text):
        end = m.end()
        # Test the veto AFTER the terminator group: a sentence-final period
        # inside a closing quote (`… "the rules." Do not …`) sits in a quoted
        # region, but that region closes with it and is spent.
        if end >= len(text) or mask[end] or _is_vetoed(text, m.group(), end):
            continue
        after = _sentence_start(text, m, end, code_tokens)
        if after is None or _is_abbrev(text[:end], text[end:]):
            continue
        cuts.append(after.end())
    return cuts


def _drop_contentless_cuts(text: str, cuts: list[int]) -> list[int]:
    """Drop each cut that would open a segment carrying no letter or digit.

    A cut whose right side is a bare marker (`✔`, `»`, a lone arrow) invents a
    unit with no instruction in it. The marker decorates the sentence it follows,
    so it stays with that sentence. Dropping the cut rather than re-joining the
    strings keeps every emitted segment a verbatim slice of the source. A word is
    what makes a span content — a number carries meaning only through the words
    around it, so a bare figure is a marker too.
    """
    bounds = [*cuts, len(text)]
    return [cut for i, cut in enumerate(cuts) if _carries_word(text[cut : bounds[i + 1]])]


def split_prose_sentences(text: str, code_tokens: Iterable[str] | None = None) -> list[str]:
    """Split a prose run into whole sentences (no sub-sentence fragments).

    `code_tokens` optionally names the run's code identifiers (an atom's
    backtick-wrapped tokens). Supplying them lets a lowercase identifier open a
    sentence — `PASS. pytest exits non-zero` splits only when `pytest` is known
    to be an identifier rather than an ordinary word.

    Returns the trimmed non-empty sentences. A run with no internal sentence
    boundary returns a single-element list, so the caller keeps the atom whole.
    """
    text = text.strip()
    if not text:
        return []
    mask = _protected_mask(text)
    cuts = _drop_contentless_cuts(text, _cut_offsets(text, mask, frozenset(code_tokens or ())))
    if not cuts:
        return [text]
    bounds = [0, *cuts, len(text)]
    out = [text[bounds[i] : bounds[i + 1]].strip() for i in range(len(bounds) - 1)]
    return [s for s in out if s]
