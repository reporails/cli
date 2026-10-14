"""Fixed charge rules for lines whose shape decides their charge.

Shape checks that mark a line as structural or as a non-instruction opener (a meta label,
a `See ...` pointer, a third-person description, a past-tense narration), and the floors
that apply those determinations to an atom's charge.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from reporails_cli.core.mapper.classify import (
    best_to_sign,
    classify_charge,
    hedges_with_lead,
    hedges_with_phrase,
    hedges_with_should,
)
from reporails_cli.core.mapper.classify_lexicon import ALL_VERBS, WORD_RE
from reporails_cli.core.mapper.classify_no import is_terse_no_prohibition, starts_bare_no_status
from reporails_cli.core.mapper.md_parser import code_spans, leading_bold_run
from reporails_cli.core.platform.dto.ruleset import Atom
from reporails_cli.core.platform.policy.negative_headings import in_negative_section

# Rule trace of a table header row: a column-label row, kept neutral.
TABLE_HEADER_RULE = "table_header"

# A line that IS a quotation: opens with a quote mark and the matching close mark ends
# it (trailing punctuation allowed). A line that merely opens with a quoted term and
# goes on — `"Dry run" is a flag; pass it early` — is running text
# and keeps whatever charge it carries.
_QUOTED_LINE_RE = re.compile(r'^["\u201c\u201e][^"\u201c\u201d\u201e]*["\u201c\u201d]\s*[.,;:!?]*\s*$')


def is_quoted_line(text: str) -> bool:
    """True when the whole line is one quotation (a sample, not an instruction)."""
    return _QUOTED_LINE_RE.match(text) is not None


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
    return starts_bare_no_status([w.lower() for w in WORD_RE.findall(plain)])


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
    if len(label_words) > 1 and any(w.lower() in ALL_VERBS for w in label_words):
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
    return m is not None and m.group(0).lower() in ALL_VERBS


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
    if tail is None or any(ch.isspace() for ch in term) or term.lower() in ALL_VERBS:
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
        is_quoted_line(md_text)
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
    if word not in _RIDING_DEONTICS and word not in ALL_VERBS:
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
        if not is_terse_no_prohibition([w.lower() for w in WORD_RE.findall(plain)]):
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
    """Read an instruction given with `should`, opening with a hedge word (`Prefer …`, `Try
    to …`, `Perhaps …`), or carrying `where possible` / `It's best (not) to …`, as hedged.

    `You should run the linter first` recommends rather than requires, so a charged atom whose text
    hedges that way (:func:`~reporails_cli.core.mapper.classify.hedges_with_should`, a hedge lead,
    `where possible`, `It's best (not) to …`) takes modality `hedged`. `might` and `could` keep the
    modality the atom has. The one charge it sets is on a running-text `It's best to <verb> …` (or
    `… best not to …`) atom that carries none: that lead is an instruction, so it takes its direction.
    """
    for atom in atoms:
        text = atom.plain_text or atom.text
        sign = best_to_sign(atom.text)
        if sign and atom.charge_value == 0 and atom.kind != "heading" and not _is_structural(atom.text, atom.format):
            atom.charge, atom.charge_value = ("DIRECTIVE", 1) if sign > 0 else ("CONSTRAINT", -1)
            atom.modality = "hedged"
        if atom.charge_value != 0 and (
            hedges_with_should(text) or hedges_with_lead(text) or hedges_with_phrase(atom.text)
        ):
            atom.modality = "hedged"
