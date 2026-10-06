"""Instructions in a sentence — where a sentence gives more than one, and where each one starts.

A clause gives an instruction when it opens with a command: a prohibition, or a verb telling the
reader what to do. A sentence holding two such clauses holds two instructions, whatever joins them
(a comma, a semicolon, a spaced dash, `and`, `then`).
"""

from __future__ import annotations

import re

from reporails_cli.core.mapper.classify import (
    _VERBS_AMBIGUOUS,
    _VERBS_CORE,
    _VERBS_SUPPLEMENT,
    is_conditional_frame,
)
from reporails_cli.core.mapper.markers import without_list_marker
from reporails_cli.core.mapper.md_parser import code_spans, leading_bold_run
from reporails_cli.core.mapper.parse import _SEE_POINTER_RE, _build_scope_mask
from reporails_cli.core.platform.dto.ruleset import LIST_OBJECT_ROLE, Atom

# Where a sentence can start another clause: a semicolon, a comma, a spaced dash, or a bare `and` / `then`.
_CLAUSE_CUT_RE = re.compile(r"[;,]\s+|\s+[\u2014\u2013]\s+|\s+(?:and|then)\s+", re.IGNORECASE)
_LEAD_CONNECTOR_RE = re.compile(r"^(?:(?:and|but|or|then|also|so|always|only|just|please|first)\s+)+", re.IGNORECASE)
# A plain word label before the instruction (`Note:`) introduces it; it gives no command itself.
_LEAD_LABEL_RE = re.compile(r"^[A-Za-z][\w-]*:\s+")
_SPACES_RE = re.compile(r"\s+")
_NEGATION_ONSET_RE = re.compile(r"(?:do not|don't|never|avoid|refrain from)\b", re.IGNORECASE)
# `never` before what it excludes (`…, never the two-file base`) closes a contrast; it forbids nothing.
_CONTRAST_RE = re.compile(r"never\s+(?:the|a|an|this|that|these|those|one)\b", re.IGNORECASE)
_WORD_RE = re.compile(r"[`\w'\-/.]+")
# Words that also name tools (`find`, `make`, `mock`) join the words that are also nouns (`format`, `test`,
# `build`): either opens a command only with its object after it.
_TOOL_NAMES = frozenset({"find", "make", "mock"})
# Command verbs the shared charge lexicon does not carry, that a packed sentence's second
# clause still needs recognised to find where it starts (`Bump the version and update the
# changelog.`) — a split-boundary decision this module owns, not a charge decision the
# shared lexicon owns, so the gap is closed here rather than by widening `classify`'s sets.
_UNLEXICONED_COMMAND_VERBS = frozenset(
    {
        "bump",
        "debug",
        "escape",
        "label",
        "lock",
        "merge",
        "pin",
        "publish",
        "rebase",
        "reload",
        "restore",
        "rewrite",
        "ship",
        "sign",
        "squash",
        "tag",
        "trim",
        "upgrade",
    }
)
_COMMAND_VERBS = frozenset(_VERBS_CORE | _VERBS_SUPPLEMENT | _UNLEXICONED_COMMAND_VERBS) - _TOOL_NAMES
_NOUN_OR_VERB = frozenset(_VERBS_AMBIGUOUS | _TOOL_NAMES)
_OBJECT_OPENERS = frozenset(
    {"the", "a", "an", "it", "them", "this", "that", "these", "those", "every", "all", "each", "any", "your", "its"}
    | {"sure"}
)
# `to install`, `to build`: the verbs listed after it say what the one instruction is for.
_PURPOSE_RE = re.compile(r"\bto\s+([a-z]+)\b", re.IGNORECASE)
_WORD_START_RE = re.compile(r"\S+")
# The `and` joining two instructions belongs to neither of them.
_JOINING_AND_RE = re.compile(r"^and\s+", re.IGNORECASE)
# `or` / `nor` closing a list after a prohibition: the items are what it forbids.
_DISJUNCTION_RE = re.compile(r"(?:^|\s)(?:or|nor)\s+", re.IGNORECASE)


def _bold_lead_label_end(text: str) -> int:
    """Where the bold label (`**Rule:**`, `**Rule**:`) that opens `text` ends, with the space after it,
    or 0 when `text` opens with none."""
    run = leading_bold_run(text)
    if run is None:
        return 0
    end = run.end
    if not text[run.content_start : run.content_end].endswith(":"):
        if text[end : end + 1] != ":":
            return 0
        end += 1
    gap = _SPACES_RE.match(text, end)
    return gap.end() if gap else 0


def _is_bold_label(clause: str) -> bool:
    """Whether the clause is only a bold label, which titles what follows a dash (`**Update narrative** — update …`)."""
    run = leading_bold_run(clause)
    return run is not None and run.end == len(clause)


def without_lead(text: str) -> str:
    """The text without its list marker, checkbox and lead label, none of which gives a command.

    A label before the instruction (`Note:`, `**Rule:**`) introduces it.
    """
    text = without_list_marker(text)
    label_end = _bold_lead_label_end(text)
    return text[label_end:] if label_end else _LEAD_LABEL_RE.sub("", text)


def _clause_text(clause: str) -> str:
    """The clause without its list marker, lead label and emphasis."""
    return without_lead(clause).strip(" *_")


def _opens_command(clause: str, *, sequenced: bool = False) -> bool:
    """Whether a clause starts with a command: a prohibition, or a verb telling the reader what to do.

    A clause of one bare word is a command only when `then` sets it after another (`…, then commit.`);
    otherwise it is an item of a list.
    """
    text = _LEAD_CONNECTOR_RE.sub("", _clause_text(clause))
    if _NEGATION_ONSET_RE.match(text):
        return _CONTRAST_RE.match(text) is None
    words = _WORD_RE.findall(text)[:2]
    if not words or (len(words) < 2 and not sequenced):
        return False
    head = words[0].lower().rstrip(".!?")
    if head in _COMMAND_VERBS:
        return True
    if head not in _NOUN_OR_VERB or len(words) < 2:
        return False
    return words[1].lower().rstrip(".!?") in _OBJECT_OPENERS or words[1][0] == "`"


_PIPE_JOIN_RE = re.compile(r"\s\|\s")


def _pipe_cuts(sentence: str, inside: list[bool]) -> list[re.Match[str]]:
    """A ` | ` table-cell join, where the cell after it opens a command, as a cut.

    A row is one joined line (`Deploys | Always deploy from CI | Never deploy on Friday`);
    the label cell before the first command gives no instruction of its own and stays with
    the cell it introduces, but a cell join whose next cell opens a command is where one
    instruction ends and the row's next one begins.
    """
    return [
        m for m in _PIPE_JOIN_RE.finditer(sentence) if not inside[m.start()] and _opens_command(sentence[m.end() :])
    ]


def _cut_mask(sentence: str) -> list[bool]:
    """Where a comma or dash belongs to an aside, an example or a command: inside quotes, parentheses or
    a code span."""
    inside = _build_scope_mask(sentence)
    for span in code_spans(sentence):
        inside[span.start : span.end] = [True] * (span.end - span.start)
    return inside


def _states_purpose(clause: str) -> bool:
    """Whether the clause says what it is for with `to` and a verb (`Use uv to install packages`)."""
    return any(m.group(1).lower() in _COMMAND_VERBS | _NOUN_OR_VERB for m in _PURPOSE_RE.finditer(clause))


def _boundary(cut: re.Match[str]) -> int:
    """Where the next instruction's text begins: after a comma, semicolon or dash; before a joining word."""
    joined_by_word = cut.group().strip().lower() in {"and", "then"}
    return cut.start() + len(cut.group()) - len(cut.group().lstrip()) if joined_by_word else cut.end()


def _clauses(sentence: str) -> list[tuple[int, str, str]]:
    """Each clause as ``(where its text begins, its text, the joint before it)``.

    A comma or dash inside quotes, parentheses or a code span starts no clause.
    """
    inside = _cut_mask(sentence)
    cuts = sorted(
        [m for m in _CLAUSE_CUT_RE.finditer(sentence) if not inside[m.start()]] + _pipe_cuts(sentence, inside),
        key=lambda m: m.start(),
    )
    clauses: list[tuple[int, str, str]] = []
    prev: re.Match[str] | None = None
    for m in [*cuts, None]:
        text = sentence[prev.end() if prev else 0 : m.start() if m else len(sentence)]
        clauses.append((_boundary(prev) if prev else 0, text, prev.group() if prev else ""))
        prev = m
    return clauses


def _is_prohibition(clause: str) -> bool:
    text = _LEAD_CONNECTOR_RE.sub("", _clause_text(clause))
    return _NEGATION_ONSET_RE.match(text) is not None and _CONTRAST_RE.match(text) is None


def _titles_next(clauses: list[tuple[int, str, str]], k: int) -> bool:
    """Whether clause `k` is only a bold label and a dash joins it to the clause it titles."""
    return (
        k + 1 < len(clauses)
        and _is_bold_label(clauses[k][1].strip())
        and clauses[k + 1][2].strip() in ("\u2014", "\u2013")
    )


def _joins_actions(clause: str) -> bool:
    """Whether `or` / `nor` in the clause closes a list of actions: it opens the clause (`or share tokens`) or
    joins something other than an object (`push keys or share tokens`, not `open a branch or a fork`)."""
    for m in _DISJUNCTION_RE.finditer(clause):
        after = _WORD_RE.findall(clause[m.end() :])[:1]
        if m.start() == 0 or (after and after[0].lower() not in _OBJECT_OPENERS):
            return True
    return False


def _prohibited_items(clauses: list[tuple[int, str, str]]) -> set[int]:
    """The clauses that list what a prohibition forbids (`Do not commit secrets, push keys, or share tokens`).

    After a prohibition, comma-joined clauses closed by `or` / `nor` are its items, not instructions of their
    own; a semicolon, a dash, `and`, `then` or another prohibition ends the list. Where the list and a stated
    alternative read alike (`never edit it, run make gen or make all`), the clauses stay with the prohibition.
    """
    items: set[int] = set()
    i = 0
    while i < len(clauses):
        j = i + 1
        if _is_prohibition(clauses[i][1]):
            while j < len(clauses) and clauses[j][2].strip() == "," and not _is_prohibition(clauses[j][1]):
                j += 1
            if j > i + 1 and _joins_actions(clauses[j - 1][1]):
                items.update(range(i + 1, j))
        i = j
    return items


def _sets_condition(clause: str) -> bool:
    """Whether the clause is a condition that gives no command (`when the build fails`)."""
    return is_conditional_frame(_LEAD_CONNECTOR_RE.sub("", _clause_text(clause))) and not _opens_command(clause)


def _acts_on_an_object(clause: str) -> bool:
    """Whether the clause's first word is followed by what it acts on (`push the tag`, `run `pytest``)."""
    words = _WORD_RE.findall(_LEAD_CONNECTOR_RE.sub("", _clause_text(clause)))[:2]
    return len(words) == 2 and (words[1].lower() in _OBJECT_OPENERS or words[1][0] == "`")


def _closes_item_list(clauses: list[tuple[int, str, str]], k: int) -> bool:
    """Whether clause ``k`` is the last, `and`-joined item of a list of things that are not commands
    (`Preserve `id`, `slug`, and coordinate fields`); a closing clause that acts on an object
    (`…, and push the tag`) is an instruction of its own."""
    if k < 2:
        return False
    _, clause, joint = clauses[k]
    _, prev, prev_joint = clauses[k - 1]
    joined_by_and = joint.strip().lower() == "and" or _JOINING_AND_RE.match(clause.strip()) is not None
    listed = prev_joint.strip() == "," and not _opens_command(prev) and not _sets_condition(prev)
    return joined_by_and and listed and not _acts_on_an_object(clause)


def _with_condition(clauses: list[tuple[int, str, str]], k: int) -> int:
    """Where instruction ``k`` begins: at the conditions set just before its command (`if they fail, fix them`)."""
    j = k
    while j > 0 and _sets_condition(clauses[j - 1][1]):
        j -= 1
    return clauses[j][0]


def instruction_starts(sentence: str) -> list[int]:
    """The offset where each instruction of the sentence starts, one per clause that opens with a command.

    Verbs listed after `to` (`Use uv to install packages, add dependencies, and run scripts`) say what one
    instruction is for, until a semicolon, a `then` or a prohibition starts the next; what a prohibition
    lists stays part of it, and so does the `and`-joined last item of a list. A condition set before a
    command (`…; when the build fails, run it again`) starts the instruction it leads into. What a
    `See …` pointer names runs to the next punctuation (`See the build and deploy guide`).
    """
    clauses = _clauses(sentence)
    items = _prohibited_items(clauses)
    starts: list[int] = []
    purpose = titled = False
    for k, (_, clause, joint) in enumerate(clauses):
        sequenced = "then" in joint.lower() or re.match(r"\s*then\b", clause, re.IGNORECASE) is not None
        purpose = purpose and ";" not in joint and not sequenced and not _is_prohibition(clause)
        titled = titled and joint.strip().lower() == "and"
        listed = k in items or purpose or titled or _closes_item_list(clauses, k) or _titles_next(clauses, k)
        if clause and not listed and _opens_command(clause, sequenced=sequenced):
            starts.append(_with_condition(clauses, k))
        purpose = purpose or _states_purpose(clause)
        titled = titled or _SEE_POINTER_RE.match(_LEAD_CONNECTOR_RE.sub("", _clause_text(clause))) is not None
    return starts


def instruction_count(sentence: str) -> int:
    """How many instructions a sentence gives: the clauses that each start with a command."""
    return len(instruction_starts(sentence))


def instruction_word_cuts(sentence: str) -> list[int]:
    """The word index where each instruction after the first begins.

    Text before the first instruction (`Before merging, run the tests`) and a clause that gives no command
    stay with the instruction they lead into or follow.
    """
    return [len(sentence[:start].split()) for start in instruction_starts(sentence)[1:]]


def cut_at_words(text: str, cuts: list[int]) -> list[str]:
    """``text`` cut before each word index in ``cuts``; every piece is a verbatim slice of ``text``."""
    words = [m.start() for m in _WORD_START_RE.finditer(text)]
    bounds = [0, *(words[k] for k in cuts if 0 < k < len(words)), len(text)]
    pieces = (text[bounds[i] : bounds[i + 1]].rstrip() for i in range(len(bounds) - 1))
    return [p for p in pieces if p.strip()]


def instruction_texts(sentence: str, written: str | None = None) -> list[str]:
    """The sentence's instructions, in order, each a verbatim slice of ``sentence``; together they cover it.

    ``written`` is the same sentence with its markdown (code spans, emphasis) when ``sentence`` is the plain
    reading of it: where each instruction starts is read there, so a comma inside a code span never cuts,
    and the cut lands on the same word of ``sentence``.
    """
    source = written if written is not None and len(written.split()) == len(sentence.split()) else sentence
    return cut_at_words(sentence, instruction_word_cuts(source))


def without_joining_word(instruction: str) -> str:
    """The instruction without the `and` that joins it to the one before, which belongs to neither."""
    return _JOINING_AND_RE.sub("", instruction)


_LIST_FORMATS = frozenset({"list", "numbered"})


def _list_after(atoms: list[Atom], k: int) -> list[Atom]:
    """The list nested under the lead-in ``atoms[k]``: the list items after it, deeper than it, each
    starting within two lines of the one before."""
    lead = atoms[k]
    items: list[Atom] = []
    last = lead.line
    for atom in atoms[k + 1 :]:
        if (
            atom.kind == "heading"
            or atom.format not in _LIST_FORMATS
            or atom.list_depth <= lead.list_depth
            or atom.line > last + 2
        ):
            break
        items.append(atom)
        last = atom.line
    return items


def _gives_command(atom: Atom) -> bool:
    return atom.charge_value != 0 or _opens_command(atom.text)


def fold_lead_ins(atoms: list[Atom]) -> list[Atom]:
    """One file's atoms with each instruction that introduces a list of things read together with it.

    An instruction ending with a colon, followed by a list none of whose items gives a command, is one
    instruction with the list as its object (`Audit these surfaces:` and the files): each item line counts
    as one word of it, as a code span does, and a named item names it. The items stay lines of their file,
    marked as its object (`LIST_OBJECT_ROLE`), and take no place of their own among the file's instructions
    and context. A list that gives commands is left as it is: each command is an instruction of its own.
    """
    for k, lead in enumerate(atoms):
        if not lead.lead_in or lead.charge_value == 0 or lead.role == LIST_OBJECT_ROLE:
            continue
        items = _list_after(atoms, k)
        if not items or any(_gives_command(item) for item in items):
            continue
        lead.token_count += len({item.line for item in items})
        lead.named_tokens = list(dict.fromkeys([*lead.named_tokens, *(t for item in items for t in item.named_tokens)]))
        if any(item.specificity == "named" for item in items):
            lead.specificity = "named"
        for item in items:
            item.role = LIST_OBJECT_ROLE
    return atoms
