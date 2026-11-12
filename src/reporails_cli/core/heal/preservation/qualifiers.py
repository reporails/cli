"""Words a rewrite puts into an instruction that restrict what it covers: a qualifier or a new
head noun on a prohibition's forbidden noun, a `for` phrase it never had, and a list of kinds it
never named."""

from __future__ import annotations

import difflib
import re
from collections.abc import Set as AbstractSet

from reporails_cli.core.heal.preservation.words import NEGATION_RE, WORD_RE, word_forms
from reporails_cli.core.mapper.classify_lexicon import (
    CONDITION_CONJUNCTIONS,
    DEFINITE_DETERMINERS,
    DETERMINERS,
    GENERAL_QUANTIFIERS,
    INDEFINITE_ARTICLES,
    PHRASE_PREPOSITIONS,
    STOPWORDS,
)
from reporails_cli.core.mapper.lexical import CLAUSE_DASH_RE, DASH_PAIR_RE
from reporails_cli.core.mapper.md_parser import replace_code_spans
from reporails_cli.core.platform.dto.heal import Pair, RewriteWords, Section

# Quantifiers a `for` may open without cutting what a rule covers (`For each file, run lint`).
_FOR_QUANTIFIERS = DETERMINERS & GENERAL_QUANTIFIERS


def _content(words: list[str]) -> list[str]:
    """The content words of `words`: longer than two letters and not a function word."""
    return [w for w in words if len(w) > 2 and w not in STOPWORDS]


def _known_qualifier(words: list[str], known: AbstractSet[str]) -> bool:
    """Whether `words` hold content words and every one of them is a word of the author's line."""
    content = _content(words)
    return bool(content) and all(w in known for w in content)


def _sentence_words(p: Pair) -> tuple[list[str], list[str]]:
    """The lowered words of the author's sentence and of its rewrite."""
    return [w.lower() for w in WORD_RE.findall(p.old_sentence)], [w.lower() for w in WORD_RE.findall(p.new_sentence)]


def _new_head_noun(new: list[str], j1: int, j2: int) -> bool:
    """Whether the words inserted at `new[j1:j2]` open a noun phrase of their own (an indefinite
    article and a content word) placed before what the sentence already named, which then reads as
    an example of the new phrase (`treat a memory` -> `treat a prior orientation — a memory`)."""
    span = new[max(j1 - 1, 0) : j2 + 1]
    return bool(INDEFINITE_ARTICLES & set(span)) and bool(_content(new[j1:j2])) and new[j2] not in PHRASE_PREPOSITIONS


_LIST_RE = re.compile(r",|\b(?:or|and)\b")


def _keep_list_aside(match: re.Match[str]) -> str:
    """The text between two dashes as an aside when it holds a list (`— X, Y, or Z —`); two clauses
    (`— prefer a fake —`) stay cut."""
    inner = match.group(1)
    return f" {inner} " if _LIST_RE.search(inner) else match.group(0)


def _negated_words(sentence: str) -> set[str]:
    """The lowered words of the parts of `sentence` (cut at `;`, `:` and a single dash) that hold
    its negation: a clause after the dash (`Do not use a mock — prefer a fake`) is not what it
    forbids, while a list between two dashes stays in its clause. An unspaced en dash or hyphen
    (`client-server`, a number range) cuts nothing."""
    text = DASH_PAIR_RE.sub(_keep_list_aside, sentence)
    text = CLAUSE_DASH_RE.sub("\n", text.replace(";", "\n").replace(":", "\n"))
    return {w.lower() for part in text.split("\n") if NEGATION_RE.search(part) for w in WORD_RE.findall(part)}


def qualified_general_noun(p: Pair, known: set[str]) -> bool:
    """Whether a prohibition's rewrite restricts what it forbids: content words put into its
    sentence anywhere but after a definite reference (`the linter` -> `the ruff linter` names what
    the sentence already pointed at), from words that stand elsewhere on the line (`known`) —
    `file plans` -> `file X or Y plans`, `present a menu` -> `present a UX recommendation as a
    menu`; a forbidden noun replaced by such words (`file plans` -> `file X or Y`); or a new noun
    phrase put before what it forbade (`treat a memory` -> `treat a prior orientation — a memory`).
    Words the rewrite only moved within the sentence to label what it lists restrict nothing
    (`modify X — those are Y` -> `modify Y: X`); an aside moved in front of the noun does
    (`modify the docs — those are generated` -> `modify generated docs`)."""
    if not NEGATION_RE.search(p.new_sentence):
        return False
    old, new = _sentence_words(p)
    ops = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
    removed = {w for _, i1, i2, _, _ in ops if i1 < i2 for w in _content(old[i1:i2])}
    moved = removed if ":" in p.new_sentence and ":" not in p.old_sentence else set()
    words = RewriteWords(frozenset(known), frozenset(moved), frozenset(_negated_words(p.new_sentence)))
    return any(
        _op_restricts(tag, old[i1:i2], new, (j1, j2), words) for tag, i1, i2, j1, j2 in ops if j1 > 0 and j2 < len(new)
    )


def _op_restricts(tag: str, old_span: list[str], new: list[str], at: tuple[int, int], words: RewriteWords) -> bool:
    """Whether one diff op of a prohibition's rewrite (`tag`, the author's words `old_span`, the
    rewrite's words `new[at]`) restricts what it forbids; a replaced article (`the docs` ->
    `generated docs`) puts words in as an insert does."""
    j1, j2 = at
    added = new[j1:j2]
    dropped = _content(old_span)
    content = set(_content(added))
    if tag == "equal" or not added or not content <= words.negated:
        return False
    if tag == "replace" and dropped:
        return not set(dropped) & set(added) and _known_qualifier(added, words.known)
    if words.moved and content <= words.moved:
        return False
    if new[j1 - 1] not in DEFINITE_DETERMINERS and _known_qualifier(added, words.known):
        return True
    return _new_head_noun(new, j1, j2)


# Words after a fronted `for` / scope preposition that make it an aside, not a scope (`For example,`,
# `In general,`).
FOR_ASIDES = frozenset({"example", "instance"})
NOT_A_SCOPE = FOR_ASIDES | frozenset(
    {"general", "short", "particular", "practice", "summary", "addition", "fact", "times"}
)
_SEE_ASIDE_RE = re.compile(r"\(\s*see\b[^)]*\)", re.IGNORECASE)
_TOKEN_EDGES = ".,;:()[]*_\"'\u2014"


def _prose_tokens(sentence: str) -> list[str]:
    """The lowered whitespace tokens of `sentence` outside code spans, a hyphenated word kept whole
    (`ready-for-review` holds no `for`), a `(see …)` reference aside left out."""
    text = _SEE_ASIDE_RE.sub(" ", replace_code_spans(sentence, " code "))
    return [t.strip(_TOKEN_EDGES).lower() for t in text.split()]


def for_phrase_added(p: Pair) -> bool:
    """Whether the rewrite gives the instruction a `for` phrase its author's sentence had none of:
    what the verb covers is cut down to the phrase (`add tests under tests/` -> `add tests for src/
    under tests/`); a `for` in code or before a quantifier (`For each file, run lint`) cuts nothing."""
    old, new = _prose_tokens(p.old_sentence), _prose_tokens(p.new_sentence)
    if "for" in old:
        return False
    leads = _FOR_QUANTIFIERS | FOR_ASIDES
    return any(w == "for" and i + 1 < len(new) and new[i + 1] not in leads for i, w in enumerate(new))


# Words that make a list a set of examples rather than the whole of what a rule covers.
_EXAMPLE_LEADS = frozenset({"such", "e", "g", "eg", "including", "like", "example", "examples"})


def _extends_author_noun(new: list[str], j1: int, j2: int, named: set[str]) -> bool:
    """Whether the words inserted at `new[j1:j2]` only add bare alternatives to the author's own
    noun before them (`secrets` -> `secrets or credentials`, `secrets, keys or credentials`): a
    content word of the author's sentence, then words that are all `or`, `and` or content words
    (`repo` -> `repo name or a per-repo segment` has function words and is a list of its own)."""
    noun = new[j1 - 1]
    if not _content([noun]) or not word_forms(noun) & named:
        return False
    return all(w in CONDITION_CONJUNCTIONS or (len(w) > 2 and w not in STOPWORDS) for w in new[j1:j2])


def kinds_listed(p: Pair) -> bool:
    """Whether a prohibition's rewrite lists, joined by `or`, kinds its author's sentence did not
    name, which then read as all the rule forbids (`file plans` -> `file any plan — X, Y, or Z`); an
    `or` list put right after the author's own noun keeps it as an alternative (`commit secrets` ->
    `commit secrets or credentials`) and widens the rule; a
    list led by `such as`, `e.g.` or `including` gives examples and restricts nothing."""
    if not NEGATION_RE.search(p.new_sentence):
        return False
    old, new = _sentence_words(p)
    named = set(old) | {f for w in old for f in word_forms(w)}
    negated = _negated_words(p.new_sentence)
    for tag, _, _, j1, j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        added = new[j1:j2]
        if tag == "equal" or "or" not in added or _EXAMPLE_LEADS & set(new[max(j1 - 3, 0) : j2]):
            continue
        if tag == "insert" and j1 > 0 and _extends_author_noun(new, j1, j2, named):
            continue
        fresh = [w for w in _content(added) if not word_forms(w) & named]
        if fresh and set(fresh) <= negated:
            return True
    return False


_LIST_SEPARATORS = frozenset({","}) | CONDITION_CONJUNCTIONS


def _kept_tokens(text: str) -> list[str]:
    """The lowered content words of `text` in order, with a `,` kept where one stood and `and` /
    `or` kept as separators."""
    tokens: list[str] = []
    for i, part in enumerate(text.lower().split(",")):
        if i:
            tokens.append(",")
        tokens.extend(w for w in WORD_RE.findall(part) if w in _LIST_SEPARATORS or _content([w]))
    return tokens


def _phrase_starts(tokens: list[str], phrase: list[str]) -> list[int]:
    """Where `phrase` (content words, any singular / plural form) stands in `tokens`, as start indices."""
    n = len(phrase)
    return [k for k in range(len(tokens) - n + 1) if all(tokens[k + d] in word_forms(w) for d, w in enumerate(phrase))]


def _listed(tokens: list[str], phrase: list[str]) -> bool:
    """Whether `phrase` is an item of a coordinated list in `tokens` (`Lint Python, shell, or Docker`):
    a `,` / `and` / `or` stands next to it."""
    for k in _phrase_starts(tokens, phrase):
        end = k + len(phrase)
        if (k > 0 and tokens[k - 1] in _LIST_SEPARATORS) or (end < len(tokens) and tokens[end] in _LIST_SEPARATORS):
            return True
    return False


def _named_beside_others(section: Section, own_line: int, phrase: list[str]) -> bool:
    """Whether another line of `section` names `phrase` as one kind among several: as an item of a
    coordinated list, or on one of two or more lines that open with the same verb and name different
    objects (`Author Python ...`, `Author Bash hooks ...`)."""
    siblings = [_kept_tokens(s.text) for s in section.lines if s.line != own_line]
    siblings = [t for t in siblings if t]
    if any(_listed(t, phrase) for t in siblings):
        return True
    objects_by_verb: dict[str, set[str]] = {}
    for tokens in siblings:
        if len(tokens) > 1:
            objects_by_verb.setdefault(tokens[0], set()).add(tokens[1])
    return any(len(objects_by_verb[t[0]]) >= 2 and bool(_phrase_starts(t, phrase)) for t in siblings if len(t) > 1)


def object_added(p: Pair, section: Section) -> bool:
    """Whether the rewrite gives an object to an instruction whose verb took none, so it no longer
    covers everything the verb did: a list of objects (joined by `and` / `or`), or one kind the
    section's other lines name beside others (`Edit at canonical paths only` -> `Edit instruction
    surfaces at canonical paths only`, where the section also lists `Author Python ...` and `Author
    Bash hooks ...`). An object the section's heading names, or that no other line names beside
    others, is the referent the line left implied (`Only use on trusted machines` under `## Remote
    debugging` -> `Only use remote debugging on trusted machines`)."""
    old, new = _sentence_words(p)
    verb = next((i for i, w in enumerate(old) if w not in STOPWORDS), None)
    if verb is None or verb + 1 >= len(old) or old[verb + 1] not in PHRASE_PREPOSITIONS:
        return False
    heading = {f for w in WORD_RE.findall(section.heading.lower()) for f in word_forms(w)}
    for tag, i1, _, j1, j2 in difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes():
        content = _content(new[j1:j2])
        if tag != "insert" or i1 != verb + 1 or not content:
            continue
        if CONDITION_CONJUNCTIONS & set(new[j1:j2]) and len(content) >= 2:
            return True
        if not all(w in heading for w in content) and _named_beside_others(section, p.old.line, content):
            return True
    return False
