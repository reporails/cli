"""Rule-based charge classification (no embedding model).

Deterministic steps classify each atom's charge into CONSTRAINT (-1),
DIRECTIVE (+1), IMPERATIVE (+1), or NEUTRAL (0), from the wording of the
atom alone.

Public entry point: `classify_charge(md_text, plain_text=...)`.
"""

from __future__ import annotations

import re

from reporails_cli.core.mapper.markers import strip_markdown_inline, without_list_marker
from reporails_cli.core.mapper.md_parser import leading_bold_run

# ──────────────────────────────────────────────────────────────────
# RULE-BASED CHARGE CLASSIFIER
# Verb lexicon. Three phases: negation → modal → imperative
# verb detection. No spaCy dependency, no embedding.
# ──────────────────────────────────────────────────────────────────

# Phase 1: Negation / Prohibition
_NEGATION_PHRASES_RE = re.compile(
    r"^(do not|don't|must not|shall not|should not|will not|cannot|can not|can't)\b",
    re.IGNORECASE,
)
_PROHIBITION_START_RE = re.compile(
    r"^(never|no|don't|cannot|can't|won't|avoid|refrain|prevent|prohibit|forbid)\b",
    re.IGNORECASE,
)
_MID_NEGATION_RE = re.compile(
    r"\b(is|are|does|do|did|has|have|was|were)\s+(NOT|not|n't)\b",
)
_LATE_DONOT_RE = re.compile(r"\bdo not\b|\bdon't\b|\bdo NOT\b", re.IGNORECASE)

# Phase 2: Modals / Adverbs
_MODAL_ABSOLUTE: set[str] = {"must", "shall"}
# Removed: "will" — future tense, not directive. "you will" handled in Phase 2.
_MODAL_HEDGED: frozenset[str] = frozenset({"should", "could", "might"})
# Removed: "can" (capability), "may" (possibility) — not instructions.

# Words that make an instruction a suggestion rather than an order.
HEDGE_WORDS: frozenset[str] = _MODAL_HEDGED | frozenset(
    {
        "maybe", "probably", "perhaps", "possibly", "try", "consider",
        "ideally", "generally", "usually", "prefer", "preferably",
    }
)  # fmt: skip
# The hedge words that, opening an instruction (after `you` / `we` / `please`), make all of it a
# suggestion (`Prefer real objects`, `Try not to mock`, `Perhaps run the linter`).
HEDGE_LEADS: frozenset[str] = frozenset(
    {"prefer", "preferably", "consider", "try", "perhaps", "maybe", "possibly", "ideally"}
)
_HEDGE_LEAD_SKIP = frozenset({"you", "we", "please"})
# Words that give an instruction as an order that admits no exception. `must` and `shall` read as
# absolute modality in the classifier but are not among these cues.
ABSOLUTE_CUES: frozenset[str] = frozenset({"never", "always", "exclusively"})
# The absolute cues that affirm (`Always run the tests`) rather than prohibit.
AFFIRMATIVE_ABSOLUTES: frozenset[str] = ABSOLUTE_CUES - {"never"}
# Capitalised words that mark a line as a hard constraint.
CONSTRAINT_WORDS: frozenset[str] = frozenset({"MUST", "NEVER", "ALWAYS", "IMPORTANT"})
_ABSOLUTE_ADVERBS: frozenset[str] = AFFIRMATIVE_ABSOLUTES | {"only"}
# Words that narrow where, when or to what an instruction applies, whatever follows them ...
SCOPE_RESTRICTORS: frozenset[str] = frozenset({"solely", "except", "excluding", "outside"}) | (
    _ABSOLUTE_ADVERBS - {"always"}
)
# ... and prepositions that narrow it when followed by a place, time or thing the line did not name.
SCOPE_PREPOSITIONS: frozenset[str] = frozenset({"on", "in", "at", "during", "within", "inside", "across", "under"})
# Words that open a noun phrase (`for the api module`).
# Words that quantify over a whole class (`every gate`, `any file`, `no exception`): naming one member
# right after one narrows what the line covers.
GENERAL_QUANTIFIERS: frozenset[str] = frozenset({"every", "each", "all", "any", "no", "one"})
DETERMINERS: frozenset[str] = frozenset({"the", "this", "that", "these", "those"}) | (
    GENERAL_QUANTIFIERS - {"no", "one"}
)

# Phase 3: verb lexicon
# CORE: high-confidence charged verbs
_VERBS_CORE: set[str] = {
    "add",
    "apply",
    "ask",
    "assume",
    "call",
    "check",
    "clone",
    "commit",
    "configure",
    "copy",
    "create",
    "define",
    "deploy",
    "document",
    "edit",
    "enable",
    "ensure",
    "execute",
    "export",
    "follow",
    "generate",
    "handle",
    "identify",
    "implement",
    "import",
    "include",
    "install",
    "invoke",
    "keep",
    "lint",
    "list",
    "load",
    "locate",
    "maintain",
    "mark",
    "minimize",
    "modify",
    "monitor",
    "navigate",
    "open",
    "optimize",
    "organize",
    "preserve",
    "preview",
    "provide",
    "pull",
    "push",
    "put",
    "query",
    "read",
    "refactor",
    "register",
    "restart",
    "return",
    "reuse",
    "review",
    "run",
    "search",
    "set",
    "show",
    "skip",
    "switch",
    "sync",
    "update",
    "use",
    "validate",
    "verify",
    "view",
    "wrap",
    "write",
}
# SUPPLEMENT: legitimate but lower-frequency charged verbs
_VERBS_SUPPLEMENT: set[str] = {
    "accept",
    "achieve",
    "activate",
    "adapt",
    "adjust",
    "advise",
    "analyze",
    "annotate",
    "answer",
    "append",
    "assess",
    "assign",
    "assist",
    "audit",
    "avoid",
    "be",
    "begin",
    "capture",
    "choose",
    "cite",
    "clarify",
    "classify",
    "collaborate",
    "collect",
    "compare",
    "compose",
    "confirm",
    "consolidate",
    "coordinate",
    "continue",
    "convert",
    "cross",
    "customize",
    "debounce",
    "deduplicate",
    "delete",
    "derive",
    "describe",
    "deserialize",
    "determine",
    "detect",
    "display",
    "distinguish",
    "document",
    "enforce",
    "establish",
    "evaluate",
    "examine",
    "explain",
    "expose",
    "extend",
    "extract",
    "fall",
    "favor",
    "fetch",
    "find",
    "flag",
    "give",
    "go",
    "group",
    "highlight",
    "improve",
    "inject",
    "inspect",
    "integrate",
    "investigate",
    "iterate",
    "leave",
    "leverage",
    "limit",
    "link",
    "look",
    "make",
    "manage",
    "map",
    "match",
    "maximize",
    "migrate",
    "mock",
    "move",
    "normalize",
    "note",
    "offer",
    "omit",
    "parametrize",
    "parse",
    "pass",
    "patch",
    "place",
    "populate",
    "prefer",
    "prefix",
    "prepare",
    "present",
    "print",
    "prioritize",
    "proceed",
    "produce",
    "profile",
    "propose",
    "raise",
    "recommend",
    "reconcile",
    "record",
    "refer",
    "release",
    "remember",
    "rename",
    "render",
    "repeat",
    "replace",
    "report",
    "request",
    "require",
    "reset",
    "resolve",
    "respect",
    "respond",
    "restrict",
    "reuse",
    "revert",
    "sanitize",
    "save",
    "scaffold",
    "scan",
    "scope",
    "serialize",
    "stage",
    "seed",
    "select",
    "send",
    "separate",
    "serve",
    "sort",
    "specify",
    "store",
    "structure",
    "submit",
    "suggest",
    "summarize",
    "support",
    "surface",
    "take",
    "throttle",
    "transform",
    "treat",
    "trigger",
    "understand",
    "upload",
    "utilize",
    "wait",
    "warn",
    "wire",
}
# AMBIGUOUS: mixed-confidence or genuinely dual noun/verb in tech context
_VERBS_AMBIGUOUS: set[str] = {
    "abstract",
    "archive",
    "benchmark",
    "break",
    "build",
    "cache",
    "clean",
    "close",
    "complete",
    "connect",
    "consider",
    "delegate",
    "design",
    "exercise",
    "fail",
    "fix",
    "focus",
    "format",
    "get",
    "help",
    "ignore",
    "initialize",
    "inline",
    "log",
    "name",
    "outline",
    "override",
    "pass",
    "plan",
    "process",
    "prototype",
    "react",
    "reference",
    "remove",
    "research",
    "route",
    "see",
    "split",
    "start",
    "state",
    "stop",
    "stub",
    "target",
    "test",
    "toggle",
    "trace",
    "track",
    "work",
}
_ALL_VERBS = _VERBS_CORE | _VERBS_SUPPLEMENT | _VERBS_AMBIGUOUS

CONDITIONAL_MARKERS: set[str] = {
    # Conditional
    "if",
    "unless",
    "provided",
    "given",
    "assuming",
    "whether",
    # Temporal
    "when",
    "whenever",
    "before",
    "after",
    "while",
    "until",
    "once",
    "during",
    "upon",
    # Restrictive
    "except",
    "where",
    # General
    "for",
}

# Words that only join or quantify a condition (`every time`, `prior to`, `whenever`): swapping one
# for a marker above adds no content of its own.
CONDITION_QUANTIFIERS: frozenset[str] = frozenset(
    {
        "wherever", "whilst", "till", "since", "otherwise", "then", "each", "every", "time", "case",
        "soon", "prior", "else", "only",
    }
)  # fmt: skip

# Words that join two conditions of one frame (`If the tests fail and the branch is main, ...`).
CONDITION_CONJUNCTIONS: frozenset[str] = frozenset({"and", "or"})

# Context words that can precede an imperative verb without blocking detection.
_CONTEXT_WORDS = CONDITIONAL_MARKERS | {
    # Determiners, articles, adverbs
    "each",
    "every",
    "all",
    "any",
    "first",
    "then",
    "also",
    "next",
    "finally",
    "immediately",
    "the",
    "a",
    "an",
    "this",
    "that",
    "these",
    "those",
    "now",
    "here",
    "there",
    "instead",
    "to",
    "and",
    "or",
    "not",
    "with",
    "in",
    "on",
    "at",
    "by",
    "from",
    "into",
    "only",
    "just",
    "simply",
    "please",
    "automatically",
    "optionally",
    "alternatively",
    "additionally",
    # CLI tools — invocation context preceding a verb
    "npm",
    "npx",
    "bun",
    "pnpm",
    "yarn",
    "cargo",
    "pip",
    "uv",
    "dotnet",
    "docker",
    "git",
    "go",
    "python",
    "node",
    "deno",
    "make",
    "composer",
    "mix",
    "flutter",
    "dart",
    "swift",
    "java",
    "mvn",
    "gradle",
    "gradlew",
    "ruby",
    "zig",
    "nix",
    "brew",
    "apt",
    "snap",
    "curl",
    "wget",
    "pytest",
    "ruff",
    "eslint",
    "prettier",
    "vitest",
    "jest",
    "mocha",
    "turbo",
    "nx",
    "lerna",
    "rushx",
    "hatch",
    "poetry",
    "pipx",
    "uvx",
    "helm",
    "kubectl",
    "terraform",
    "ansible",
    "ssh",
    "scp",
}

_CLASSIFY_WORD_RE = re.compile(r"[a-zA-Z']+")

# "No X is/are/was/were Y" — descriptive, not a prohibition. Shared by the
# Phase 1 prohibition guard and the map-validation must_constraint check.
_DESCRIPTIVE_NO_COPULAS = frozenset({"is", "are", "was", "were", "has", "have", "does", "did"})


def starts_descriptive_no(lowers: list[str]) -> bool:
    """True for a descriptive `No X is/are Y` opener (not a prohibition)."""
    return bool(lowers) and lowers[0] == "no" and any(v in _DESCRIPTIVE_NO_COPULAS for v in lowers[1:8])


# A `No …` opener is a determiner only in front of a noun phrase. These followers
# turn it into an adverbial or a pronoun (`no longer used`, `no matter what`), so
# the line is neither a status report nor a prohibition of the `No <NP>` kind.
_NO_ADVERBIAL_FOLLOWERS = frozenset({"longer", "matter", "more", "less", "doubt", "one", "other", "such"})

# A prohibition scopes itself with a LOCATIONAL preposition — it names the place
# the rule binds (`in code`, `between sections`, `on the main branch`, `at the
# boundary`). Every other preposition / subordinator describes an absence instead
# (`No support for Windows`, `No plans for v2`, `No context unless configured`),
# so this is the set that disqualifies the prohibition reading.
_NO_DESCRIPTIVE_PREPS = frozenset(
    {
        "for",
        "of",
        "about",
        "with",
        "without",
        "by",
        "to",
        "from",
        "unless",
        "when",
        "while",
        "except",
        "after",
        "before",
        "during",
        "beyond",
        "near",
        "around",
        "since",
        "per",
    }
)

# The noun phrases a `No <NP>` STATUS report names. A status line reports a count
# or a verdict; anything else a two-word `No <NP>` names is the forbidden thing
# itself (`No console.log`, `No blank lines`), so the status reading is a closed
# vocabulary rather than a shape rule.
_NO_STATUS_PHRASES = frozenset(
    {
        "open issues",
        "known issues",
        "open questions",
        "issues found",
        "issues remain",
        "priority action items",
        "action items",
        "action required",
        "action needed",
        "further action",
        "change needed",
        "changes needed",
        "change required",
        "changes required",
        "setup required",
        "setup needed",
        "drift detected",
        "cloud dependencies",
    }
)
_NO_STATUS_PHRASE_MAX_WORDS = max(len(p.split()) for p in _NO_STATUS_PHRASES)

# Adverbs that date a statement — a line reporting what is absent *so far* reports,
# it does not forbid (`No data in this table yet`).
_NO_STATUS_ADVERBS = ("yet", "currently", "so far", "right now", "at the moment", "for now", "at present", "to date")

# Nouns that merely end in `-ed`; the inflection read below would take them for a
# participle and mistake the clause for a report.
_ED_NOUNS = frozenset({"speed", "breed", "creed", "tweed", "steed", "embed"})

# A terse prohibition is a short verbless clause; past that length the line is prose.
_NO_PROHIBITION_MAX_WORDS = 10


def starts_bare_no_status(lowers: list[str]) -> bool:
    """True for a `No <noun phrase>` STATUS line — not a prohibition.

    A status line reports a count or a verdict and stops (`No regressions.`,
    `No changes.`, `None.`, `No open issues`, `No drift detected on the tracked
    dimensions`). A prohibition written with the same opener names the thing it
    forbids (`No console.log`, `No hardcoded secrets`, `No blank lines`), and that
    naming takes at least two words — so the one-word form is the status shape
    itself, and past one word the line only reports when it names one of the
    status phrases in `_NO_STATUS_PHRASES`.
    """
    if not lowers or lowers[0] not in ("no", "none"):
        return False
    rest = lowers[1:]
    if not rest:
        return True  # a bare "None." / "No."
    if rest[0] in _NO_ADVERBIAL_FOLLOWERS:
        return False
    if len(rest) == 1:
        return True  # `No regressions.` / `No changes.` — the bare count
    return any(" ".join(rest[:n]) in _NO_STATUS_PHRASES for n in range(2, _NO_STATUS_PHRASE_MAX_WORDS + 1))


def _carries_status_adverb(lowers: list[str]) -> bool:
    """True when the clause dates its own statement (`… yet`, `… so far`)."""
    joined = f" {' '.join(lowers)} "
    return any(f" {adverb} " in joined for adverb in _NO_STATUS_ADVERBS)


def is_terse_no_prohibition(lowers: list[str]) -> bool:
    """True for a verbless `No <noun phrase>` prohibition.

    The positive side of :func:`starts_bare_no_status`: a short clause that names a
    forbidden thing, with or without the place it is forbidden in
    (`No console.log`, `No hardcoded secrets in code`, `No blank lines between
    sections`).

    Three shapes are excluded because they describe an absence instead of forbidding
    a thing: a non-locational preposition, which names what is missing rather than
    where a rule binds (`No support for Windows`, `No plans for v2`); a dating adverb
    (`No data in this table yet`); and a predicate — a copula
    (:func:`starts_descriptive_no`) or a past participle past the attributive slot,
    which turns the line into a report (`No new CSS classes introduced`, `No rule
    existed to verify file scope`). The one word directly after `No` is the head
    noun's own modifier (`No hardcoded secrets`), so it is never read as the verb.
    """
    if len(lowers) < 3 or lowers[0] != "no" or len(lowers) > _NO_PROHIBITION_MAX_WORDS:
        return False
    if lowers[1] in _NO_ADVERBIAL_FOLLOWERS:
        return False
    if (
        starts_descriptive_no(lowers)
        or starts_bare_no_status(lowers)
        or _carries_status_adverb(lowers)
        or any(w in _NO_DESCRIPTIVE_PREPS for w in lowers[1:])
    ):
        return False
    return not any(_is_past_participle(w) for w in lowers[2:])


def _is_past_participle(word: str) -> bool:
    """True for an `-ed` form that reads as a clause's verb, not as a noun."""
    return word.endswith("ed") and len(word) > 4 and word not in _ED_NOUNS


# Probable sentence subjects — block mid-sentence verb promotion
_PROBABLE_SUBJECTS = {
    "it",
    "this",
    "that",
    "they",
    "we",
    "he",
    "she",
    "everything",
    "nothing",
    "something",
    "anything",
}


def _strip_md_for_classify(text: str) -> str:
    """Strip markdown markers for charge classification. Keeps content."""
    return without_list_marker(strip_markdown_inline(text))


def _classify_words(text: str) -> list[str]:
    """Extract alphabetic words from text."""
    return _CLASSIFY_WORD_RE.findall(text)


# What sits between a bold label and the text it introduces: a colon, a dash, a slash or a sentence
# mark, or only space.
_AFTER_BOLD_LABEL_RE = re.compile(r"\s*[:\u2014\u2013.!?/-]\s*|\s+")


def _after_bold_label(md_text: str) -> str | None:
    """Return text after **Label**: / **Label** — patterns, or None."""
    raw = without_list_marker(md_text)
    run = leading_bold_run(raw)
    if run is None:
        return None
    m = _AFTER_BOLD_LABEL_RE.match(raw, run.end)
    return raw[m.end() :] if m else None


def _find_verb_idx(lowers: list[str]) -> int:
    """Index of first known verb in word list, or -1."""
    for i, w in enumerate(lowers):
        if w in _ALL_VERBS:
            return i
    return -1


# The words that open a condition clause; a bare `for` opens none.
CONDITION_OPENERS = CONDITIONAL_MARKERS - {"for"}

# Limiting adverbs that may sit in front of a frame marker without breaking the
# frame (`Only for TypeScript files, …`, `Just when the build fails, …`).
_COND_FRAME_LEADS = frozenset({"only", "just", "strictly", "solely", "even"})


def is_conditional_frame(text: str) -> bool:
    """True when ``text`` opens a conditional / restrictive frame.

    Reads the frame marker at the head of the text — `if`, `when`, `unless`,
    `before`, `while`, … — allowing a limiting adverb in front of it. A bare `for`
    opener counts only behind such an adverb (`Only for TypeScript files`), because
    an unqualified `For example, …` names no condition.
    """
    lowers = [w.lower() for w in _CLASSIFY_WORD_RE.findall(text)]
    i = 0
    while i < len(lowers) and lowers[i] in _COND_FRAME_LEADS:
        i += 1
    if i >= len(lowers):
        return False
    head = lowers[i]
    if head in CONDITION_OPENERS:
        return True
    return head == "for" and i > 0


# A frame CLOSES before the clause it governs: `If X, Y` / `When X, do Y` /
# `Unless X, then Y`. The comma (or `then`) is what makes the opener a frame at
# all — without it the word is the sentence's own subject or a section label
# (`While loops must be bounded`, `Before hooks run on every commit`, `When to use`).
_COND_CLAUSE_CLOSE_RE = re.compile(r"[,;]\s*\S|\s+then\s+\S", re.IGNORECASE)
# The governing clause is short; past that the comma belongs to the main clause.
_COND_CLAUSE_MAX_WORDS = 12


def opens_conditional_clause(text: str) -> bool:
    """True when ``text`` opens a conditional frame AND closes it before its clause.

    The stricter reading of :func:`is_conditional_frame`, for the case where the
    whole sentence is the evidence: a frame marker at the head settles nothing on
    its own, because the same words open a noun phrase (`While loops …`) or a
    heading (`When to use`). A real frame hands off to the clause it governs at a
    comma or a `then`.
    """
    if not is_conditional_frame(text):
        return False
    head = " ".join(text.split()[:_COND_CLAUSE_MAX_WORDS])
    return bool(_COND_CLAUSE_CLOSE_RE.search(head))


def _classify_phase1(
    clean: str,
    words: list[str],
    lowers: list[str],
    has_cond_prefix: bool,
) -> tuple[str, int, str, str, bool] | None:
    """Phase 1: Negation/prohibition patterns → CONSTRAINT."""
    if _NEGATION_PHRASES_RE.match(clean):
        return "CONSTRAINT", -1, "direct", "p1_negation_phrase", False
    if _PROHIBITION_START_RE.match(clean):
        # "No X is/are/was/were Y" is descriptive and a bare "No <noun phrase>" is a
        # status report — neither prohibits anything.
        if starts_descriptive_no(lowers) or starts_bare_no_status(lowers):
            pass  # fall through — descriptive "No X is Y" / bare status pattern
        else:
            return "CONSTRAINT", -1, "absolute" if lowers[0] == "never" else "direct", "p1_prohibition_start", False
    if words[0] in ("NOT", "NO", "NEVER"):
        return "CONSTRAINT", -1, "absolute", "p1_caps_negation", False
    # Main-clause only: split at STRONG markers (em/en-dash, ; : , .) so a
    # trailing prohibition in a compound ("Read X — do not skim") does not
    # invert the affirmative main clause. The trailing clause becomes its own
    # atom via the granularity split in parse.
    first_clause = re.split(r"\s+[\u2014\u2013]\s+|[,;:.]", clean, maxsplit=1)[0]
    if _MID_NEGATION_RE.search(first_clause):
        return "CONSTRAINT", -1, "direct", "p1_mid_negation", has_cond_prefix
    if _LATE_DONOT_RE.search(first_clause):
        return "CONSTRAINT", -1, "direct", "p1_late_donot", has_cond_prefix
    return None


# Words that negate the word before them (`should not`, `must never`, `would n't`, `must cannot`).
NEGATION_WORDS: frozenset[str] = frozenset({"not", "never", "n't", "cannot"})
# Lowered words whose presence as a line's first word gives it as an order: absolute and negation
# cues, constraint words and the modals the classifier reads as a directive.
DIRECTIVE_CUES: frozenset[str] = (
    ABSOLUTE_CUES
    | NEGATION_WORDS
    | frozenset(w.lower() for w in CONSTRAINT_WORDS)
    | _MODAL_ABSOLUTE
    | _MODAL_HEDGED
    | {"only"}
)


def _modal_result(
    next_negated: bool,
    modality: str,
    directive_trace: str,
    negated_trace: str,
) -> tuple[str, int, str, str, bool]:
    """Return CONSTRAINT if negated, DIRECTIVE otherwise."""
    if next_negated:
        return "CONSTRAINT", -1, modality, negated_trace, False
    return "DIRECTIVE", 1, modality, directive_trace, False


def _check_modal_word(
    w: str,
    i: int,
    lowers: list[str],
) -> tuple[str, int, str, str, bool] | None:
    """Check a single word for modal/hedged/you-will patterns. Returns result or None."""
    next_negated = i + 1 < len(lowers) and lowers[i + 1] in NEGATION_WORDS
    if w in _MODAL_ABSOLUTE:
        return _modal_result(next_negated, "absolute", f"p2_modal_{w}", "p2_modal_negated")
    if w in _MODAL_HEDGED:
        if next_negated:
            return "CONSTRAINT", -1, "hedged", f"p2_hedged_{w}_negated", False
        is_positioned = (
            w == "should"
            or i == 0
            or (i > 0 and lowers[i - 1] in ("you", "we"))
            or (i > 0 and lowers[i - 1] in CONDITIONAL_MARKERS)
        )
        return ("DIRECTIVE", 1, "hedged", f"p2_hedged_{w}", False) if is_positioned else None
    if w == "will" and i > 0 and lowers[i - 1] == "you":
        return _modal_result(next_negated, "absolute", "p2_you_will", "p2_you_will_not")
    return None


def _classify_phase2(
    lowers: list[str],
) -> tuple[str, int, str, str, bool] | None:
    """Phase 2: Modal verbs and absolute adverbs → DIRECTIVE."""
    for i, w in enumerate(lowers):
        result = _check_modal_word(w, i, lowers)
        if result is not None:
            return result
    for w in lowers[:6]:
        if w in _ABSOLUTE_ADVERBS:
            if w == "only" and not any(v in _ALL_VERBS for v in lowers):
                continue
            return "DIRECTIVE", 1, "absolute", f"p2_adverb_{w}", False
    return None


# Determiners for verb-noun disambiguation in Phase 3c: the noun-phrase openers plus articles,
# possessives and quantifiers.
_VERB_NOUN_DETERMINERS: frozenset[str] = DETERMINERS | {
    "a",
    "an",
    "your",
    "our",
    "my",
    "its",
    "their",
    "his",
    "her",
    "no",
    "some",
    "both",
    "either",
    "neither",
}

# Declarative sentence starters for Phase 3g
_DECLARATIVE_STARTS: frozenset[str] = frozenset(
    _PROBABLE_SUBJECTS
    | {
        "the",
        "a",
        "an",
        "its",
        "their",
        "our",
        "your",
        "my",
        "his",
        "her",
    }
)


def _classify_phase3e_break(
    clean: str,
) -> tuple[str, int, str, str, bool] | None:
    """Phase 3e: verb after sentence/clause break."""
    sentences = re.split(r"(?<=[.!?:;])\s+", clean)
    for sent in sentences[1:]:
        sw = _classify_words(sent)
        if not sw:
            continue
        sl = [w.lower() for w in sw]
        if sl[0] in _ALL_VERBS:
            has_cond = any(w in CONDITIONAL_MARKERS for w in sl[:6])
            amb = "!amb" if sl[0] in _VERBS_AMBIGUOUS else ""
            return "IMPERATIVE", 1, "imperative", f"p3e_break_{sl[0]}{amb}", has_cond
        if sl[0] in CONDITIONAL_MARKERS:
            return "IMPERATIVE", 1, "imperative", "p3e_break_cond", True
    return None


def _classify_phase3d_context(
    lowers: list[str],
    verb_idx: int,
    pre: set[str],
) -> tuple[str, int, str, str, bool] | None:
    """Phase 3d: verb after context words only."""
    if not (pre <= _CONTEXT_WORDS):
        return None
    has_cond = bool(pre & CONDITIONAL_MARKERS)
    if "not" in pre:
        return "CONSTRAINT", -1, "direct", "p3d_context_not", has_cond
    verb = lowers[verb_idx]
    amb = "!amb" if verb in _VERBS_AMBIGUOUS else ""
    return "IMPERATIVE", 1, "imperative", f"p3d_context_{verb}{amb}", has_cond


def _classify_phase3_deep(
    clean: str,
    lowers: list[str],
    verb_idx: int,
    pre: set[str],
) -> tuple[str, int, str, str, bool]:
    """Phase 3 deep detection: sub-phases 3d-3g (mid-sentence verb detection)."""
    # 3d: Verb after context words only
    p3d = _classify_phase3d_context(lowers, verb_idx, pre)
    if p3d is not None:
        return p3d

    # 3e: Verb after sentence/clause break
    p3e = _classify_phase3e_break(clean)
    if p3e is not None:
        return p3e

    # 3f: Conditional marker at sentence start
    if lowers[0] in CONDITIONAL_MARKERS:
        return "IMPERATIVE", 1, "imperative", f"p3f_cond_{lowers[0]}", True

    # 3g: Mid-sentence verb with conditional marker before it
    if lowers[0] not in _DECLARATIVE_STARTS and verb_idx <= 7 and pre & CONDITIONAL_MARKERS:
        verb = lowers[verb_idx]
        amb = "!amb" if verb in _VERBS_AMBIGUOUS else ""
        if "not" in pre:
            return "CONSTRAINT", -1, "direct", f"p3g_mid_not{amb}", True
        return "IMPERATIVE", 1, "imperative", f"p3g_mid_{verb}{amb}", True

    return "NEUTRAL", 0, "none", "fallthrough", False


def _classify_phase3_lexicon(
    clean: str,
    lowers: list[str],
    verb_idx: int,
    *,
    shallow: bool,
) -> tuple[str, int, str, str, bool]:
    """Phase 3 fallback: verb lexicon detection (when spaCy unavailable or returns None).

    Covers sub-phases 3c through 3g.
    """
    # 3c: Verb at position 0
    if verb_idx == 0:
        verb = lowers[0]
        amb = ""
        if verb in _VERBS_AMBIGUOUS:
            pos1 = lowers[1] if len(lowers) > 1 else ""
            if pos1 not in _VERB_NOUN_DETERMINERS:
                amb = "!amb"
        has_cond = any(w in CONDITION_OPENERS for w in lowers[1:8])
        return "IMPERATIVE", 1, "imperative", f"p3c_verb0_{verb}{amb}", has_cond

    if shallow:
        return "NEUTRAL", 0, "none", "p3_shallow_stop", False

    return _classify_phase3_deep(clean, lowers, verb_idx, set(lowers[:verb_idx]))


_NEUTRAL_RESULT: tuple[str, int, str, str, bool] = ("NEUTRAL", 0, "none", "fallthrough", False)


def _classify_phase3b_bold(md_text: str) -> tuple[str, int, str, str, bool] | None:
    """Phase 3b: Bold label + verb after it — shallow recursive call."""
    after = _after_bold_label(md_text)
    if after is None:
        return None
    after_clean = _strip_md_for_classify(after)
    if not after_clean:
        return None
    sub_c, sub_cv, sub_m, _sub_trace, sub_sc = classify_charge(
        after,
        plain_text=after_clean,
        _shallow=True,
    )
    if sub_cv != 0:
        return sub_c, sub_cv, sub_m, "p3b_bold_label", sub_sc
    return None


def _classify_phase3(
    clean: str,
    md_text: str,
    lowers: list[str],
    *,
    shallow: bool,
) -> tuple[str, int, str, str, bool]:
    """Phase 3: Imperative verb detection (embedding-free / spaCy-free lexicon)."""
    # 3b: Bold label recursive
    if not shallow:
        p3b = _classify_phase3b_bold(md_text)
        if p3b is not None:
            return p3b

    # 3c-3g: verb lexicon (primary path)
    verb_idx = _find_verb_idx(lowers)
    if verb_idx != -1:
        return _classify_phase3_lexicon(clean, lowers, verb_idx, shallow=shallow)

    # Lexicon miss: no verb found (`_ALL_VERBS` is the sole verb source).
    return "NEUTRAL", 0, "none", "p3_no_verb", False


def hedges_with_should(text: str) -> bool:
    """True when `text` gives its instruction with `should` (`You should run the linter`).

    Reads the same modal the classifier itself settles on: a prohibition opener
    (`Never …`) or an absolute modal met first keeps the line from reading hedged, and
    only `should` counts — `might` and `could` do not.
    """
    if "should" not in text.lower():
        return False
    _charge, _cv, _mod, trace, _scope = classify_charge(text, plain_text=text)
    return trace.startswith("p2_hedged_should")


def words_of(text: str) -> list[str]:
    """`text`'s alphabetic words, lowered, in order."""
    return [w.lower() for w in _CLASSIFY_WORD_RE.findall(text)]


def hedges_with_lead(text: str) -> bool:
    """True when `text` opens with a hedge word (`Prefer …`, `Try not to …`, `Perhaps …`): after
    `you` / `we` / `please`, its first word is one of `HEDGE_LEADS`."""
    lowers = words_of(text)
    start = 0
    while start < len(lowers) and lowers[start] in _HEDGE_LEAD_SKIP:
        start += 1
    return start < len(lowers) and lowers[start] in HEDGE_LEADS


def has_hedge_cue(text: str) -> bool:
    """True when any word of `text` is a hedge word — how a line the mapper read as plain prose
    (`You might want to run the linter`) shows it was a suggestion."""
    return any(w in HEDGE_WORDS for w in words_of(text))


def leading_prohibition(text: str) -> re.Match[str] | None:
    """The prohibition marker (`Never`, `Do not`, `Avoid`, ...) that opens `text`, read off its words;
    the match's `string` is the words rejoined, so `string[end():]` is what follows the marker."""
    clean = " ".join(words_of(text))
    return _NEGATION_PHRASES_RE.match(clean) or _PROHIBITION_START_RE.match(clean)


def absolute_cues(text: str) -> set[str]:
    """The words of `text` that give its instruction as an order without exception."""
    return {w for w in words_of(text) if w in ABSOLUTE_CUES}


def classify_charge(
    md_text: str,
    *,
    plain_text: str | None = None,
    _shallow: bool = False,
) -> tuple[str, int, str, str, bool]:
    """Classify an atom's charge and modality using deterministic rules.

    Input: raw markdown text (with formatting markers intact).
    Returns: (charge, charge_value, modality, rule_trace, scope_conditional)

    rule_trace identifies which rule fired (e.g. "p1_negation_phrase",
    "p3c_verb0_use"). Traces ending with "!amb" indicate the classification
    depends on a verb-noun interpretation (ambiguous charge).

    Three-phase classification:
      Phase 1 — Negation/prohibition patterns → CONSTRAINT
      Phase 2 — Modal verbs and absolute adverbs → DIRECTIVE
      Phase 3 — Imperative verb detection (verb lexicon) → IMPERATIVE

    When _shallow=True (recursive from Phase 3b), only high-precision
    phases fire: Phase 1, Phase 2, Phase 3a, Phase 3c. Phases 3d-3g
    (deep mid-sentence detection) are skipped to avoid noise from
    descriptive text after bold labels.
    """
    clean = without_list_marker(plain_text) if plain_text is not None else _strip_md_for_classify(md_text)
    if len(clean) < 3:
        return "NEUTRAL", 0, "none", "short_text", False

    words = _classify_words(clean)
    if not words:
        return "NEUTRAL", 0, "none", "no_words", False
    lowers = [w.lower() for w in words]
    has_cond_prefix = lowers[0] in CONDITIONAL_MARKERS

    p1 = _classify_phase1(clean, words, lowers, has_cond_prefix)
    if p1 is not None:
        return p1

    p2 = _classify_phase2(lowers)
    if p2 is not None:
        return p2

    return _classify_phase3(
        clean,
        md_text,
        lowers,
        shallow=_shallow,
    )
