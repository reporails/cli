"""Verb and condition lexicon for the rule-based charge classifier.

The charged verbs, the words that open a condition, and the context words that may
precede an imperative verb without blocking its detection.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from collections.abc import Set as AbstractSet

from reporails_cli.core.mapper.classify_no import NO_CLAUSE_OPENERS, NO_DESCRIPTIVE_PREPS
from reporails_cli.core.mapper.md_parser import replace_code_spans

# CORE: high-confidence charged verbs
VERBS_CORE: set[str] = {
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
# Verbs that also name tools (`find`, `make`, `mock`).
VERBS_NAMING_TOOLS: frozenset[str] = frozenset({"find", "make", "mock"})
# SUPPLEMENT: legitimate but lower-frequency charged verbs
VERBS_SUPPLEMENT: set[str] = set(VERBS_NAMING_TOOLS) | {
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
VERBS_AMBIGUOUS: set[str] = {
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
ALL_VERBS = VERBS_CORE | VERBS_SUPPLEMENT | VERBS_AMBIGUOUS

# The openers of a condition on a situation, a time or a place (`If`, `When`, `Whenever`, `Where`).
SITUATIONAL_OPENERS: frozenset[str] = frozenset({"if", "when", "whenever", "where"})
# `possible` after one of these, ending its clause, hedges an instruction (`Run it where possible`):
# the situational openers plus `wherever`, which opens no condition on its own.
HEDGE_POSSIBLE_LEADS: frozenset[str] = SITUATIONAL_OPENERS | {"wherever"}

CONDITIONAL_MARKERS: set[str] = set(SITUATIONAL_OPENERS) | {
    # Conditional
    "unless",
    "provided",
    "given",
    "assuming",
    "whether",
    # Temporal
    "before",
    "after",
    "while",
    "until",
    "once",
    "during",
    "upon",
    # Restrictive
    "except",
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
# Words that start the next clause of a packed sentence (`Bump the version and update the docs`, `lint, then test`).
STEP_JOINER = "then"
CLAUSE_JOINERS: frozenset[str] = frozenset({"and", STEP_JOINER})
# The pronoun and copula of `it is` / `it's`.
IT_IS: tuple[str, str] = ("it", "is")

# Context words that can precede an imperative verb without blocking detection.
CONTEXT_WORDS = (
    CONDITIONAL_MARKERS
    | {
        # Determiners, articles, adverbs
        "each",
        "every",
        "all",
        "any",
        "first",
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
        "npm", "npx", "bun", "pnpm", "yarn", "cargo", "pip", "uv", "dotnet", "docker", "git", "go",
        "python", "node", "deno", "make", "composer", "mix", "flutter", "dart", "swift", "java", "mvn",
        "gradle", "gradlew", "ruby", "zig", "nix", "brew", "apt", "snap", "curl", "wget", "pytest", "ruff",
        "eslint", "prettier", "vitest", "jest", "mocha", "turbo", "nx", "lerna", "rushx", "hatch", "poetry",
        "pipx", "uvx", "helm", "kubectl", "terraform", "ansible", "ssh", "scp",
    }
    | CONDITION_CONJUNCTIONS
    | CLAUSE_JOINERS
)  # fmt: skip

# The words that open a condition clause; a bare `for` opens none.
CONDITION_OPENERS = CONDITIONAL_MARKERS - {"for"}

# The people an instruction addresses or speaks for (`you must`, `we always`).
ADDRESSEE_SUBJECTS: frozenset[str] = frozenset({"you", "we"})
# Personal pronouns: after an ambiguous opening verb they start a clause of their own (`Fix tests you can reproduce`).
SUBJECT_PRONOUNS: frozenset[str] = ADDRESSEE_SUBJECTS | {"i", "they", "he", "she", "it"}

# Phase 2: Modals / Adverbs
MODAL_ABSOLUTE: set[str] = {"must", "shall"}
# Removed: "will" — future tense, not directive. "you will" handled in Phase 2.
MODAL_HEDGED: frozenset[str] = frozenset({"should", "could", "might"})
# Removed: "can" (capability), "may" (possibility) — not instructions.

SCOPE_PREPOSITIONS: frozenset[str] = frozenset({"on", "in", "at", "during", "within", "inside", "across", "under"})
# Words that open a noun phrase (`for the api module`).
# Words that quantify over a whole class (`every gate`, `any file`, `no exception`): naming one member
# right after one narrows what the line covers.
GENERAL_QUANTIFIERS: frozenset[str] = frozenset({"every", "each", "all", "any", "no", "one"})
DEFINITE_DETERMINERS: frozenset[str] = frozenset({"the", "this", "that", "these", "those"})
# Words that open a noun phrase of their own (`a prior orientation`).
INDEFINITE_ARTICLES: frozenset[str] = frozenset({"a", "an"})
DETERMINERS: frozenset[str] = DEFINITE_DETERMINERS | (GENERAL_QUANTIFIERS - {"no", "one"})

# Common English function words, dropped from content-word coverage: polarity already tracks
# negation/modality (`charge_value`), so these words would only pad an overlap between two
# otherwise-unrelated instructions without adding topic signal.
STOPWORDS: frozenset[str] = (
    CONDITION_CONJUNCTIONS
    | CLAUSE_JOINERS
    | frozenset(IT_IS)
    | MODAL_ABSOLUTE
    | MODAL_HEDGED
    | GENERAL_QUANTIFIERS
    | DEFINITE_DETERMINERS
    | INDEFINITE_ARTICLES
    | frozenset(
        {
            "after", "again", "also", "always", "are", "as", "at", "be", "been", "before",
            "being", "but", "by", "can", "did", "do", "does", "down", "few", "for", "from", "here", "if",
            "in", "into", "its", "just", "may", "more", "most", "never", "nor", "not", "of", "on", "once",
            "only", "onto", "other", "out", "over", "own", "per", "so", "some", "such", "than", "there",
            "to", "too", "under", "up", "very", "was", "were", "when", "will", "with", "would", "you",
            "your",
        }
    )
)  # fmt: skip

# scope prepositions and the prepositions above less the words that open a clause rather than a phrase
# (`unless`, `when`, `while`, `except`, `since`; `before` / `after` stay, opening a time phrase), with a few more.
PHRASE_PREPOSITIONS: frozenset[str] = (
    SCOPE_PREPOSITIONS
    | (NO_DESCRIPTIVE_PREPS - NO_CLAUSE_OPENERS)
    | frozenset({"into", "onto", "over", "through", "against", "between", "via"})
)

# Quantifiers a `for` may open without cutting what a rule covers (`For each file, run lint`).
FOR_QUANTIFIERS: frozenset[str] = DETERMINERS & GENERAL_QUANTIFIERS
# Words after a fronted `for` / scope preposition that make it an aside, not a scope (`For example,`,
# `In general,`).
FOR_ASIDES: frozenset[str] = frozenset({"example", "instance"})
NOT_A_SCOPE: frozenset[str] = FOR_ASIDES | frozenset(
    {"general", "short", "particular", "practice", "summary", "addition", "fact", "times"}
)
# Words that make a list a set of examples rather than the whole of what a rule covers.
EXAMPLE_LEADS: frozenset[str] = frozenset({"such", "e", "g", "eg", "including", "like", "example", "examples"})
# Words that only mark a condition or a quantifier over it: swapping one marker for another
# ("every time" -> "whenever", "prior to" -> "before") adds no content of its own.
CONDITION_WORDS: frozenset[str] = frozenset(CONDITIONAL_MARKERS) | CONDITION_QUANTIFIERS
# What ends the phrase a scope preposition opens.
PHRASE_END: frozenset[str] = PHRASE_PREPOSITIONS | CONDITION_CONJUNCTIONS
# Words that open a fronted scope phrase (`For all,`, `In CI,`).
FRAME_OPENERS: frozenset[str] = SCOPE_PREPOSITIONS | {"for"}

# The alphabetic words of a line.
WORD_RE = re.compile(r"[a-zA-Z']+")
# A word as written in code-aware prose: letters, digits, underscores and apostrophes (`python3`, `snake_case`).
CODE_WORD_RE = re.compile(r"[a-zA-Z0-9_']+")
# A word of letters and digits only: the sub-words of an identifier or a path segment.
ALNUM_WORD_RE = re.compile(r"[a-zA-Z0-9]+")
# A token that is one plain word (`except`), as against a path, a dotted name or a multi-word token.
SINGLE_WORD_RE = re.compile(r"\w+")
# A hyphenated word opening with a scope preposition (`in-memory`, `on-call`) is one word, not a place.
PREPOSITION_COMPOUND_RE = re.compile(r"\b(" + "|".join(sorted(SCOPE_PREPOSITIONS)) + r")-(?=[a-z])", re.IGNORECASE)
# A `(see ...)` reference aside.
SEE_ASIDE_RE = re.compile(r"\(\s*see\b[^)]*\)", re.IGNORECASE)
# An example marker (`e.g.`, `for example`, `such as`, `like`, `for instance`, bare or opening a
# parenthetical) or a reason-clause marker (`because`, `since`, `so that`, `to avoid`, `otherwise`, or
# a `,` / `—` before a clause-opening `so`): once one opens, the rest of an instruction is an
# illustration or a justification.
EXAMPLE_OR_REASON_RE = re.compile(
    r"\((?:e\.g\.|for example|such as|like|for instance)(?!\w)"
    r"|\b(?:e\.g\.|for example|such as|like|for instance)(?!\w)"
    r"|\b(?:because|since|so that|to avoid|otherwise)\b"
    r"|[,—-]\s*so\b",
    re.IGNORECASE,
)
# Punctuation a whitespace token carries around its word.
TOKEN_EDGES = ".,;:()[]*_\"'—"


def words_of(text: str) -> list[str]:
    """`text`'s alphabetic words, lowered, in order."""
    return [w.lower() for w in WORD_RE.findall(text)]


def prose_tokens(sentence: str) -> list[str]:
    """The lowered whitespace tokens of `sentence` outside code spans, a hyphenated word kept whole
    (`ready-for-review` holds no `for`), a `(see ...)` reference aside left out."""
    text = SEE_ASIDE_RE.sub(" ", replace_code_spans(sentence, " code "))
    return [t.strip(TOKEN_EDGES).lower() for t in text.split()]


def word_forms(word: str) -> set[str]:
    """`word` with its plain singular and plural spellings (`test` / `tests`, `match` / `matches`)."""
    forms = {word, word + "s", word + "es"}
    if word.endswith("es"):
        forms.add(word[:-2])
    if word.endswith("s"):
        forms.add(word[:-1])
    return forms


def is_content_word(word: str) -> bool:
    """Whether `word` is longer than two letters and not a function word."""
    return len(word) > 2 and word not in STOPWORDS


COMMA: frozenset[str] = frozenset({","})
# What stands between the items of a coordinated list.
LIST_SEPARATORS: frozenset[str] = COMMA | CONDITION_CONJUNCTIONS
# Words that open the next clause after a joiner (`Build docs and push`), told from the nouns a verb-like
# word may also be.
_CLAUSE_OPENING_VERBS: frozenset[str] = frozenset(VERBS_CORE | VERBS_SUPPLEMENT)


def list_tokens(text: str) -> list[str]:
    """The lowered content words of `text` in order, with a `,` kept where one stood and `and` / `or`
    kept as separators, except an `and` that joins clauses (`CLAUSE_JOINERS`, followed by a verb:
    `Build docs and push`), which separates no items."""
    tokens: list[str] = []
    for i, part in enumerate(text.lower().split(",")):
        if i:
            tokens.append(",")
        words = CODE_WORD_RE.findall(part)
        for k, w in enumerate(words):
            joins_clauses = w in CLAUSE_JOINERS and words[k + 1 : k + 2] and words[k + 1] in _CLAUSE_OPENING_VERBS
            if not joins_clauses and (w in LIST_SEPARATORS or is_content_word(w)):
                tokens.append(w)
    return tokens


def phrase_starts(tokens: Sequence[str], phrase: Sequence[str]) -> list[int]:
    """Where `phrase` (content words, any singular / plural form) stands in `tokens`, as start indices."""
    n = len(phrase)
    return [k for k in range(len(tokens) - n + 1) if all(tokens[k + d] in word_forms(w) for d, w in enumerate(phrase))]


def is_list_item(
    tokens: Sequence[str],
    phrase: Sequence[str],
    *,
    before: AbstractSet[str] = LIST_SEPARATORS,
    after: AbstractSet[str] = LIST_SEPARATORS,
) -> bool:
    """Whether `phrase` stands as an item of a coordinated list in `tokens` (`list_tokens` of a text;
    `Lint Python, shell, or Docker`): a separator stands right before it (one of `before`) or right
    after it (one of `after`)."""
    for k in phrase_starts(tokens, phrase):
        end = k + len(phrase)
        if (k > 0 and tokens[k - 1] in before) or (end < len(tokens) and tokens[end] in after):
            return True
    return False
