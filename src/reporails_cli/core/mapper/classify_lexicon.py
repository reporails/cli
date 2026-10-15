"""Verb and condition lexicon for the rule-based charge classifier.

The charged verbs, the words that open a condition, and the context words that may
precede an imperative verb without blocking its detection.
"""

from __future__ import annotations

import re

from reporails_cli.core.mapper.classify_no import NO_CLAUSE_OPENERS, NO_DESCRIPTIVE_PREPS

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
CLAUSE_JOINERS: frozenset[str] = frozenset({"and", "then"})
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
    | CONDITION_CONJUNCTIONS
    | CLAUSE_JOINERS
)

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
    | frozenset(
        {
            "a", "after", "again", "also", "always", "an", "are", "as", "at", "be", "been", "before",
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


# The alphabetic words of a line.
WORD_RE = re.compile(r"[a-zA-Z']+")


def words_of(text: str) -> list[str]:
    """`text`'s alphabetic words, lowered, in order."""
    return [w.lower() for w in WORD_RE.findall(text)]
