# pylint: disable=C0302
# ruff: noqa: C901, SIM102, SIM108, N806, PERF401, RUF034
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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from markdown_it import MarkdownIt

if TYPE_CHECKING:
    pass  # sentence_transformers types if needed

logger = logging.getLogger(__name__)

SCHEMA_VERSION = "1.0.0"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Topic clustering threshold (L2 distance on L2-normalized embeddings).
TOPIC_CLUSTER_THRESHOLD = 1.2


# ──────────────────────────────────────────────────────────────────
# DATA MODEL
# ──────────────────────────────────────────────────────────────────


@dataclass
class InlineToken:
    """A word-level token with format context from AST parsing.

    Used by Phase 3 backtick filter to determine if a ROOT word
    falls inside a backtick span without regex heuristics.
    """

    text: str
    format: str  # "backtick" | "bold" | "italic" | "plain"


@dataclass
class Atom:
    """A classified content atom from an instruction file."""

    line: int
    text: str
    kind: str  # heading | excitation
    charge: str  # CONSTRAINT | DIRECTIVE | IMPERATIVE | NEUTRAL | AMBIGUOUS
    charge_value: int  # q: -1 (constraint), 0 (neutral/ambiguous), +1 (directive/imperative)
    modality: str  # imperative | direct | absolute | hedged | none
    specificity: str  # named | abstract
    scope_conditional: bool = False  # True when conditional frame (if/when/unless) detected
    format: str = "prose"  # prose | heading | list | numbered | table | blockquote | code_block | data_block
    named_tokens: list[str] = field(default_factory=list)
    italic_tokens: list[str] = field(default_factory=list)
    bold_tokens: list[str] = field(default_factory=list)
    unformatted_code: list[str] = field(default_factory=list)
    position_index: int = 0  # 0-based index among non-heading atoms
    token_count: int = 0  # approximate word-level token count
    file_path: str = ""  # source file (for cross-file analysis)
    cluster_id: int = -1  # topic cluster assignment
    embedding_int8: tuple[int, ...] | None = None  # int8 quantized 384-d embedding
    heading_context: str = ""  # parent heading text (for context-aware embedding)
    depth: int | None = None  # heading level 1-6 (set on heading atoms)
    plain_text: str = ""  # AST-stripped text for NLP/embedding
    rule: str = ""  # which classifier rule fired (p1_negation_phrase, p3c_verb0_use, etc.)
    ambiguous: bool = False  # True when charge depends on verb-noun interpretation
    charge_confidence: float = 1.0  # 0.0-1.0 confidence in charge classification
    embedded_charge_markers: list[str] = field(default_factory=list)  # charge markers found in neutral atoms
    # Optional fields (topographer-classified maps)
    topics: tuple[str, ...] = ()  # noun phrases from topographer
    role: str = ""  # directive | constraint | anchor | glue


@dataclass
class TopicCluster:
    """A group of atoms on the same topic, from embedding-based clustering."""

    topic_id: int
    atoms: list[Atom]
    charged: list[Atom]
    j: float  # per-topic charge density (structural stat only)
    centroid: tuple[float, ...] = ()  # L2-normalized mean of member embeddings


@dataclass
class FileRecord:
    """A source file in the ruleset with M2 loading metadata."""

    path: str
    content_hash: str  # sha256:hex
    loading: str = "session_start"  # session_start | on_demand | on_invocation
    scope: str = "global"  # global | path_scoped | task_scoped
    globs: tuple[str, ...] = ()  # activation patterns (on_demand/on_invocation)
    agent: str = "generic"  # owning agent (claude, codex, copilot, etc.)
    description: str = ""  # frontmatter name+description (always in base context)
    description_embedding: tuple[int, ...] | None = None  # int8 quantized embedding


@dataclass
class ClusterRecord:
    """A topic cluster with centroid."""

    id: int
    n_atoms: int
    n_charged: int
    n_neutral: int
    centroid: tuple[float, ...] = ()  # 384-d embedding (empty if single-atom cluster)


@dataclass
class RulesetSummary:
    """Aggregate statistics for the ruleset."""

    n_atoms: int
    n_charged: int
    n_neutral: int
    n_topics: int = 0
    n_topics_charged: int = 0


@dataclass
class RulesetMap:
    """Compact map of an instruction ruleset — the wire format."""

    schema_version: str
    embedding_model: str
    generated_at: str  # ISO 8601
    files: tuple[FileRecord, ...]
    atoms: tuple[Atom, ...]
    clusters: tuple[ClusterRecord, ...] = ()
    summary: RulesetSummary = field(default_factory=lambda: RulesetSummary(0, 0, 0))


# ──────────────────────────────────────────────────────────────────
# KNOWN CODE TOKENS — things that should be in backticks
# ──────────────────────────────────────────────────────────────────

KNOWN_CODE_TOKENS: set[str] = {
    # Python
    "pytest",
    "unittest",
    "mypy",
    "ruff",
    "black",
    "flake8",
    "pylint",
    "pip",
    "pipx",
    "poetry",
    "pdm",
    "dataclass",
    "dataclasses",
    "pydantic",
    "fastapi",
    "flask",
    "django",
    "numpy",
    "scipy",
    "pandas",
    "sklearn",
    "spacy",
    "transformers",
    # JS/TS
    "npm",
    "npx",
    "yarn",
    "pnpm",
    "webpack",
    "vite",
    "eslint",
    "prettier",
    "typescript",
    "tsx",
    "jsx",
    # Tools
    "git",
    "docker",
    "kubectl",
    "terraform",
    "ansible",
    "curl",
    "wget",
    "jq",
    "sed",
    "awk",
    "grep",
    # Formats / config
    "json",
    "yaml",
    "toml",
    # Our project
    "ails",
    "reporails",
    "topographer",
    "conftest",
    "parametrize",
}

# Single-pass regex for all KNOWN_CODE_TOKENS.  Sorted longest-first so
# the alternation engine prefers longer matches (e.g. "dataclasses" over
# "dataclass"), though word-boundary assertions make this a safety belt.
_KNOWN_TOKEN_RE = re.compile(
    r"(?<![`\w])(" + "|".join(re.escape(t) for t in sorted(KNOWN_CODE_TOKENS, key=len, reverse=True)) + r")(?![`\w])",
    re.IGNORECASE,
)

# Abbreviations that look like dotted names but aren't code
_DOTTED_EXCLUSIONS: set[str] = {
    "e.g",
    "i.e",
    "a.m",
    "p.m",
    "vs.",
    "cf.",
    "al.",
    "e.g.",
    "i.e.",
    "a.m.",
    "p.m.",
}

_DOTTED_EXCLUSIONS_NORMALIZED: frozenset[str] = frozenset(e.rstrip(".") for e in _DOTTED_EXCLUSIONS)

# Patterns that look like code but aren't in backticks
CODE_SHAPE_RE = re.compile(
    r"(?<![`\w])"
    r"("
    r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*"  # dotted.name
    r"|[a-z_][a-z0-9_]*\(\)"  # function()
    r"|[A-Z][a-z]+[A-Z]\w+"  # CamelCase
    r"|[a-z]+_[a-z]+_[a-z]+"  # multi_snake_case (3+ parts)
    r"|\w+\.(py|js|ts|yml|yaml|md|json|toml|cfg|ini|sh|env)"  # file.ext
    r"|--[a-z][\w-]+"  # --cli-flag
    r")"
    r"(?![`\w])",
)

_BACKTICK_RE = re.compile(r"`[^`]+`")
_ITALIC_RE = re.compile(r"(?<!\*)\*([^*]+)\*(?!\*)")
_BOLD_TERM_RE = re.compile(r"\*\*([^*]+)\*\*")
# Negation/prohibition phrases — bold on these is harmless
_BOLD_NEGATION_RE = re.compile(
    r"^(do not|don't|never|avoid|must not|shall not|cannot|can't|should not|won't|will not)\b",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────────────────────────
# RULE-BASED CHARGE CLASSIFIER
# Corpus-calibrated verb lexicon from 434 projects (13,789 atoms).
# Three phases: negation → modal → imperative verb detection.
# No spaCy dependency.
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
_MODAL_HEDGED: set[str] = {"should", "could", "might"}
# Removed: "can" (capability), "may" (possibility) — not instructions.
_ABSOLUTE_ADVERBS: set[str] = {"always", "only", "exclusively"}

# Phase 3: Corpus-calibrated verb lexicon
# CORE: charged_ratio >= 0.80, count >= 5 across 434 projects
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
# SUPPLEMENT: legitimate verbs too low-frequency in 434-project corpus
_VERBS_SUPPLEMENT: set[str] = {
    "accept",
    "achieve",
    "activate",
    "adapt",
    "adjust",
    "advise",
    "analyze",
    "annotate",
    "assess",
    "assign",
    "assist",
    "audit",
    "avoid",
    "be",
    "begin",
    "capture",
    "choose",
    "clarify",
    "classify",
    "collaborate",
    "compare",
    "confirm",
    "consolidate",
    "coordinate",
    "continue",
    "convert",
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
# AMBIGUOUS: corpus ratio 0.60-0.80 or genuinely dual noun/verb in tech context
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

_CONDITIONAL_MARKERS: set[str] = {
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

# Context words that can precede an imperative verb without blocking detection.
_CONTEXT_WORDS = _CONDITIONAL_MARKERS | {
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

# Finite verbs that signal a descriptive sentence (subject + predicate).
# Only includes unambiguous 3rd-person forms — words like "tests", "returns",
# "calls" are excluded because they're commonly nouns in instruction files
# ("Run tests", "Use early returns", "API calls").
_FINITE_VERB_RE = re.compile(
    r"\b(is|are|was|were|has|have|had|does|did"
    r"|applies|operates|contains|provides|requires|includes"
    r"|degrades|produces|generates|supports|handles"
    r"|manages|maintains|sends|connects|implements"
    r"|triggers|fetches|stores|processes|validates|accepts"
    r"|exists|means|comes|needs|works|gets|goes|takes"
    r"|tells|lives|varies)\b",
)

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
    t = re.sub(r"`([^`]*)`", r"\1", text)
    t = re.sub(r"\*{2}([^*]+)\*{2}", r"\1", t)
    t = re.sub(r"(?<!\*)\*([^*]+)\*(?!\*)", r"\1", t)
    return t.strip().lstrip("-+>#0123456789. ")


def _classify_words(text: str) -> list[str]:
    """Extract alphabetic words from text."""
    return _CLASSIFY_WORD_RE.findall(text)


def _starts_with_bold_verb(md_text: str) -> bool:
    """Check if text starts with single-word **Verb** pattern.

    Multi-word bold spans like **Build configuration** are labels, not
    instructions — only single-word bold verbs (**Use**, **Run**) qualify.
    """
    raw = md_text.strip().lstrip("-+>#0123456789. ")
    m = re.match(r"^\*{2}([^*]+)\*{2}", raw)
    if not m:
        return False
    bold_words = _CLASSIFY_WORD_RE.findall(m.group(1))
    return bool(bold_words and len(bold_words) == 1 and bold_words[0].lower() in _ALL_VERBS)


def _after_bold_label(md_text: str) -> str | None:
    """Return text after **Label**: / **Label** — patterns, or None."""
    raw = md_text.strip().lstrip("-+>#0123456789. ")
    m = re.match(r"^\*{2}[^*]+\*{2}\s*[:\u2014\u2013.!?/-]\s*", raw)
    if m:
        return raw[m.end() :]
    m = re.match(r"^\*{2}[^*]+\*{2}\s+", raw)
    if m:
        return raw[m.end() :]
    return None


def _is_descriptive(words: list[str], clean: str) -> bool:
    """Detect descriptive sentences where the first word is a noun subject.

    Only checks word positions 1-2 of the main clause for finite verbs.
    A finite verb deeper in the sentence is in a subordinate structure.
    """
    if len(words) < 2:
        return False
    main = re.split(
        r"[.!?]\s+|\s+[-\u2014\u2013]+\s+"
        r"|\s+(?:if|when|where|unless|while|although|that|which)\s+",
        clean,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0]
    mw = _CLASSIFY_WORD_RE.findall(main)
    if len(mw) < 2:
        return False
    check = " ".join(mw[1 : min(3, len(mw))])
    return bool(_FINITE_VERB_RE.search(check))


def _find_verb_idx(lowers: list[str]) -> int:
    """Index of first known verb in word list, or -1."""
    for i, w in enumerate(lowers):
        if w in _ALL_VERBS:
            return i
    return -1


# Conditional marker set excluding "for" — reused across scope detection.
_COND_CHECK = _CONDITIONAL_MARKERS - {"for"}


def _detect_scope_conditional(doc: Any, has_cond_prefix: bool) -> bool:
    """Detect conditional scope frame from first 8 tokens of a spaCy doc."""
    lowers = [t.text.lower() for t in doc[:8]]
    has_cond = any(w in _COND_CHECK for w in lowers)
    return has_cond_prefix or has_cond


def _is_root_in_backtick(
    root_lower: str,
    clean: str,
    md_text: str,
    inline_tokens: list[InlineToken] | None,
) -> bool:
    """Check if the ROOT word falls inside a backtick span."""
    if inline_tokens is not None:
        for itok in inline_tokens:
            if itok.text.lower() == root_lower:
                return itok.format == "backtick"
        return False
    # Regex fallback: position-0 heuristic for direct calls
    root_pos = clean.lower().find(root_lower)
    if root_pos == -1 or root_pos != 0:
        return False
    return any(root_lower in _CLASSIFY_WORD_RE.findall(m.group().lower()) for m in _BACKTICK_RE.finditer(md_text))


def _is_advcl_rescue_candidate(doc: Any) -> bool:
    """Check if position-0 token qualifies for advcl verb rescue."""
    return (
        len(doc) > 0
        and doc[0].tag_ in {"VB", "VBP"}
        and doc[0].dep_ in ("advcl", "ccomp", "ROOT")
        and doc[0].text.lower() in _ALL_VERBS
        and doc[0].text.lower() not in _VERBS_AMBIGUOUS
    )


def _check_colon_label(doc: Any, root: Any) -> tuple[str, int, str, str, bool] | None:
    """Detect 'Noun: verb ...' label pattern in early tokens.

    Returns NEUTRAL result if a noun-colon label is found, None otherwise.
    Guard: skip when position 0 is a known verb (verb-object-colon pattern).
    """
    if len(doc) > 0 and doc[0].text.lower() in _ALL_VERBS:
        return None
    for tok in doc:
        if tok.i >= root.i:
            break
        if tok.text == ":" and 0 < tok.i <= 4:
            if any(t.text.lower() in _CONDITIONAL_MARKERS for t in doc[: tok.i]):
                break  # conditional clause break, not a label
            prev = doc[tok.i - 1]
            if prev.tag_ in {"NN", "NNS", "NNP", "NNPS"}:
                return ("NEUTRAL", 0, "none", "p3_spacy_colon_label", False)
    return None


def _check_postcolon_verb(doc: Any) -> tuple[str, int, str, str, bool] | None:
    """Post-colon verb rescue: conditional markers before colon, verb after.

    Returns IMPERATIVE result if a conditional-colon-verb pattern is found,
    None otherwise. Shared by NN and non-verb tag branches.
    """
    colon_idx = next((t.i for t in doc if t.text == ":"), -1)
    if colon_idx <= 0:
        return None
    if not any(t.text.lower() in _CONDITIONAL_MARKERS for t in doc[:colon_idx]):
        return None
    for pt in (t for t in doc if t.i > colon_idx):
        if pt.i > colon_idx + 3:
            break
        if pt.text.lower() in _ALL_VERBS and pt.tag_ in {"VB", "VBP", "VBG", "VBN"}:
            return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_postcolon_verb", True)
    return None


def _classify_nn_tag(
    doc: Any,
    root: Any,
    has_subj: bool,
    has_cond_prefix: bool,
) -> tuple[str, int, str, str, bool]:
    """POS classification for NN/NNS/NNP/NNPS root tags."""
    # Lexicon override: imperative verbs mistagged as nouns at position 0
    if root.i == 0 and root.text.lower() in _ALL_VERBS:
        sc = _detect_scope_conditional(doc, has_cond_prefix)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_verb0", sc)
    # Position-0 verb rescue: non-ambiguous verb demoted by spaCy
    t0_lower = doc[0].text.lower() if len(doc) > 0 else ""
    if root.i > 0 and not has_subj and t0_lower in _ALL_VERBS and t0_lower not in _VERBS_AMBIGUOUS:
        sc = _detect_scope_conditional(doc, has_cond_prefix)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_verb0_rescue", sc)
    # Post-colon verb rescue
    pcv = _check_postcolon_verb(doc)
    if pcv is not None:
        return pcv
    return ("NEUTRAL", 0, "none", "p3_spacy_nn", False)


def _classify_vb_vbp_tag(
    doc: Any,
    root: Any,
    tag: str,
    has_subj: bool,
    has_cond_prefix: bool,
    *,
    shallow: bool,
) -> tuple[str, int, str, str, bool] | None:
    """POS classification for VB/VBP root tags.

    Returns 5-tuple result or None to fall through to lexicon.
    """
    subj_trace = f"p3_spacy_{tag.lower()}_subj"
    if has_subj:
        return ("NEUTRAL", 0, "none", subj_trace, False)
    # In shallow mode, only charge if pre-root words are context words
    if shallow and root.i > 0:
        pre_words = {t.text.lower() for t in doc[: root.i]}
        if not (pre_words <= _CONTEXT_WORDS):
            return None  # fall through to lexicon
    # Lexicon cross-check: only charge confirmed verbs
    if root.text.lower() not in _ALL_VERBS:
        return None  # fall through to lexicon
    sc = _detect_scope_conditional(doc, has_cond_prefix)
    if tag == "VBP":
        next_tok = doc[root.i + 1] if root.i + 1 < len(doc) else None
        if next_tok and (next_tok.tag_ == "DT" or next_tok.dep_ == "dobj"):
            return ("IMPERATIVE", 1, "imperative", "p3_spacy_vbp_det", sc)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_vbp!amb", sc)
    return ("IMPERATIVE", 1, "imperative", "p3_spacy_vb", sc)


def _classify_nonverb_tag(
    doc: Any,
    root: Any,
    tag: str,
) -> tuple[str, int, str, str, bool]:
    """POS classification for non-verb root tags (JJ, RB, CD, etc.)."""
    if root.i == 0 and root.text.lower() in _ALL_VERBS:
        amb = "!amb" if root.text.lower() in _VERBS_AMBIGUOUS else ""
        return ("IMPERATIVE", 1, "imperative", f"p3_spacy_{tag.lower()}_verb0{amb}", False)
    # Post-colon verb rescue for conditional markers as ROOT
    pcv = _check_postcolon_verb(doc)
    if pcv is not None:
        # Rename trace for non-verb branch
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_postcolon_verb", True)
    return ("NEUTRAL", 0, "none", f"p3_spacy_{tag.lower()}", False)


_VERB0_RESCUE_DEPS = frozenset({"csubj", "compound", "nmod", "dep", "amod", "advcl", "ccomp"})


def _check_verb0_rescue(
    doc: Any,
    root: Any,
    has_cond_prefix: bool,
) -> tuple[str, int, str, str, bool] | None:
    """Check position-0 verb rescue: advcl rescue and general dep-demotion rescue.

    Returns IMPERATIVE result if position 0 has a non-ambiguous verb that
    spaCy demoted, or None to continue classification.
    """
    if root.i == 0 or len(doc) == 0:
        return None
    t0_lower = doc[0].text.lower()
    if t0_lower not in _ALL_VERBS or t0_lower in _VERBS_AMBIGUOUS:
        return None
    # advcl/ccomp rescue (verb at pos 0 demoted by clause boundary)
    if doc[0].tag_ in {"VB", "VBP"} and doc[0].dep_ in ("advcl", "ccomp", "ROOT"):
        sc = _detect_scope_conditional(doc, has_cond_prefix)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_vb_advcl_rescue", sc)
    # General rescue (csubj, compound, nmod, etc.)
    if doc[0].dep_ in _VERB0_RESCUE_DEPS:
        sc = _detect_scope_conditional(doc, has_cond_prefix)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_verb0_rescue", sc)
    return None


_PAST_TENSE_TAGS = frozenset({"VBZ", "VBD", "VBN", "VBG"})


def _spacy_pre_checks(
    doc: Any,
    root: Any,
    clean: str,
    md_text: str,
    has_cond_prefix: bool,
    inline_tokens: list[InlineToken] | None,
) -> tuple[str, int, str, str, bool] | None:
    """Run pre-POS checks: backtick filter, verb0 rescue, colon label."""
    if _is_root_in_backtick(root.text.lower(), clean, md_text, inline_tokens):
        return ("NEUTRAL", 0, "none", "p3_spacy_backtick", False)
    rescue = _check_verb0_rescue(doc, root, has_cond_prefix)
    if rescue is not None:
        return rescue
    return _check_colon_label(doc, root)


def _classify_phase3_spacy(
    clean: str,
    md_text: str,
    nlp: Any,
    has_cond_prefix: bool,
    *,
    shallow: bool = False,
    inline_tokens: list[InlineToken] | None = None,
) -> tuple[str, int, str, str, bool] | None:
    """Phase 3 imperative detection via spaCy dependency parse.

    Returns 5-tuple (charge, cv, modality, rule_trace, scope_conditional)
    or None to fall through to verb lexicon.

    When shallow=True (called from bold-label recursive path), only
    charge when root is VB at position 0 — avoids over-charging
    descriptive text after labels.
    """
    doc = nlp(clean)

    # Find ROOT token
    root = None
    for tok in doc:
        if tok.dep_ == "ROOT":
            root = tok
            break
    if root is None:
        return None

    pre = _spacy_pre_checks(doc, root, clean, md_text, has_cond_prefix, inline_tokens)
    if pre is not None:
        return pre

    has_subj = any(child.dep_ in ("nsubj", "nsubjpass") for child in root.children)
    tag = root.tag_

    # POS classification by tag group
    if tag in {"NN", "NNS", "NNP", "NNPS"}:
        return _classify_nn_tag(doc, root, has_subj, has_cond_prefix)
    if tag in _PAST_TENSE_TAGS:
        return ("NEUTRAL", 0, "none", f"p3_spacy_{tag.lower()}", False)
    if tag in {"VB", "VBP"}:
        return _classify_vb_vbp_tag(doc, root, tag, has_subj, has_cond_prefix, shallow=shallow)
    return _classify_nonverb_tag(doc, root, tag)


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
        # "No X is/are/was/were Y" is descriptive, not a prohibition.
        if lowers[0] == "no" and any(
            v in {"is", "are", "was", "were", "has", "have", "does", "did"} for v in lowers[1:8]
        ):
            pass  # fall through — descriptive "No X is Y" pattern
        else:
            return "CONSTRAINT", -1, "absolute" if lowers[0] == "never" else "direct", "p1_prohibition_start", False
    if words[0] in ("NOT", "NO", "NEVER"):
        return "CONSTRAINT", -1, "absolute", "p1_caps_negation", False
    first_clause = re.split(r"[,;.]", clean, maxsplit=1)[0]
    if _MID_NEGATION_RE.search(first_clause):
        return "CONSTRAINT", -1, "direct", "p1_mid_negation", has_cond_prefix
    if _LATE_DONOT_RE.search(first_clause):
        return "CONSTRAINT", -1, "direct", "p1_late_donot", has_cond_prefix
    return None


_NEGATION_WORDS = frozenset({"not", "never", "n't"})


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
    next_negated = i + 1 < len(lowers) and lowers[i + 1] in _NEGATION_WORDS
    if w in _MODAL_ABSOLUTE:
        return _modal_result(next_negated, "absolute", f"p2_modal_{w}", "p2_modal_negated")
    if w in _MODAL_HEDGED:
        if next_negated:
            return "CONSTRAINT", -1, "hedged", f"p2_hedged_{w}_negated", False
        is_positioned = (
            w == "should"
            or i == 0
            or (i > 0 and lowers[i - 1] in ("you", "we"))
            or (i > 0 and lowers[i - 1] in _CONDITIONAL_MARKERS)
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


# Determiners for verb-noun disambiguation in Phase 3c
_DETERMINERS: frozenset[str] = frozenset(
    {
        "the",
        "a",
        "an",
        "any",
        "all",
        "each",
        "every",
        "this",
        "that",
        "these",
        "those",
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
)

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
            has_cond = any(w in _CONDITIONAL_MARKERS for w in sl[:6])
            amb = "!amb" if sl[0] in _VERBS_AMBIGUOUS else ""
            return "IMPERATIVE", 1, "imperative", f"p3e_break_{sl[0]}{amb}", has_cond
        if sl[0] in _CONDITIONAL_MARKERS:
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
    has_cond = bool(pre & _CONDITIONAL_MARKERS)
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
    if lowers[0] in _CONDITIONAL_MARKERS:
        return "IMPERATIVE", 1, "imperative", f"p3f_cond_{lowers[0]}", True

    # 3g: Mid-sentence verb with conditional marker before it
    if lowers[0] not in _DECLARATIVE_STARTS and verb_idx <= 7 and pre & _CONDITIONAL_MARKERS:
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
            if pos1 not in _DETERMINERS:
                amb = "!amb"
        has_cond = any(w in _COND_CHECK for w in lowers[1:8])
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
    has_cond_prefix: bool,
    *,
    shallow: bool,
    inline_tokens: list[InlineToken] | None,
) -> tuple[str, int, str, str, bool]:
    """Phase 3: Imperative verb detection (spaCy + lexicon fallback)."""
    # 3b: Bold label recursive
    if not shallow:
        p3b = _classify_phase3b_bold(md_text)
        if p3b is not None:
            return p3b

    # 3_spacy: primary Phase 3
    nlp = get_models().nlp
    if nlp is not None:
        result = _classify_phase3_spacy(
            clean,
            md_text,
            nlp,
            has_cond_prefix,
            shallow=shallow,
            inline_tokens=inline_tokens,
        )
        if result is not None:
            return result

    # 3c-3g: fallback verb lexicon
    verb_idx = _find_verb_idx(lowers)
    if verb_idx == -1:
        return "NEUTRAL", 0, "none", "p3_no_verb", False
    return _classify_phase3_lexicon(clean, lowers, verb_idx, shallow=shallow)


def classify_charge(
    md_text: str,
    *,
    plain_text: str | None = None,
    _shallow: bool = False,
    inline_tokens: list[InlineToken] | None = None,
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
      Phase 3 — Imperative verb detection (corpus-calibrated lexicon) → IMPERATIVE

    When _shallow=True (recursive from Phase 3b), only high-precision
    phases fire: Phase 1, Phase 2, Phase 3a, Phase 3c. Phases 3d-3g
    (deep mid-sentence detection) are skipped to avoid noise from
    descriptive text after bold labels.
    """
    clean = plain_text.strip().lstrip("-+>#0123456789. ") if plain_text is not None else _strip_md_for_classify(md_text)
    if len(clean) < 3:
        return "NEUTRAL", 0, "none", "short_text", False

    words = _classify_words(clean)
    if not words:
        return "NEUTRAL", 0, "none", "no_words", False
    lowers = [w.lower() for w in words]
    has_cond_prefix = lowers[0] in _CONDITIONAL_MARKERS

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
        has_cond_prefix,
        shallow=_shallow,
        inline_tokens=inline_tokens,
    )


def check_specificity(
    text: str,
) -> tuple[str, list[str], list[str], list[str], list[str]]:
    """Check for named constructs, italic tokens, bold tokens, and unformatted code tokens.

    Returns:
        (named|abstract, named_tokens, unformatted_code_tokens, italic_tokens, bold_tokens)
    """
    backtick_content = set(_BACKTICK_RE.findall(text))
    named = [m.strip("`") for m in backtick_content]

    text_no_bold = _BOLD_TERM_RE.sub("", text)
    italic = _ITALIC_RE.findall(text_no_bold)

    # Bold tokens — exclude negation phrases (bold on prohibitions is harmless)
    bold_raw = _BOLD_TERM_RE.findall(text)
    bold = [b for b in bold_raw if not _BOLD_NEGATION_RE.match(b)]

    text_no_bt = _BACKTICK_RE.sub("", text)
    unformatted: list[str] = []

    # Pre-lowercase backtick content once for O(1)-ish lookups below.
    bt_lower = {bt.lower() for bt in backtick_content}

    # Single regex pass finds all known code tokens in one engine invocation.
    seen: set[str] = set()
    for m in _KNOWN_TOKEN_RE.finditer(text_no_bt):
        tok = m.group(1).lower()
        if tok not in seen:
            seen.add(tok)
            if not any(tok in bt for bt in bt_lower):
                unformatted.append(tok)

    for m in CODE_SHAPE_RE.finditer(text_no_bt):
        token = m.group(1)
        if token.lower().rstrip(".") in _DOTTED_EXCLUSIONS_NORMALIZED:
            continue
        if token not in unformatted and not any(token in bt for bt in bt_lower):
            unformatted.append(token)

    # Named if ANY construct is identified — backtick-wrapped OR unformatted known token.
    # The model recognizes `pytest` with or without backticks at the token level.
    spec = "named" if (named or unformatted) else "abstract"
    return spec, named, unformatted, italic, bold


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

    return atoms


# Sentence boundary: period/exclamation/question followed by whitespace
# and then uppercase letter or markdown emphasis (*bold*, **italic**).
# Excludes common abbreviations (e.g., i.e., etc., vs.).
_SENTENCE_SPLIT_RE = re.compile(
    r"(?<!\be\.g)(?<!\bi\.e)(?<!\betc)(?<!\bvs)"
    r"[.!?]\s+(?=[A-Z*])"
)


def _split_sentences(text: str) -> list[str] | None:
    """Split text at sentence boundaries. Returns None if fewer than 2 sentences."""
    splits = list(_SENTENCE_SPLIT_RE.finditer(text))
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
# MODEL LOADING (lazy singleton)
# ──────────────────────────────────────────────────────────────────


_UNSET = object()


class Models:
    """Lazy-loaded models. Load once, reuse across files.

    Thread-safe: both ``.st`` and ``.nlp`` lazy loads are guarded by a lock
    so the daemon's background warmup thread and a serving thread can't
    double-initialise the same model.
    """

    def __init__(self) -> None:
        import threading as _threading

        self._st: Any | None = None
        self._nlp: Any = _UNSET
        self._st_lock = _threading.Lock()
        self._nlp_lock = _threading.Lock()

    @property
    def st(self) -> Any:
        if self._st is None:
            with self._st_lock:
                if self._st is None:
                    # ONNX Runtime directly on the bundled MiniLM-L6-v2 ONNX
                    # export — no torch, no sentence-transformers. Loads in
                    # ~0.3s (vs ~20s for `import torch`), produces bit-identical
                    # output to the PyTorch reference (float32 epsilon).
                    # ORT and PyTorch hit the SAME per-atom throughput on this
                    # model (~67 atoms/s bs=32, ~86 atoms/s length-sorted) —
                    # both dispatch to MLAS kernels. The torch import cost was
                    # the only real bottleneck, and the _torch_blocker hook at
                    # CLI/MCP/daemon entry points eliminates it.
                    try:
                        from reporails_cli.core.mapper.onnx_embedder import OnnxEmbedder
                    except ImportError as exc:
                        raise RuntimeError("onnxruntime / tokenizers not installed.\nRun: uv sync") from exc
                    self._st = OnnxEmbedder()
        return self._st

    @property
    def nlp(self) -> Any | None:
        if self._nlp is _UNSET:
            with self._nlp_lock:
                if self._nlp is _UNSET:
                    try:
                        import spacy

                        # Phase 3 classification only reads tok.dep_ / tok.tag_ /
                        # tok.text / tok.i / root.children. That needs tok2vec +
                        # tagger + parser only; ner / lemmatizer / attribute_ruler
                        # are dead weight on both load time and per-doc inference.
                        try:
                            self._nlp = spacy.load(
                                "en_core_web_sm",
                                disable=["ner", "lemmatizer", "attribute_ruler"],
                            )
                        except OSError:
                            # Model not installed — download it once
                            import subprocess
                            import sys

                            subprocess.run(
                                [sys.executable, "-m", "spacy", "download", "en_core_web_sm"],
                                capture_output=True,
                            )
                            self._nlp = spacy.load(
                                "en_core_web_sm",
                                disable=["ner", "lemmatizer", "attribute_ruler"],
                            )
                    except (ImportError, OSError):
                        self._nlp = None
        return self._nlp

    def warmup(self) -> None:
        """Eagerly load both models in parallel.

        Both loads are CPU-bound in native code that releases the GIL, so
        threads actually parallelise. Saves roughly ``min(T_spacy, T_st)``
        on cold start. Idempotent — safe to call multiple times.
        """
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=2) as pool:
            fut_st = pool.submit(lambda: self.st)
            fut_nlp = pool.submit(lambda: self.nlp)
            # Surface exceptions from the ST load (nlp load already tolerates
            # ImportError/OSError and stores None).
            fut_st.result()
            fut_nlp.result()


_models: Models | None = None


def get_models() -> Models:
    """Get or create the lazy model singleton."""
    global _models
    if _models is None:
        _models = Models()
    return _models


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


# ──────────────────────────────────────────────────────────────────
# @PATH IMPORT EXPANSION
# ──────────────────────────────────────────────────────────────────

# Match @path references in instruction files.
# Claude Code: @README, @docs/guide.md, @~/path, @./relative
# Gemini CLI: @./path.md, @../path.md, @/absolute/path.md
# Must NOT match: email@addr, @mentions in code blocks, inline `@code`
_IMPORT_REF_RE = re.compile(
    r"(?<![`\w@])"  # not inside backtick or after word char/@ (email)
    r"@("
    r"~[\w./_-]+"  # ~/home/path
    r"|\.\.?/[\w./_-]+"  # ./relative or ../parent
    r"|[\w][\w./_-]*/[\w./_-]+"  # path/with/slash (must have at least one /)
    r"|[\w][\w._-]*\.m(?:d|dc)"  # bare file.md or file.mdc
    r"|[A-Z][\w._-]*"  # UPPERCASE bare filename (README, AGENTS, CHANGELOG)
    r")"
)

# Non-markdown extensions that should NOT be expanded
_NON_EXPANDABLE_EXT = frozenset(
    {
        ".json",
        ".yml",
        ".yaml",
        ".toml",
        ".py",
        ".js",
        ".ts",
        ".sh",
        ".env",
        ".lock",
        ".txt",
        ".cfg",
        ".ini",
        ".xml",
        ".html",
        ".css",
    }
)

_MAX_IMPORT_DEPTH = 5

# Fenced code block pattern for stripping before import detection
_FENCED_BLOCK_RE = re.compile(r"^(`{3,}|~{3,}).*?^\1", re.MULTILINE | re.DOTALL)


def _resolve_import_target(
    ref: str,
    source_path: Path,
    visited: set[str],
) -> Path | None:
    """Resolve an @path reference to a file path.

    Returns the resolved Path if it should be expanded, or None if it should
    be left as-is (non-expandable ext, circular, broken, etc.).
    """
    if ref.startswith("~"):
        target = Path(ref).expanduser()
    else:
        target = source_path.parent / ref
    try:
        target = target.resolve(strict=False)
    except (OSError, RuntimeError):
        return None  # circular or broken symlink
    if target.suffix.lower() in _NON_EXPANDABLE_EXT:
        return None
    if str(target) in visited:
        return None
    if not target.is_file():
        return None
    return target


def expand_imports(
    content: str,
    source_path: Path,
    *,
    depth: int = 0,
    visited: set[str] | None = None,
) -> str:
    """Expand @path inline imports in instruction file content.

    Claude Code and Gemini CLI use @path syntax for inline expansion —
    the file content is spliced in at the reference position before the
    model sees it. The mapper must see the same expanded content.

    - Resolves paths relative to the importing file's directory
    - Expands ~/... to home directory
    - Recursively expands up to MAX_IMPORT_DEPTH (5 hops)
    - Detects circular imports via visited set
    - Only expands markdown-compatible files
    - Skips @references inside fenced code blocks
    """
    if depth >= _MAX_IMPORT_DEPTH:
        return content
    if visited is None:
        visited = {str(source_path.resolve())}

    code_ranges = [(m.start(), m.end()) for m in _FENCED_BLOCK_RE.finditer(content)]

    def _in_code_block(pos: int) -> bool:
        return any(start <= pos < end for start, end in code_ranges)

    def _replace(match: re.Match[str]) -> str:
        if _in_code_block(match.start()):
            return match.group(0)
        target = _resolve_import_target(match.group(1), source_path, visited)
        if target is None:
            return match.group(0)
        try:
            imported = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return match.group(0)
        visited.add(str(target))
        return expand_imports(imported, target, depth=depth + 1, visited=visited)

    return _IMPORT_REF_RE.sub(_replace, content)


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
        from reporails_cli.core.bootstrap import get_rules_path

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

    from reporails_cli.core.agents import _extract_patterns, _extract_properties

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
    rel = str(path.relative_to(root)) if path.is_relative_to(root) else str(path)
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
    from reporails_cli.core.mapper.map_cache import (
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
    from reporails_cli.core.mapper.map_cache import CachedFileEntry, atoms_to_dicts

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
    from reporails_cli.core.mapper.map_cache import MapCache

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

    # Evict stale cache entries and save
    if map_cache is not None:
        map_cache.evict_stale({fr.content_hash for fr in file_records})
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
