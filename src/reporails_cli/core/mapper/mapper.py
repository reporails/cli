# pylint: disable=C0302
# ruff: noqa: C901, SIM102, SIM108, N806, PERF401, F541, RUF034
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

    tag = root.tag_

    # Backtick filter: neutralise when the ROOT word is inside a backtick span.
    # Two paths: inline_tokens (AST-derived, used by pipeline) and regex
    # fallback (used by direct classify_charge calls from tests/calibration).
    _root_lower = root.text.lower()
    if inline_tokens is not None:
        # AST path: check if the FIRST token matching ROOT word is backtick.
        # Must be first-occurrence — "Run `uv run`" has ROOT "Run" (plain)
        # but a different "run" inside backticks.
        for itok in inline_tokens:
            if itok.text.lower() == _root_lower:
                if itok.format == "backtick":
                    return ("NEUTRAL", 0, "none", "p3_spacy_backtick", False)
                break  # first occurrence is not backtick — stop
    else:
        # Regex fallback: position-0 heuristic for direct calls
        _root_pos_in_clean = clean.lower().find(_root_lower)
        if _root_pos_in_clean != -1:
            _in_backtick = False
            for m in _BACKTICK_RE.finditer(md_text):
                span_lower = m.group().lower()
                if _root_lower in _CLASSIFY_WORD_RE.findall(span_lower):
                    if _root_pos_in_clean == 0:
                        _in_backtick = True
                        break
            if _in_backtick:
                return ("NEUTRAL", 0, "none", "p3_spacy_backtick", False)

    # Position-0 advcl verb rescue: when a colon or dash creates a clause
    # boundary, spaCy demotes the imperative verb at position 0 to advcl or
    # ccomp and picks a verb from the after-clause as ROOT. But the instruction
    # IS the pre-clause verb. "Check kill list: do not test..." has ROOT="test"
    # with has_subj=True, but "Check" at position 0 is the imperative.
    if (
        root.i > 0
        and len(doc) > 0
        and doc[0].tag_ in {"VB", "VBP"}
        and doc[0].dep_ in ("advcl", "ccomp", "ROOT")
        and doc[0].text.lower() in _ALL_VERBS
        and doc[0].text.lower() not in _VERBS_AMBIGUOUS
    ):
        cond_check = _CONDITIONAL_MARKERS - {"for"}
        lowers = [t.text.lower() for t in doc[:8]]
        has_cond = any(w in cond_check for w in lowers)
        sc = has_cond_prefix or has_cond
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_vb_advcl_rescue", sc)

    # Colon filter: "Noun: verb ..." label pattern — only when the colon
    # appears in the first 4 tokens (actual labels like "Testing:" or
    # "Security: be mindful").  Mid-sentence colons ("When X: do Y") are
    # clause breaks, not labels.
    #
    # Guard: skip when position 0 is a known verb — "Read theory state: ..."
    # is "Verb Object: continuation", not a descriptive label.
    _t0_is_verb = len(doc) > 0 and doc[0].text.lower() in _ALL_VERBS
    if not _t0_is_verb:
        for tok in doc:
            if tok.i >= root.i:
                break
            if tok.text == ":" and 0 < tok.i <= 4:
                # Guard: if any word before the colon is a conditional marker,
                # this is a conditional clause break ("before X: do Y"), not
                # a descriptive label.
                _pre_colon_has_cond = any(t.text.lower() in _CONDITIONAL_MARKERS for t in doc[: tok.i])
                if _pre_colon_has_cond:
                    break  # not a label — fall through to normal classification
                prev = doc[tok.i - 1]
                if prev.tag_ in {"NN", "NNS", "NNP", "NNPS"}:
                    return ("NEUTRAL", 0, "none", "p3_spacy_colon_label", False)

    # Check for subject dependents
    has_subj = any(child.dep_ in ("nsubj", "nsubjpass") for child in root.children)

    # General position-0 verb rescue: spaCy commonly demotes position-0
    # imperative verbs to csubj, compound, nmod, or other non-root deps
    # and picks a later word as ROOT. When position 0 has a known verb
    # from our corpus-calibrated lexicon, it's the imperative regardless
    # of what spaCy thinks ROOT is.
    # Examples: "Create custom commands..." (Create=csubj, ROOT=workflows)
    #           "Verify data location is..." (Verify=csubj, ROOT=is)
    #           "Use Taskmaster to expand..." (Use=compound, ROOT=expand)
    #           "Update docs/roadmap.md if..." (Update=nmod, ROOT=added)
    if root.i > 0 and len(doc) > 0:
        _t0_lower = doc[0].text.lower()
        if (
            _t0_lower in _ALL_VERBS
            and _t0_lower not in _VERBS_AMBIGUOUS
            and doc[0].dep_ in ("csubj", "compound", "nmod", "dep", "amod", "advcl", "ccomp")
        ):
            cond_check = _CONDITIONAL_MARKERS - {"for"}
            lowers = [t.text.lower() for t in doc[:8]]
            has_cond = any(w in cond_check for w in lowers)
            sc = has_cond_prefix or has_cond
            return ("IMPERATIVE", 1, "imperative", "p3_spacy_verb0_rescue", sc)

    # POS classification
    if tag in {"NN", "NNS", "NNP", "NNPS"}:
        # Lexicon override: spaCy often mistaggs imperative verbs as nouns
        # ("Use", "List", "Report", "Focus", etc.).  If the root is at
        # position 0 and the word is in our verb lexicon, treat as VB.
        if root.i == 0 and root.text.lower() in _ALL_VERBS:
            cond_check = _CONDITIONAL_MARKERS - {"for"}
            lowers = [t.text.lower() for t in doc[:8]]
            has_cond = any(w in cond_check for w in lowers)
            sc = has_cond_prefix or has_cond
            return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_verb0", sc)
        # Position-0 verb rescue: spaCy picked an NN as ROOT but position 0
        # has a known non-ambiguous verb — "Audit conditions", "Scan experiments/".
        # The verb was demoted (compound, amod, etc.) but is the imperative.
        # Excludes _VERBS_AMBIGUOUS ("Cache operations", "Process body") which
        # are genuinely noun compounds.
        _t0_lower = doc[0].text.lower()
        if root.i > 0 and not has_subj and _t0_lower in _ALL_VERBS and _t0_lower not in _VERBS_AMBIGUOUS:
            cond_check = _CONDITIONAL_MARKERS - {"for"}
            lowers = [t.text.lower() for t in doc[:8]]
            has_cond = any(w in cond_check for w in lowers)
            sc = has_cond_prefix or has_cond
            return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_verb0_rescue", sc)
        # Post-colon verb rescue: "[conditional frame]: [verb] ..."
        # spaCy picked a noun from after the colon as ROOT (often a path
        # component like "experiments"), but there's a known verb right after
        # the colon. Only fires when a conditional marker appears pre-colon,
        # confirming this is a conditional instruction, not a label.
        # E.g. "IMMEDIATELY before writing conditions: Re-read ..."
        _colon_idx = next((t.i for t in doc if t.text == ":"), -1)
        if _colon_idx > 0:
            _pre_has_cond = any(t.text.lower() in _CONDITIONAL_MARKERS for t in doc[:_colon_idx])
            if _pre_has_cond:
                _post_colon = [t for t in doc if t.i > _colon_idx]
                for _pt in _post_colon[:3]:
                    if _pt.text.lower() in _ALL_VERBS and _pt.tag_ in {"VB", "VBP", "VBG", "VBN"}:
                        return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_postcolon_verb", True)
        return ("NEUTRAL", 0, "none", "p3_spacy_nn", False)
    if tag == "VBZ":
        return ("NEUTRAL", 0, "none", "p3_spacy_vbz", False)
    if tag == "VBD":
        return ("NEUTRAL", 0, "none", "p3_spacy_vbd", False)
    if tag == "VBN":
        return ("NEUTRAL", 0, "none", "p3_spacy_vbn", False)
    if tag == "VBG":
        return ("NEUTRAL", 0, "none", "p3_spacy_vbg", False)

    if tag == "VB":
        if has_subj:
            return ("NEUTRAL", 0, "none", "p3_spacy_vb_subj", False)
        # In shallow mode (bold-label recursive), only charge if all tokens
        # before the root are context words (adverbs, conditionals, etc.).
        # Mid-sentence VB buried in descriptive text is noise.
        if shallow and root.i > 0:
            pre_words = {t.text.lower() for t in doc[: root.i]}
            if not (pre_words <= _CONTEXT_WORDS):
                return None  # fall through to lexicon
        # Lexicon cross-check: spaCy often mistaggs tech nouns as VB
        # ("Plugin", "Vite", "Frontend", "Sarif").  Only charge when
        # the root word is independently confirmed as a verb by our
        # corpus-calibrated lexicon.  Unknown words fall through to the
        # lexicon path which has its own disambiguation.
        if root.text.lower() not in _ALL_VERBS:
            return None  # fall through to lexicon
        # Imperative — detect scope
        cond_check = _CONDITIONAL_MARKERS - {"for"}
        lowers = [t.text.lower() for t in doc[:8]]
        has_cond = any(w in cond_check for w in lowers)
        sc = has_cond_prefix or has_cond
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_vb", sc)

    if tag == "VBP":
        if has_subj:
            return ("NEUTRAL", 0, "none", "p3_spacy_vbp_subj", False)
        # In shallow mode, same restriction as VB.
        if shallow and root.i > 0:
            pre_words = {t.text.lower() for t in doc[: root.i]}
            if not (pre_words <= _CONTEXT_WORDS):
                return None
        # Same lexicon cross-check as VB — fall through for unknown words
        if root.text.lower() not in _ALL_VERBS:
            return None
        # No subject — likely imperative, but VBP is ambiguous
        cond_check = _CONDITIONAL_MARKERS - {"for"}
        lowers = [t.text.lower() for t in doc[:8]]
        has_cond = any(w in cond_check for w in lowers)
        sc = has_cond_prefix or has_cond
        # Check if next token is DT or has dobj dependency
        next_tok = doc[root.i + 1] if root.i + 1 < len(doc) else None
        if next_tok and (next_tok.tag_ == "DT" or next_tok.dep_ == "dobj"):
            return ("IMPERATIVE", 1, "imperative", "p3_spacy_vbp_det", sc)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_vbp!amb", sc)

    # Non-verb tags (JJ, RB, CD, etc.) → NEUTRAL
    # But rescue known verbs at position 0 that spaCy mistagged
    # (e.g. "Close" as JJ, "Scan" as JJ).
    if tag not in {"VB", "VBP", "VBZ", "VBD", "VBN", "VBG"}:
        if root.i == 0 and root.text.lower() in _ALL_VERBS:
            amb = "!amb" if root.text.lower() in _VERBS_AMBIGUOUS else ""
            return ("IMPERATIVE", 1, "imperative", f"p3_spacy_{tag.lower()}_verb0{amb}", False)
        # Post-colon verb rescue (same logic as NN branch): conditional
        # markers like "After", "Before", "When" can be ROOT (IN/RB/etc.)
        # with the imperative verb after the colon.
        _colon_idx_nv = next((t.i for t in doc if t.text == ":"), -1)
        if _colon_idx_nv > 0:
            _pre_has_cond_nv = any(t.text.lower() in _CONDITIONAL_MARKERS for t in doc[:_colon_idx_nv])
            if _pre_has_cond_nv:
                _post_colon_nv = [t for t in doc if t.i > _colon_idx_nv]
                for _pt in _post_colon_nv[:3]:
                    if _pt.text.lower() in _ALL_VERBS and _pt.tag_ in {"VB", "VBP", "VBG", "VBN"}:
                        return ("IMPERATIVE", 1, "imperative", "p3_spacy_postcolon_verb", True)
        return ("NEUTRAL", 0, "none", f"p3_spacy_{tag.lower()}", False)

    # Unrecognized — fall through to lexicon
    return None


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
    if plain_text is not None:
        clean = plain_text.strip().lstrip("-+>#0123456789. ")
    else:
        clean = _strip_md_for_classify(md_text)
    if len(clean) < 3:
        return "NEUTRAL", 0, "none", "short_text", False

    words = _classify_words(clean)
    if not words:
        return "NEUTRAL", 0, "none", "no_words", False
    lowers = [w.lower() for w in words]

    # Helper: detect conditional scope frame from sentence-initial markers
    has_cond_prefix = lowers[0] in _CONDITIONAL_MARKERS if lowers else False

    # ── Phase 1: CONSTRAINT ──
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
    # First-clause restriction for mid-sentence negation.
    _first_clause = re.split(r"[,;.]", clean, maxsplit=1)[0]
    if _MID_NEGATION_RE.search(_first_clause):
        return "CONSTRAINT", -1, "direct", "p1_mid_negation", has_cond_prefix
    if _LATE_DONOT_RE.search(_first_clause):
        return "CONSTRAINT", -1, "direct", "p1_late_donot", has_cond_prefix

    # ── Phase 2: DIRECTIVE ──
    for i, w in enumerate(lowers):
        if w in _MODAL_ABSOLUTE:
            if i + 1 < len(lowers) and lowers[i + 1] in ("not", "never", "n't"):
                return "CONSTRAINT", -1, "absolute", "p2_modal_negated", False
            return "DIRECTIVE", 1, "absolute", f"p2_modal_{w}", False
        if w in _MODAL_HEDGED:
            if i + 1 < len(lowers) and lowers[i + 1] in ("not", "never", "n't"):
                return "CONSTRAINT", -1, "hedged", f"p2_hedged_{w}_negated", False
            # "should" fires at any position — corpus data shows "X should Y"
            # is always a directive regardless of subject.  "could"/"might" only
            # fire at position 0 or after you/we/conditional (ambiguous otherwise).
            if w == "should":
                return "DIRECTIVE", 1, "hedged", f"p2_hedged_{w}", False
            if (
                i == 0
                or (i > 0 and lowers[i - 1] in ("you", "we"))
                or (i > 0 and lowers[i - 1] in _CONDITIONAL_MARKERS)
            ):
                return "DIRECTIVE", 1, "hedged", f"p2_hedged_{w}", False
            continue
        if w == "will" and i > 0 and lowers[i - 1] == "you":
            if i + 1 < len(lowers) and lowers[i + 1] in ("not", "never", "n't"):
                return "CONSTRAINT", -1, "absolute", "p2_you_will_not", False
            return "DIRECTIVE", 1, "absolute", "p2_you_will", False
    for w in lowers[:6]:
        if w in _ABSOLUTE_ADVERBS:
            if w == "only" and not any(v in _ALL_VERBS for v in lowers):
                continue
            return "DIRECTIVE", 1, "absolute", f"p2_adverb_{w}", False

    # ── Phase 3: IMPERATIVE ──

    # 3a: DISABLED — 20.7% precision.

    # 3b: Bold label + verb after it — shallow recursive call.
    if not _shallow:
        after = _after_bold_label(md_text)
        if after is not None:
            after_clean = _strip_md_for_classify(after)
            if after_clean:
                sub_c, sub_cv, sub_m, _sub_trace, sub_sc = classify_charge(
                    after,
                    plain_text=after_clean,
                    _shallow=True,
                )
                if sub_cv != 0:
                    return sub_c, sub_cv, sub_m, "p3b_bold_label", sub_sc

    # 3_spacy: primary Phase 3 (spaCy dependency parse)
    nlp = get_models().nlp
    if nlp is not None:
        result = _classify_phase3_spacy(
            clean,
            md_text,
            nlp,
            has_cond_prefix,
            shallow=_shallow,
            inline_tokens=inline_tokens,
        )
        if result is not None:
            return result

    # 3c-3g: fallback verb lexicon (when spaCy unavailable or returns None)
    verb_idx = _find_verb_idx(lowers)
    if verb_idx == -1:
        return "NEUTRAL", 0, "none", "p3_no_verb", False

    # 3c: Verb at position 0
    if verb_idx == 0:
        verb = lowers[0]
        # Ambiguity check: verb-noun words (test, build, state, ...) are
        # ambiguous UNLESS position 1 is a determiner — "State the X" is
        # clearly imperative (VB DT NN), "State machine" is a compound noun.
        _DETERMINERS = {
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
        amb = ""
        if verb in _VERBS_AMBIGUOUS:
            pos1 = lowers[1] if len(lowers) > 1 else ""
            if pos1 not in _DETERMINERS:
                amb = "!amb"
        cond_check = _CONDITIONAL_MARKERS - {"for"}
        has_cond = any(w in cond_check for w in lowers[1:8])
        return "IMPERATIVE", 1, "imperative", f"p3c_verb0_{verb}{amb}", has_cond

    # In shallow mode (recursive from 3b), skip deep detection phases 3d-3g
    if _shallow:
        return "NEUTRAL", 0, "none", "p3_shallow_stop", False

    # 3d: Verb after context words only
    pre = set(lowers[:verb_idx])
    if pre <= _CONTEXT_WORDS:
        has_cond = bool(pre & _CONDITIONAL_MARKERS)
        if "not" in pre:
            return "CONSTRAINT", -1, "direct", "p3d_context_not", has_cond
        verb = lowers[verb_idx]
        amb = "!amb" if verb in _VERBS_AMBIGUOUS else ""
        return "IMPERATIVE", 1, "imperative", f"p3d_context_{verb}{amb}", has_cond

    # 3e: Verb after sentence/clause break
    sentences = re.split(r"(?<=[.!?:;])\s+", clean)
    if len(sentences) > 1:
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

    # 3f: Conditional marker at sentence start
    if lowers[0] in _CONDITIONAL_MARKERS:
        return "IMPERATIVE", 1, "imperative", f"p3f_cond_{lowers[0]}", True

    # 3g: Mid-sentence verb with conditional marker before it
    _DECLARATIVE_STARTS = _PROBABLE_SUBJECTS | {
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
    if lowers[0] not in _DECLARATIVE_STARTS and verb_idx <= 7:
        if pre & _CONDITIONAL_MARKERS:
            verb = lowers[verb_idx]
            amb = "!amb" if verb in _VERBS_AMBIGUOUS else ""
            if "not" in pre:
                return "CONSTRAINT", -1, "direct", f"p3g_mid_not{amb}", True
            return "IMPERATIVE", 1, "imperative", f"p3g_mid_{verb}{amb}", True

    return "NEUTRAL", 0, "none", "fallthrough", False


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

    for tok in KNOWN_CODE_TOKENS:
        pat = re.compile(r"(?<![`\w])" + re.escape(tok) + r"(?![`\w])", re.IGNORECASE)
        if pat.search(text_no_bt):
            if not any(tok.lower() in bt.lower() for bt in backtick_content):
                unformatted.append(tok)

    for m in CODE_SHAPE_RE.finditer(text_no_bt):
        token = m.group(1)
        if token.lower().rstrip(".") in {e.rstrip(".") for e in _DOTTED_EXCLUSIONS}:
            continue
        if token not in unformatted and not any(token in bt for bt in backtick_content):
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
        if child.type == "text":
            md_parts.append(child.content)
            plain_parts.append(child.content)
            current_fmt = format_stack[-1]
            for word in child.content.split():
                inline_tokens.append(InlineToken(text=word, format=current_fmt))
        elif child.type == "code_inline":
            md_parts.append(f"`{child.content}`")
            plain_parts.append(child.content)
            for word in child.content.split():
                inline_tokens.append(InlineToken(text=word, format="backtick"))
        elif child.type == "strong_open":
            md_parts.append("**")
            format_stack.append("bold")
        elif child.type == "strong_close":
            md_parts.append("**")
            if len(format_stack) > 1:
                format_stack.pop()
        elif child.type == "em_open":
            md_parts.append("*")
            format_stack.append("italic")
        elif child.type == "em_close":
            md_parts.append("*")
            if len(format_stack) > 1:
                format_stack.pop()
        elif child.type in ("link_open", "link_close"):
            pass  # skip link markers, text child handles content
        elif child.type == "html_inline":
            md_parts.append(child.content)
            plain_parts.append(child.content)
            current_fmt = format_stack[-1]
            for word in child.content.split():
                inline_tokens.append(InlineToken(text=word, format=current_fmt))

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

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        # Track block nesting
        if tok.type in _BLOCK_TYPES:
            block_stack.append(_BLOCK_TYPES[tok.type])
        elif tok.type in _BLOCK_CLOSE:
            if block_stack:
                block_stack.pop()

        # Emit code block atoms (fence) — captures language tag for mermaid detection
        if tok.type == "fence":
            lang = (tok.info or "").strip().lower()
            atoms.append(
                Atom(
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
            )
            i += 1
            continue

        # Skip horizontal rules
        if tok.type == "hr":
            i += 1
            continue

        # Headings: depth from tag, text from next inline token
        if tok.type == "heading_open":
            depth = int(tok.tag[1])
            line_num = (tok.map[0] if tok.map else 0) + line_offset + 1
            # Next token is the inline with heading text
            if i + 1 < len(tokens) and tokens[i + 1].type == "inline":
                heading_text = tokens[i + 1].content
            else:
                heading_text = ""
            current_heading = heading_text
            # Headings are content — "## Never push to main" is a constraint.
            h_charge, h_cv, h_mod, h_rule, h_sc = classify_charge(heading_text)
            h_spec, h_named, _h_unfmt, _h_italic, _h_bold = check_specificity(heading_text)
            atoms.append(
                Atom(
                    line=line_num,
                    text=heading_text,
                    kind="heading",
                    charge=h_charge,
                    charge_value=h_cv,
                    modality=h_mod,
                    specificity=h_spec,
                    format="heading",
                    depth=depth,
                    named_tokens=h_named,
                    token_count=len(heading_text.split()),
                    rule=h_rule,
                    scope_conditional=h_sc,
                )
            )
            i += 3  # skip heading_open, inline, heading_close
            continue

        # Table rows: collect cells, join with " | ", one atom per row
        if tok.type == "tr_open":
            line_num = (tok.map[0] if tok.map else 0) + line_offset + 1
            cells: list[str] = []
            j = i + 1
            while j < len(tokens) and tokens[j].type != "tr_close":
                if tokens[j].type == "inline":
                    cells.append(tokens[j].content.strip())
                j += 1
            cell_text = " | ".join(cells)
            if len(cell_text) >= 5:
                spec, named, unformatted, italic, bold = check_specificity(
                    cell_text,
                )
                token_count = len(_BACKTICK_RE.sub("x", cell_text).split())
                atoms.append(
                    Atom(
                        line=line_num,
                        text=cell_text,
                        kind="excitation",
                        charge="NEUTRAL",
                        charge_value=0,
                        modality="none",
                        specificity=spec,
                        format="table",
                        named_tokens=named,
                        italic_tokens=italic,
                        bold_tokens=bold,
                        unformatted_code=unformatted,
                        position_index=pos_idx,
                        token_count=token_count,
                        heading_context=current_heading,
                    )
                )
                pos_idx += 1
            i = j + 1  # skip past tr_close
            continue

        # Process inline content tokens
        if tok.type == "inline" and tok.children:
            base_line = (tok.map[0] if tok.map else 0) + line_offset + 1
            fmt = _determine_format(block_stack)

            # Table inlines are handled by tr_open above
            if fmt == "table":
                i += 1
                continue

            segments = _split_at_softbreaks(tok.children)
            for seg_idx, segment in enumerate(segments):
                md_text, plain_text, inline_tokens = _extract_texts(segment)
                if len(md_text) < 5:
                    continue

                charge, cv, mod, rule_trace, scope_cond = _classify_content(
                    md_text,
                    plain_text,
                    fmt,
                    inline_tokens=inline_tokens,
                )
                spec, named, unformatted, italic, bold = check_specificity(
                    md_text,
                )
                token_count = len(_BACKTICK_RE.sub("x", md_text).split())

                atoms.append(
                    Atom(
                        line=base_line + seg_idx,
                        text=md_text,
                        kind="excitation",
                        charge=charge,
                        charge_value=cv,
                        modality=mod,
                        scope_conditional=scope_cond,
                        specificity=spec,
                        format=fmt,
                        named_tokens=named,
                        italic_tokens=italic,
                        bold_tokens=bold,
                        unformatted_code=unformatted,
                        position_index=pos_idx,
                        token_count=token_count,
                        heading_context=current_heading,
                        plain_text=plain_text,
                        rule=rule_trace,
                        ambiguous=rule_trace.endswith("!amb"),
                    )
                )
                pos_idx += 1

        i += 1

    # Post-classification pass: split multi-sentence atoms when sub-sentences
    # carry different charges. Catches both "Don't X. Use Y instead." (charged
    # atom with charge flip) and "You are X. Never do Y." (neutral atom with
    # embedded constraint). Without this, compound sentences get classified by
    # their first clause and charged sub-sentences are lost.
    atoms = _split_mixed_charge_atoms(atoms)

    # Assign confidence scores based on rule trace reliability.
    for atom in atoms:
        atom.charge_confidence = _rule_confidence(atom.rule, atom.charge)

    # Scan neutral atoms for embedded charge markers.
    # Runs AFTER confidence scoring so it can lower confidence for flagged atoms.
    _scan_neutral_for_embedded_markers(atoms)

    return atoms


# Sentence boundary: period/exclamation/question followed by whitespace
# and then uppercase letter or markdown emphasis (*bold*, **italic**).
# Excludes common abbreviations (e.g., i.e., etc., vs.).
_SENTENCE_SPLIT_RE = re.compile(
    r"(?<!\be\.g)(?<!\bi\.e)(?<!\betc)(?<!\bvs)"
    r"[.!?]\s+(?=[A-Z*])"
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

        # Try to split at sentence boundaries
        splits = list(_SENTENCE_SPLIT_RE.finditer(atom.text))
        if not splits:
            result.append(atom)
            continue

        # Build sentence segments from split points
        boundaries = [0] + [m.end() for m in splits] + [len(atom.text)]
        sentences = [atom.text[boundaries[i] : boundaries[i + 1]].strip() for i in range(len(boundaries) - 1)]
        sentences = [s for s in sentences if len(s) >= 5]

        if len(sentences) < 2:
            result.append(atom)
            continue

        # Classify each sentence independently
        classified = []
        for sent in sentences:
            plain = _BACKTICK_RE.sub("x", sent)
            plain = re.sub(r"[*_]+", "", plain).strip()
            charge, cv, mod, rule, scope = _classify_content(sent, plain, atom.format)
            classified.append((sent, charge, cv, mod, rule, scope))

        # Only split if charges actually differ
        charges = {cv for _, _, cv, _, _, _ in classified}
        if len(charges) < 2:
            result.append(atom)
            continue

        # Produce separate atoms for each sentence
        for sent, charge, cv, mod, rule, scope in classified:
            spec, named, unformatted, italic, bold = check_specificity(sent)
            token_count = len(_BACKTICK_RE.sub("x", sent).split())
            result.append(
                Atom(
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
                    token_count=token_count,
                    heading_context=atom.heading_context,
                    plain_text=re.sub(r"[*_`]+", "", sent).strip(),
                    rule=rule,
                    ambiguous=rule.endswith("!amb"),
                )
            )

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
        # Neutral classifications from explicit rules are high confidence.
        # Fallthrough neutrals are slightly lower (nothing matched).
        if rule == "fallthrough":
            return 0.85
        return 0.95

    if rule in _HIGH_CONFIDENCE_RULES:
        return 0.95

    if rule in _MEDIUM_CONFIDENCE_RULES:
        return 0.80

    # Ambiguous rules (verb-noun words)
    if rule.endswith("!amb"):
        return 0.60

    # Conditional/scope rules
    if "cond" in rule or "3f_" in rule or "3g_" in rule:
        return 0.70

    # Default for any other charged rule
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


def cluster_topics(
    atoms: list[Atom],
) -> list[TopicCluster]:
    """Cluster atoms into topic groups using pre-computed embeddings.

    Uses AgglomerativeClustering with distance_threshold on the already-embedded
    int8 vectors from map_ruleset(). Does NOT re-encode — uses embedding_int8
    directly, dequantized to float32 for clustering.

    Falls back to single cluster when embeddings are missing.
    """
    import numpy as np

    exc = [a for a in atoms if a.kind != "heading"]
    if not exc:
        return []

    # Use pre-computed embeddings (already set by map_ruleset)
    embedded = [a for a in exc if a.embedding_int8 is not None]
    if len(embedded) < 2:
        # Not enough embeddings — single cluster
        charged = [a for a in exc if a.charge_value != 0]
        j = len(charged) / len(exc) if exc else 0.0
        for a in exc:
            a.cluster_id = 0
        return [TopicCluster(topic_id=0, atoms=exc, charged=charged, j=j)]

    # Dequantize int8 embeddings to float32 for clustering
    vecs = np.array([list(a.embedding_int8) for a in embedded if a.embedding_int8 is not None], dtype=np.float32)

    from sklearn.cluster import AgglomerativeClustering
    from sklearn.preprocessing import normalize

    embeddings_norm = normalize(vecs, norm="l2")
    clustering = AgglomerativeClustering(
        n_clusters=None,
        distance_threshold=TOPIC_CLUSTER_THRESHOLD,
        metric="euclidean",
        linkage="average",
    )
    labels = clustering.fit_predict(embeddings_norm)

    # Per-label index bookkeeping so we can compute centroids from the
    # normalized float32 vectors we already have (no re-encoding needed).
    clusters: dict[int, list[Atom]] = {}
    indices: dict[int, list[int]] = {}
    for i, (atom, label) in enumerate(zip(embedded, labels, strict=True)):
        lbl = int(label)
        atom.cluster_id = lbl
        clusters.setdefault(lbl, []).append(atom)
        indices.setdefault(lbl, []).append(i)

    # Assign unembedded atoms (headings already filtered, but safety net) to cluster -1
    for a in exc:
        if a.embedding_int8 is None:
            a.cluster_id = -1

    result: list[TopicCluster] = []
    for tid in sorted(clusters):
        cluster_atoms = clusters[tid]
        charged = [a for a in cluster_atoms if a.charge_value != 0]
        n_total = len(cluster_atoms)
        n_chg = len(charged)
        j = n_chg / n_total if n_total else 0.0

        # Centroid: mean of L2-normalized member vectors, re-normalized to the
        # unit sphere. Closed 2026-04 wire-format gap: ClusterRecord.centroid
        # was declared but never populated, forcing server consumers to re-derive.
        member_vecs = embeddings_norm[indices[tid]]
        mean_vec = member_vecs.mean(axis=0)
        norm = float(np.linalg.norm(mean_vec))
        if norm > 1e-12:
            mean_vec = mean_vec / norm
        centroid = tuple(float(x) for x in mean_vec.tolist())

        result.append(
            TopicCluster(
                topic_id=tid,
                atoms=cluster_atoms,
                charged=charged,
                j=j,
                centroid=centroid,
            )
        )

    return result


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

    # Find fenced code block ranges to skip
    code_ranges: list[tuple[int, int]] = []
    for m in _FENCED_BLOCK_RE.finditer(content):
        code_ranges.append((m.start(), m.end()))

    def _in_code_block(pos: int) -> bool:
        return any(start <= pos < end for start, end in code_ranges)

    def _replace(match: re.Match[str]) -> str:
        if _in_code_block(match.start()):
            return match.group(0)  # inside code block — don't expand

        ref = match.group(1)

        # Resolve path relative to importing file
        if ref.startswith("~"):
            target = Path(ref).expanduser()
        else:
            target = source_path.parent / ref

        # Resolve symlinks — catches circular symlinks (ELOOP)
        try:
            target = target.resolve(strict=False)
        except (OSError, RuntimeError):
            return match.group(0)  # circular or broken symlink

        # Skip known non-markdown extensions
        if target.suffix.lower() in _NON_EXPANDABLE_EXT:
            return match.group(0)

        # Circular import detection
        target_key = str(target)
        if target_key in visited:
            return match.group(0)

        # Read and recursively expand
        if not target.is_file():
            return match.group(0)  # broken reference — leave as-is

        try:
            imported = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return match.group(0)

        visited.add(target_key)
        expanded = expand_imports(imported, target, depth=depth + 1, visited=visited)
        return expanded

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


def _parse_frontmatter_description(path: Path) -> str:
    """Extract name + description from YAML frontmatter.

    These fields are surfaced into the model's base context by all agents
    (Agent Skills standard) for skill/agent discoverability. The combined
    string is what competes for attention even when the file isn't invoked.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if not text.startswith("---"):
        return ""
    end = text.find("\n---", 3)
    if end == -1:
        return ""
    try:
        import yaml

        data = yaml.safe_load(text[3:end])
        if not isinstance(data, dict):
            return ""
        name = str(data.get("name", ""))
        desc = str(data.get("description", ""))
        if name and desc:
            return f"{name}: {desc}"
        return name or desc
    except Exception:  # yaml.YAMLError; yaml imported in try scope
        return ""


def _parse_frontmatter_globs(path: Path) -> tuple[str, ...]:
    """Extract globs from YAML frontmatter of a rule/skill file."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ()
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return ()
    # Find closing ---
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "---":
            front = "\n".join(lines[1:i])
            break
    else:
        return ()
    try:
        import yaml

        data = yaml.safe_load(front)
        if isinstance(data, dict) and "globs" in data:
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
    rel_lower = rel.lower()

    import fnmatch

    # Collect all matches, then pick the most specific (longest literal prefix).
    # This prevents catch-all patterns like **/AGENTS.md from beating
    # directory-scoped patterns like .gemini/agents/*.md.
    best_match: tuple[int, str, str, dict[str, Any]] | None = None  # (specificity, agent, ft_name, props)

    for agent_id, config in registry.items():
        for _ft_name, ft in (config.get("file_types") or {}).items():
            # Support both v0.3.0 (patterns + properties) and v0.5.0 (scopes)
            from reporails_cli.core.agents import _extract_patterns, _extract_properties

            patterns = _extract_patterns(ft) if isinstance(ft, dict) else []
            props = ft.get("properties", {}) if isinstance(ft, dict) else {}
            if not props:
                props = _extract_properties(ft) if isinstance(ft, dict) else {}
            for pat in patterns:
                pat_lower = pat.lower()
                # Try multiple normalizations for ** glob patterns
                candidates = [pat_lower]
                if "**/" in pat_lower:
                    candidates.append(pat_lower.replace("**/", ""))  # zero depth
                    candidates.append(pat_lower.replace("**/", "*/"))  # one depth
                matched = any(fnmatch.fnmatch(rel_lower, c) for c in candidates)
                if matched:
                    # Specificity = length of literal prefix before first glob char
                    specificity = len(pat_lower.split("*")[0])
                    if best_match is None or specificity > best_match[0]:
                        best_match = (specificity, agent_id, _ft_name, props)

    if best_match:
        _, agent_id, _, props = best_match
        loading = props.get("loading", "session_start")
        scope = props.get("scope", "global")
        globs: tuple[str, ...] = ()
        if loading in ("on_demand", "on_invocation"):
            globs = _parse_frontmatter_globs(path)
        if loading == "on_demand" and not globs:
            loading = "session_start"
            scope = "global"
        return loading, scope, globs, agent_id

    # Fallback: single file = session_start, global, generic
    return "session_start", "global", (), "generic"


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
    from reporails_cli.core.mapper.map_cache import (
        CachedFileEntry,
        MapCache,
        atoms_to_dicts,
        dicts_to_atoms,
    )

    if models is None:
        models = get_models()
    if root is None:
        root = paths[0].parent if paths else Path(".")

    # Load incremental cache
    map_cache: MapCache | None = None
    if cache_dir is not None:
        map_cache = MapCache(cache_dir)
        map_cache.load()

    registry = _load_registry()

    # Classify all files — cache hits skip tokenization
    file_records: list[FileRecord] = []
    all_atoms: list[Atom] = []
    atoms_needing_embed: list[Atom] = []  # only uncached atoms need embedding

    for path in paths:
        raw_content = path.read_text(encoding="utf-8", errors="replace")
        # Expand @path inline imports (Claude Code, Gemini CLI).
        # The model sees expanded content — the mapper must too.
        content = expand_imports(raw_content, path)
        chash = content_hash(content)

        # Check cache
        cached = map_cache.get(chash) if map_cache else None
        if cached is not None:
            atoms = dicts_to_atoms(cached.atoms)
            # Restore file_path (cache stores it, but verify)
            for a in atoms:
                a.file_path = str(path)
            all_atoms.extend(atoms)
            # Cached atoms already have embeddings — no re-embed needed
        else:
            atoms = tokenize(content)
            for a in atoms:
                a.file_path = str(path)
            all_atoms.extend(atoms)
            # All atoms need embedding — headings included
            atoms_needing_embed.extend(atoms)
            # Store in cache (without embeddings yet — we'll update after embedding)
            if map_cache is not None:
                map_cache.put(chash, CachedFileEntry(chash, atoms_to_dicts(atoms)))

        loading, scope, globs, agent = _detect_file_loading(path, root, registry)
        # Extract frontmatter description for on_invocation files — these
        # descriptions are always in the model's base context (Agent Skills
        # standard: name+description surfaced for discoverability).
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

    # Embed only uncached non-heading atoms. Dedup by embedding-text
    # (same atom text + same heading_context = same embedding) so repeated
    # patterns like "Use `ruff`" under the same heading only hit the
    # encoder once per run.
    if atoms_needing_embed:
        texts = [_embed_text(a) for a in atoms_needing_embed]
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
        unique_embeddings = models.st.encode(unique_texts)
        for atom, u_idx in zip(atoms_needing_embed, atom_to_unique, strict=True):
            atom.embedding_int8 = _quantize_int8(unique_embeddings[u_idx])

        # Update cache with embeddings
        if map_cache is not None:
            # Group newly-embedded atoms by file, update cache entries
            by_file: dict[str, list[Atom]] = {}
            for a in all_atoms:
                by_file.setdefault(a.file_path, []).append(a)
            for frec in file_records:
                file_atoms = by_file.get(frec.path, [])
                if any(a in atoms_needing_embed for a in file_atoms):
                    map_cache.put(frec.content_hash, CachedFileEntry(frec.content_hash, atoms_to_dicts(file_atoms)))

    # Evict stale cache entries and save
    if map_cache is not None:
        known_hashes = {fr.content_hash for fr in file_records}
        map_cache.evict_stale(known_hashes)
        map_cache.save()

    # Embed check: ensure ALL atoms have embeddings (cached or fresh)
    exc = list(all_atoms)
    unembedded = [a for a in exc if a.embedding_int8 is None]
    if unembedded:
        # Same dedup as above
        texts = [_embed_text(a) for a in unembedded]
        unique_texts = []
        text_index = {}
        atom_to_unique = []
        for t in texts:
            idx = text_index.get(t)
            if idx is None:
                idx = len(unique_texts)
                text_index[t] = idx
                unique_texts.append(t)
            atom_to_unique.append(idx)
        unique_embeddings = models.st.encode(unique_texts)
        for atom, u_idx in zip(unembedded, atom_to_unique, strict=True):
            atom.embedding_int8 = _quantize_int8(unique_embeddings[u_idx])

    # Embed file descriptions (on_invocation files only — their name+description
    # is always in the model's base context per Agent Skills standard).
    desc_texts = [fr.description for fr in file_records if fr.description]
    if desc_texts and models is not None:
        desc_embeddings = models.st.encode(desc_texts)
        desc_idx = 0
        for fr in file_records:
            if fr.description:
                fr.description_embedding = _quantize_int8(desc_embeddings[desc_idx])
                desc_idx += 1

    # Cluster by topic
    topics = cluster_topics(all_atoms)
    cluster_records: list[ClusterRecord] = []
    for tc in topics:
        cluster_records.append(
            ClusterRecord(
                id=tc.topic_id,
                n_atoms=len(tc.atoms),
                n_charged=len(tc.charged),
                n_neutral=len(tc.atoms) - len(tc.charged),
                centroid=tc.centroid,
            )
        )

    # Summary
    n_charged = sum(1 for a in exc if a.charge_value != 0)
    n_topics_charged = sum(1 for tc in topics if tc.charged)

    summary = RulesetSummary(
        n_atoms=len(exc),
        n_charged=n_charged,
        n_neutral=len(exc) - n_charged,
        n_topics=len(topics),
        n_topics_charged=n_topics_charged,
    )

    ruleset = RulesetMap(
        schema_version=SCHEMA_VERSION,
        embedding_model=EMBEDDING_MODEL,
        generated_at=datetime.now(UTC).isoformat(),
        files=tuple(file_records),
        atoms=tuple(all_atoms),
        clusters=tuple(cluster_records),
        summary=summary,
    )

    # Validate — log warnings, raise on errors
    findings = validate_atoms(ruleset.atoms)
    errors = [f for f in findings if f.severity == "error"]
    warns = [f for f in findings if f.severity == "warn"]
    for f in errors:
        logger.error("Map validation: [%s] L%d: %s — %s", f.rule, f.line, f.message, f.text)
    for f in warns:
        logger.warning("Map validation: [%s] L%d: %s — %s", f.rule, f.line, f.message, f.text)
    if errors:
        raise ValueError(
            f"Map validation failed with {len(errors)} error(s). First: [{errors[0].rule}] {errors[0].message}"
        )

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
    valid_charges = {"CONSTRAINT", "DIRECTIVE", "IMPERATIVE", "NEUTRAL", "AMBIGUOUS"}
    valid_mods = {"imperative", "direct", "absolute", "hedged", "none"}

    exc: list[Atom] = []

    for a in atoms:
        # ── Schema invariants ──
        if a.charge not in valid_charges:
            findings.append(
                MapFinding(
                    "error",
                    "schema",
                    f"Invalid charge: {a.charge}",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )
        if a.modality not in valid_mods:
            findings.append(
                MapFinding(
                    "error",
                    "schema",
                    f"Invalid modality: {a.modality}",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )
        if a.charge_value not in (-1, 0, 1):
            findings.append(
                MapFinding(
                    "error",
                    "schema",
                    f"Invalid charge_value: {a.charge_value}",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )
        if a.charge_value == 0 and a.charge not in ("NEUTRAL", "AMBIGUOUS"):
            findings.append(
                MapFinding(
                    "error",
                    "consistency",
                    f"charge_value=0 but charge={a.charge}",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )
        if a.charge_value != 0 and a.charge == "NEUTRAL":
            findings.append(
                MapFinding(
                    "error",
                    "consistency",
                    f"charge_value≠0 but charge=NEUTRAL",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )
        if a.charge_value == 0 and a.modality != "none":
            findings.append(
                MapFinding(
                    "error",
                    "consistency",
                    f"NEUTRAL with modality={a.modality}",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )
        if a.charge_value != 0 and a.modality == "none":
            findings.append(
                MapFinding(
                    "error",
                    "consistency",
                    f"Charged with modality=none",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )
        # Charged headings are valid — "## Never push to main" is a constraint.

        if a.kind == "excitation":
            exc.append(a)

    # ── Deterministic charge invariants ──
    for a in exc:
        clean = _strip_md_for_classify(a.text)

        if _MUST_CONSTRAINT_RE.match(clean) and a.charge_value != -1:
            findings.append(
                MapFinding(
                    "warn",
                    "must_constraint",
                    f"Negation at start but charge={a.charge}",
                    a.line,
                    a.text[:80],
                    a.charge,
                )
            )

        # NEUTRAL with strong charge words (skip quoted examples)
        if a.charge_value == 0 and not _QUOTED_ATOM_RE.match(a.text.strip()):
            if _STRONG_CHARGE_RE.search(a.text):
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

    # ── Statistical checks ──
    n_exc = len(exc)
    if n_exc > 0:
        n_charged = sum(1 for a in exc if a.charge_value != 0)
        ratio = n_charged / n_exc
        if ratio > 0.90:
            findings.append(
                MapFinding(
                    "warn",
                    "distribution",
                    f"Charge ratio {ratio:.0%} ({n_charged}/{n_exc}) — unusually high",
                )
            )
        if ratio < 0.05 and n_exc > 10:
            findings.append(
                MapFinding(
                    "warn",
                    "distribution",
                    f"Charge ratio {ratio:.0%} ({n_charged}/{n_exc}) — unusually low",
                )
            )

    return findings


def validate_map(ruleset_map: RulesetMap) -> list[MapFinding]:
    """Validate a RulesetMap. Delegates to validate_atoms."""
    return validate_atoms(ruleset_map.atoms)
