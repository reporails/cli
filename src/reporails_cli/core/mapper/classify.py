# ruff: noqa: C901, SIM102
"""Stage 3 — three-phase charge classification.

Three deterministic phases (regex Phase 1 + Phase 2, spaCy/lexicon Phase 3 with
sub-phases 3a-3g) classify each atom's charge into CONSTRAINT (-1), DIRECTIVE
(+1), IMPERATIVE (+1), or NEUTRAL (0). The output drives sum membership in the
equation (instruction sum vs neutral mass) and conflict detection.

Public entry point: `classify_charge(md_text, plain_text=..., inline_tokens=...)`.

Imports `_BACKTICK_RE` from annotate (Stage 4) for backtick filtering during
Phase 3 spaCy disambiguation, and `get_models` from models for the spaCy `nlp`
singleton (with graceful lexicon fallback when spaCy is unavailable).
"""

from __future__ import annotations

import re
from typing import Any

from reporails_cli.core.mapper.annotate import _BACKTICK_RE
from reporails_cli.core.mapper.models import get_models
from reporails_cli.core.platform.dto.ruleset import InlineToken

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
    root_position: int = 0,
) -> bool:
    """Check if the ROOT word falls inside a backtick span.

    When root_position is 0, checks only the first occurrence in inline_tokens
    to avoid false positives from the same word appearing both as a position-0
    verb and inside a later backtick span (e.g., "Build the wheel with `uv build`").
    """
    if inline_tokens is not None:
        if root_position == 0:
            # Position-0 ROOT: only check if the first token matches and is backtick
            for itok in inline_tokens:
                if itok.text.lower() == root_lower:
                    return itok.format == "backtick"
                # First non-whitespace token reached — if it's not the root word,
                # the root is plain text at position 0, not backticked
                if itok.text.strip():
                    return False
            return False
        for itok in inline_tokens:
            if itok.text.lower() == root_lower:
                return itok.format == "backtick"
        return False
    # Regex fallback for direct calls (no inline_tokens).
    # Position-0 verbs are never code identifiers — only check backtick
    # when the root is NOT at position 0 in the text.
    root_pos = clean.lower().find(root_lower)
    if root_pos == -1:
        return False
    if root_pos == 0:
        # Position-0: check if the very first word is inside a backtick span
        first_bt = _BACKTICK_RE.search(md_text)
        return first_bt is not None and first_bt.start() == 0 and root_lower in first_bt.group().lower()
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


_POST_COLON_NEGATION = frozenset({"never", "no", "not", "don't", "do", "avoid"})

# Labels before colon/dash that are meta-descriptions, not instruction headers.
# "fix: correct a bug" is a commit type definition, not an instruction.
_META_LABELS = frozenset(
    {
        "fix",
        "feat",
        "chore",
        "docs",
        "refactor",
        "test",
        "ci",
        "build",
        "perf",
        "style",
        "goal",
        "purpose",
        "pattern",
        "example",
        "impact",
        "default",
        "note",
        "result",
        "output",
        "input",
        "return",
        "trigger",
        "both",
        "screenshot",
    }
)


def _check_colon_label(doc: Any, root: Any) -> tuple[str, int, str, str, bool] | None:
    """Detect 'Noun: ...' label pattern in early tokens.

    Scans all tokens in first 5 positions (not limited to pre-root) because
    spaCy often assigns ROOT to the label noun itself.

    Returns:
    - CONSTRAINT if post-colon text starts with negation
    - IMPERATIVE if post-colon text starts with a non-ambiguous verb
    - NEUTRAL if post-colon text is descriptive or label is meta
    - None if no colon-label pattern found
    """
    if len(doc) > 0 and doc[0].text.lower() in _ALL_VERBS:
        return None
    # Skip if ROOT is a verb before the colon — the verb is the instruction
    if root.tag_ in {"VB", "VBP"} and any(t.text == ":" and t.i > root.i for t in doc[:6]):
        return None
    for tok in doc:
        if tok.i > 5:
            break
        if tok.text == ":" and 0 < tok.i <= 4:
            if any(t.text.lower() in _CONDITIONAL_MARKERS for t in doc[: tok.i]):
                break  # conditional clause break, not a label
            prev = doc[tok.i - 1]
            if prev.tag_ in {"NN", "NNS", "NNP", "NNPS"}:
                # Skip meta-labels (commit types, purpose statements)
                label_text = doc[: tok.i].text.lower()
                if any(ml in label_text for ml in _META_LABELS):
                    return ("NEUTRAL", 0, "none", "p3_spacy_colon_label", False)
                # Skip function-like labels (camelCase or contains uppercase mid-word)
                label_raw = doc[: tok.i].text
                if any(c.isupper() for c in label_raw[1:] if c.isalpha()):
                    # camelCase or PascalCase label → description
                    if any(c.islower() for c in label_raw):
                        return ("NEUTRAL", 0, "none", "p3_spacy_colon_label", False)
                # Check post-colon tokens for charge indicators
                post = [t for t in doc if t.i > tok.i and not t.is_space]
                if post:
                    first_word = post[0].text.lower()
                    # Negation after colon → CONSTRAINT
                    if first_word in _POST_COLON_NEGATION:
                        return ("CONSTRAINT", -1, "direct", "p3_colon_label_constraint", False)
                    # Non-ambiguous verb after colon → IMPERATIVE
                    if first_word in _ALL_VERBS and first_word not in _VERBS_AMBIGUOUS:
                        return ("IMPERATIVE", 1, "imperative", "p3_colon_label_imperative", False)
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
    if root.i == 0 and root.text.lower() in _ALL_VERBS and root.text.lower() not in _VERBS_AMBIGUOUS:
        sc = _detect_scope_conditional(doc, has_cond_prefix)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_verb0", sc)
    # Ambiguous verb at position 0 with no subject: likely imperative.
    # "Test behavior" (imperative) vs "Test results showed" (noun + subj).
    if root.i == 0 and not has_subj and root.text.lower() in _VERBS_AMBIGUOUS:
        sc = _detect_scope_conditional(doc, has_cond_prefix)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_verb0!amb", sc)
    # Position-0 verb rescue: non-ambiguous verb demoted by spaCy
    t0_lower = doc[0].text.lower() if len(doc) > 0 else ""
    if root.i > 0 and not has_subj and t0_lower in _ALL_VERBS and t0_lower not in _VERBS_AMBIGUOUS:
        sc = _detect_scope_conditional(doc, has_cond_prefix)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_verb0_rescue", sc)
    # Position-0 ambiguous verb rescue: demoted by spaCy, no subject
    if root.i > 0 and not has_subj and t0_lower in _VERBS_AMBIGUOUS:
        sc = _detect_scope_conditional(doc, has_cond_prefix)
        return ("IMPERATIVE", 1, "imperative", "p3_spacy_nn_verb0_rescue!amb", sc)
    # Post-colon verb rescue (conditional markers before colon)
    pcv = _check_postcolon_verb(doc)
    if pcv is not None:
        return pcv
    # Colon-label rescue: "Label: Use X" / "Label: Never Y"
    cl = _check_colon_label(doc, root)
    if cl is not None:
        return cl
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
    if has_subj and not has_cond_prefix:
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

_LATE_CONSTRAINT_RE = re.compile(
    r"[.:;\u2014\u2013\-]\s*(?:do not|don't|never|avoid|must not|should not|cannot|no )\b",
    re.IGNORECASE,
)


def _has_late_constraint(text: str) -> bool:
    """True if text has constraint language after a sentence/clause boundary.

    Catches compound instructions like 'Prefer X. Do not introduce Y' and
    'Label — Avoid X' where the positive verb at the start masks a constraint.
    """
    return bool(_LATE_CONSTRAINT_RE.search(text))


def _spacy_pre_checks(
    doc: Any,
    root: Any,
    clean: str,
    md_text: str,
    has_cond_prefix: bool,
    inline_tokens: list[InlineToken] | None,
) -> tuple[str, int, str, str, bool] | None:
    """Run pre-POS checks: verb0 rescue, backtick filter, colon label."""
    # Verb0 rescue runs BEFORE backtick filter: "Use `createAIClient()`"
    # has a backticked ROOT (createAIClient) but the verb at position 0
    # is the instruction. The verb takes precedence over the object.
    rescue = _check_verb0_rescue(doc, root, has_cond_prefix)
    if rescue is not None:
        return rescue
    # Backtick filter: ROOT inside backticks → NEUTRAL (code reference).
    # Skip when the sentence has imperative structure — the backticked word
    # is the object of the instruction, not a code reference.
    # Imperative signals: known verb at pos 0, conditional prefix, "Please".
    t0_lower = doc[0].text.lower() if len(doc) > 0 else ""
    has_imperative_signal = t0_lower in _ALL_VERBS or has_cond_prefix or t0_lower in {"to", "please", "re"}
    if not has_imperative_signal and _is_root_in_backtick(
        root.text.lower(), clean, md_text, inline_tokens, root_position=root.i
    ):
        return ("NEUTRAL", 0, "none", "p3_spacy_backtick", False)
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
        result = pre
    else:
        has_subj = any(child.dep_ in ("nsubj", "nsubjpass") for child in root.children)
        tag = root.tag_

        # Position-0 nsubj rescue: spaCy demoted a known verb to noun-subject.
        # "Extract display logic" → spaCy: Extract(nsubj) display(ROOT/VBP)
        # "Group related local variables" → Group(nsubj) related(ROOT/VBD)
        # In instruction files, position-0 non-ambiguous verbs tagged as
        # nsubj are always misparsed imperatives. The ambiguous-verb guard
        # prevents false positives; the nsubj dep guard limits to cases
        # where spaCy explicitly assigned subject role to position 0.
        if has_subj and root.i > 0 and not shallow:
            t0 = doc[0]
            if (
                t0.dep_ in ("nsubj", "nsubjpass")
                and t0.text.lower() in _ALL_VERBS
                and t0.text.lower() not in _VERBS_AMBIGUOUS
            ):
                sc = _detect_scope_conditional(doc, has_cond_prefix)
                return ("IMPERATIVE", 1, "imperative", "p3_spacy_nsubj_verb0_rescue", sc)

        # POS classification by tag group
        if tag in {"NN", "NNS", "NNP", "NNPS"}:
            result = _classify_nn_tag(doc, root, has_subj, has_cond_prefix)
        elif tag in _PAST_TENSE_TAGS:
            cl = _check_colon_label(doc, root)
            result = cl if cl is not None else ("NEUTRAL", 0, "none", f"p3_spacy_{tag.lower()}", False)
        elif tag in {"VB", "VBP"}:
            vb_result = _classify_vb_vbp_tag(doc, root, tag, has_subj, has_cond_prefix, shallow=shallow)
            if vb_result is not None:
                result = vb_result
            else:
                return None  # fall through to lexicon
        else:
            result = _classify_nonverb_tag(doc, root, tag)

    # Late-constraint guard: if classified IMPERATIVE but text contains
    # constraint language after a sentence boundary or colon, the atom is
    # a compound instruction — mark AMBIGUOUS to avoid charge inversion.
    if result is not None and result[1] == 1:  # charge_value == 1 (positive)
        if _has_late_constraint(clean):
            return ("AMBIGUOUS", 0, "none", "p3_compound_ambiguous", False)

    return result


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
