"""Annotate atoms with specificity, formatting tokens, and code references.

Five passes per atom: backtick-wrapped tokens (the code spans of the markdown
parse), italic runs and bold runs (the emphasis runs of the markdown parse; bold
excluding negation phrases and a bold label that titles the line), known code
tokens (from a curated list), and code-shaped patterns. Returns the atom's
specificity and its formatting tokens.

Public entry point: `check_specificity(text)`.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache

from reporails_cli.core.mapper.classify import leading_prohibition
from reporails_cli.core.mapper.lexicon import load_dotted_exclusions
from reporails_cli.core.mapper.md_parser import EmphasisRun, code_spans, emphasis_runs, leading_bold_run, replace_spans
from reporails_cli.core.platform.dto.ruleset import Atom

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


# Abbreviations that look like dotted names but aren't code — bundled data file
# (bundled/lexicon/dotted_exclusions.yml), normalized (trailing dot stripped) once.
@lru_cache(maxsize=1)
def _dotted_exclusions_normalized() -> frozenset[str]:
    return frozenset(e.rstrip(".") for e in load_dotted_exclusions().exclusions)


# The CamelCase shape of a library or web-API name (`FastAPI`, `WebSocket`).
NAME_SHAPE = r"[A-Z][a-z]+[A-Z]\w+"
_NAME_SHAPE_RE = re.compile(NAME_SHAPE)

# Patterns that look like code but aren't in backticks
CODE_SHAPE_RE = re.compile(
    r"(?<![`\w])"
    r"("
    r"[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*"  # dotted.name
    r"|[a-z_][a-z0-9_]*\(\)"  # function()
    rf"|{NAME_SHAPE}"  # CamelCase
    r"|[a-z]+_[a-z]+_[a-z]+"  # multi_snake_case (3+ parts)
    r"|\w+\.(py|js|ts|yml|yaml|md|json|toml|cfg|ini|sh|env)"  # file.ext
    r"|--[a-z][\w-]+"  # --cli-flag
    r")"
    r"(?![`\w])",
)

# What sets a bold run that opens a line apart as its title: a colon or a dash (`**Comments** — never
# log PII`, `**Groups** - Organize related pages`). A hyphen counts only when spaced, so `**Pre**-commit`
# stays one word.
_TITLE_SEPARATOR_RE = re.compile(r"\s*(?::|[\u2014\u2013]|-(?=\s))")


def bold_title_label(text: str) -> EmphasisRun | None:
    """The bold run `text` opens with when a colon or a dash sets it off: a label that titles what
    follows, not emphasis on the instruction."""
    run = leading_bold_run(text)
    return run if run is not None and _TITLE_SEPARATOR_RE.match(text, run.end) else None


def _bold_terms(text: str) -> list[str]:
    """The bold spans that emphasise part of `text`.

    A prohibition marker is left out (bold on a prohibition's own `never` is harmless), and so
    is the bold label a line opens with, which titles the instruction after it. A bold run
    that ends in a colon (`**Label:**`) is a label wherever it sits, not emphasis.
    """
    title = bold_title_label(text)
    after_title = title.end if title else 0
    spans = [
        text[run.content_start : run.content_end]
        for run in emphasis_runs(text)
        if run.strong and run.start >= after_title
    ]
    return [b for b in spans if leading_prohibition(b) is None and not b.rstrip().endswith(":")]


def _italic_terms(text: str) -> list[str]:
    """The italic runs of `text` that are not bold: what an italic run wraps, less any bold run
    inside it, and nothing for a run inside a bold one or one that wraps only bold."""
    runs = emphasis_runs(text)
    bold = [run for run in runs if run.strong]
    terms = []
    for run in runs:
        if run.strong or any(b.start <= run.start and run.end <= b.end for b in bold):
            continue
        pieces, cursor = [], run.content_start
        for b in bold:
            if cursor <= b.start and b.end <= run.content_end:
                pieces.append(text[cursor : b.start])
                cursor = b.end
        pieces.append(text[cursor : run.content_end])
        if wrapped := "".join(pieces):
            terms.append(wrapped)
    return terms


def backticked_words(atoms: Iterable[Atom]) -> frozenset[str]:
    """The lower-cased words one file writes inside backticks."""
    return frozenset(w.lower() for a in atoms for span in a.named_tokens for w in re.findall(r"[\w.-]+", span))


def is_unbacked_library_name(token: str, backticked: frozenset[str]) -> bool:
    """True for a library or web-API name (a known code word or a CamelCase name) that the file
    never writes in backticks: it is prose, not code to wrap or to report."""
    is_name = token.lower() in KNOWN_CODE_TOKENS or _NAME_SHAPE_RE.fullmatch(token) is not None
    return is_name and token.lower() not in backticked


def check_specificity(
    text: str,
) -> tuple[str, list[str], list[str], list[str], list[str]]:
    """Check for named constructs, italic tokens, bold tokens, and unformatted code tokens.

    Returns:
        (named|abstract, named_tokens, unformatted_code_tokens, italic_tokens, bold_tokens)
    """
    spans = [span for span in code_spans(text) if span.content]
    named = list(dict.fromkeys(span.content for span in spans))

    italic = _italic_terms(text)
    bold = _bold_terms(text)

    text_no_bt = replace_spans(text, spans, lambda _span: "")
    unformatted: list[str] = []

    # Pre-lowercase backtick content once for O(1)-ish lookups below.
    bt_lower = {name.lower() for name in named}

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
        if token.lower().rstrip(".") in _dotted_exclusions_normalized():
            continue
        if token not in unformatted and not any(token in bt for bt in bt_lower):
            unformatted.append(token)

    # Named if ANY construct is identified — backtick-wrapped OR unformatted known token.
    # The model recognizes `pytest` with or without backticks at the token level.
    spec = "named" if (named or unformatted) else "abstract"
    return spec, named, unformatted, italic, bold
