"""Stage 4 — annotate atoms with specificity, formatting tokens, and code references.

Five parallel regex passes per atom: backtick-wrapped tokens, italic spans, bold
spans (excluding negation phrases), known code tokens (from a curated list), and
code-shaped patterns. The result drives the equation's specificity term and the
formatting modulator.

Public entry point: `check_specificity(text)`.

The regex constants (`_BACKTICK_RE`, `_BOLD_TERM_RE`, etc.) are also consumed by
Stage 3 (`_strip_md_for_classify`) and Stages 1+2 (`_specificity_fields` in
parse.py); both import them from this module.
"""

from __future__ import annotations

import re

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
