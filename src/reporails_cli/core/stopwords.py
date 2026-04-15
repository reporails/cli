"""Stopwords vocabulary — pattern decomposition and extraction."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_GUARD_PATTERNS = frozenset(
    {
        r"\A[\s\S]+",
        r"\A[\S\s]+",
        r"\A[\s\S]*",
    }
)


@dataclass
class PatternParts:
    """Decomposed regex pattern: flags + prefix + group(terms) + suffix."""

    flags: str
    prefix: str
    group_open: str  # "(?:" or "("
    terms: list[str]
    suffix: str


def _strip_flags(pattern: str) -> tuple[str, str]:
    """Strip leading inline flags (?i), (?s), etc."""
    flags = ""
    rest = pattern
    while rest.startswith("(?"):
        m = re.match(r"\(\?([ismx]+)\)", rest)
        if m:
            flags += m.group(0)
            rest = rest[m.end() :]
        else:
            break
    return flags, rest


def _match_close_paren(text: str, start: int) -> int:
    """Find matching close paren, returning index of ')' or -1."""
    depth = 1
    j = start
    in_cc = False
    while j < len(text):
        ch = text[j]
        if ch == "\\" and j + 1 < len(text):
            j += 2
            continue
        if ch == "[" and not in_cc:
            in_cc = True
        elif ch == "]" and in_cc:
            in_cc = False
        elif not in_cc:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return j
        j += 1
    return -1


def _find_outer_group(text: str) -> tuple[str, str, int, int, str] | None:
    """Find the outermost alternation group."""
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\" and i + 1 < len(text):
            i += 2
            continue
        if c == "(":
            prefix = text[:i]
            if text[i : i + 3] == "(?:":
                group_open = "(?:"
                content_start = i + 3
            elif text[i : i + 2] in ("(?=", "(?!", "(?<"):
                i += 1
                continue
            else:
                group_open = "("
                content_start = i + 1

            close = _match_close_paren(text, content_start)
            if close == -1:
                return None
            return prefix, group_open, content_start, close, text[close + 1 :]
        i += 1
    return None


def _split_alternation(content: str) -> list[str]:
    """Split on | at depth 0, respecting groups and char classes."""
    terms: list[str] = []
    buf: list[str] = []
    depth = 0
    in_cc = False
    i = 0
    while i < len(content):
        c = content[i]
        if c == "\\" and i + 1 < len(content):
            buf.append(c)
            buf.append(content[i + 1])
            i += 2
            continue
        if c == "[" and not in_cc:
            in_cc = True
        elif c == "]" and in_cc:
            in_cc = False
        elif not in_cc:
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            elif c == "|" and depth == 0:
                terms.append("".join(buf))
                buf = []
                i += 1
                continue
        buf.append(c)
        i += 1
    if buf:
        terms.append("".join(buf))
    return terms


def decompose(pattern: str) -> PatternParts | None:
    """Decompose a regex into wrapper + alternation terms."""
    flags, rest = _strip_flags(pattern)
    result = _find_outer_group(rest)
    if result is None:
        return None
    prefix, group_open, cs, ce, suffix = result
    content = rest[cs:ce]
    terms = _split_alternation(content)
    if len(terms) < 2:
        return None
    return PatternParts(
        flags=flags,
        prefix=prefix,
        group_open=group_open,
        terms=terms,
        suffix=suffix,
    )


def recompose(parts: PatternParts, terms: list[str] | None = None) -> str:
    """Rebuild pattern from decomposed parts, optionally with new terms."""
    t = terms if terms is not None else parts.terms
    alt = "|".join(t)
    return f"{parts.flags}{parts.prefix}{parts.group_open}{alt}){parts.suffix}"


def is_guard(pattern: str) -> bool:
    """True if pattern is a guard/catch-all (e.g., (?s)\\A[\\s\\S]+)."""
    _, rest = _strip_flags(pattern)
    rest = rest.strip()
    return any(rest == g or rest.startswith(g) for g in _GUARD_PATTERNS)


@dataclass
class _PatternInfo:
    """Info about one extractable pattern within a check."""

    target: str  # "pattern-regex", "pattern-not-regex", "args.pattern"
    terms: list[str]


def _try_decompose(pattern: str, target: str) -> _PatternInfo | None:
    """Try to decompose a pattern; return PatternInfo or None."""
    if not pattern or is_guard(pattern):
        return None
    d = decompose(pattern)
    return _PatternInfo(target, d.terms) if d else None


def _analyze_patterns_array(patterns: list[dict[str, Any]]) -> list[_PatternInfo]:
    """Extract alternation info from a patterns: array."""
    infos: list[_PatternInfo] = []
    for entry in patterns:
        for fld in ("pattern-regex", "pattern-not-regex"):
            if fld in entry:
                info = _try_decompose(entry[fld], fld)
                if info:
                    infos.append(info)
    return infos


def _analyze_check(check: dict[str, Any]) -> list[_PatternInfo]:
    """Find extractable alternation patterns in a check definition."""
    ctype = check.get("type", "")

    if ctype == "mechanical" and check.get("check") == "content_absent":
        pat = (check.get("args") or {}).get("pattern", "")
        info = _try_decompose(pat, "args.pattern")
        return [info] if info else []

    if ctype != "deterministic":
        return []

    if "pattern-regex" in check and "patterns" not in check:
        info = _try_decompose(check["pattern-regex"], "pattern-regex")
        return [info] if info else []

    if "patterns" in check:
        return _analyze_patterns_array(check["patterns"])

    return []


def extract_vocab(rule_dir: Path) -> dict[str, Any] | None:
    """Extract vocab.yml content from a rule's checks.yml."""
    checks_path = rule_dir / "checks.yml"
    if not checks_path.exists():
        return None
    try:
        data = yaml.safe_load(checks_path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return None

    checks = (data.get("checks") or []) if isinstance(data, dict) else []
    vocab: dict[str, Any] = {}

    for check in checks:
        cid = check.get("id", "")
        suffix = cid.rsplit(".", 1)[-1] if "." in cid else cid
        if not suffix:
            continue

        infos = _analyze_check(check)
        if not infos:
            continue

        if len(infos) == 1:
            vocab[suffix] = infos[0].terms
        else:
            vocab[suffix] = {info.target: info.terms for info in infos}

    return vocab if vocab else None


@dataclass
class ExtractResult:
    """Result of extracting vocab from one rule directory."""

    rule_dir: Path
    vocab: dict[str, Any] | None
    message: str


def extract_all(rules_root: Path) -> list[ExtractResult]:
    """Extract vocab from all rules under rules_root."""
    results: list[ExtractResult] = []

    for checks_path in sorted(rules_root.rglob("checks.yml")):
        if "tests" in checks_path.parts:
            continue
        rule_dir = checks_path.parent
        vocab = extract_vocab(rule_dir)
        if vocab:
            results.append(ExtractResult(rule_dir, vocab, f"{len(vocab)} check(s)"))
        else:
            results.append(ExtractResult(rule_dir, None, "no extractable vocab"))

    return results


def write_vocab(rule_dir: Path, vocab: dict[str, Any]) -> Path:
    """Write vocab.yml to a rule directory."""
    vocab_path = rule_dir / "vocab.yml"
    vocab_path.write_text(
        yaml.dump(vocab, default_flow_style=False, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    return vocab_path
