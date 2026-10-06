"""Client-side checks — run locally on RulesetMap atoms.

Four checks: unformatted code tokens, bold on
directives, broad scope terms, and sentences holding more than one instruction.
"""

from __future__ import annotations

import re
from pathlib import Path

from reporails_cli.core.heal.mechanical_fixers import unformatted_token_is_reportable
from reporails_cli.core.mapper.annotate import backticked_words
from reporails_cli.core.mapper.instructions import instruction_starts, without_lead
from reporails_cli.core.mapper.markers import strip_markdown_inline
from reporails_cli.core.mapper.md_parser import emphasis_runs, has_bold_label, wrapping_runs
from reporails_cli.core.mapper.structure import line_spans
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap

_SCOPE_RE = re.compile(
    r"^(?:when|if|unless|before|after)\s+(.+?),\s+",
    re.IGNORECASE,
)
# Words that put an outside system in the condition, singular or plural. Wide but harmless wording
# ("any file", "all tests") is not listed.
_BROAD_SCOPE_WORDS = (
    "services?",
    "third-party",
    "external",
    "integrations?",
    "dependenc(?:y|ies)",
    "databases?",
    "sql",
)
# Matched as WHOLE WORDS: a substring test reads a short word out of a longer one
# that has nothing to do with scope.
_BROAD_SCOPE_RE = re.compile(r"\b(?:" + "|".join(_BROAD_SCOPE_WORDS) + r")\b", re.IGNORECASE)

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}

BROAD_SCOPE_RULE = "CORE:C:0060"
PACKED_SENTENCE_RULE = "CORE:C:0058"
_RUNNING_TEXT = frozenset({"prose", "list", "numbered", "blockquote", "table"})
_SENTENCE_END_RE = re.compile(r"[.!?][)\]\"'`]*$")


def run_client_checks(ruleset_map: RulesetMap) -> list[LocalFinding]:
    """Run D-level client checks on a RulesetMap.

    Returns findings sorted by severity then line number. File paths
    are normalized to project-relative display paths.
    """
    findings: list[LocalFinding] = []

    # Group atoms by file for filepath context
    atoms_by_file: dict[str, list[Atom]] = {}
    for atom in ruleset_map.atoms:
        atoms_by_file.setdefault(atom.file_path, []).append(atom)

    for filepath, atoms in atoms_by_file.items():
        display = _relative_display_path(filepath)
        findings.extend(_check_file(atoms, display, _source_lines(filepath)))

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.line))
    return findings


def _relative_display_path(file_path: str) -> str:
    """Normalize file path for display. Uses merger's normalize_finding_path."""
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    return normalize_finding_path(file_path)


def _source_lines(file_path: str) -> list[str]:
    """The file's lines as written; empty when the file cannot be read."""
    try:
        return Path(file_path).read_text(encoding="utf-8").split("\n")
    except (OSError, UnicodeDecodeError, ValueError):
        return []


def _check_file(atoms: list[Atom], filepath: str, source_lines: list[str] | None = None) -> list[LocalFinding]:
    """Run all D-level checks on atoms from a single file."""
    findings: list[LocalFinding] = []
    charged = [a for a in atoms if a.charge_value != 0]

    findings.extend(_check_unformatted_code(atoms, filepath, source_lines))
    findings.extend(_check_bold_patterns(charged, filepath))
    findings.extend(_check_broad_scope(charged, filepath))
    findings.extend(_check_packed_sentences(atoms, filepath))

    return findings


def _sentences(atoms: list[Atom]) -> list[list[Atom]]:
    """The file's running-text sentences, each as the atoms it was read into.

    Atoms on one line belong to one sentence until one ends with a sentence mark; a prose
    sentence that does not end on its line continues on the next.
    """
    sentences: list[list[Atom]] = []
    for a in atoms:
        if a.kind == "heading" or a.format not in _RUNNING_TEXT:
            continue
        prev = sentences[-1][-1] if sentences else None
        continues = (
            prev is not None
            and not _SENTENCE_END_RE.search(strip_markdown_inline(prev.text, keep_code=True).rstrip())
            and (a.line == prev.line or (a.format == prev.format == "prose" and a.line == prev.line + 1))
        )
        if continues:
            sentences[-1].append(a)
        else:
            sentences.append([a])
    return sentences


def _instructions(sentence: list[Atom]) -> list[str]:
    """The instructions a sentence gives, as written: each one the sentence reads as charged.

    Parts of one instruction read apart (a label and the command it introduces) count once. The sentence's
    list marker, checkbox and lead label give no command and are left out.
    """
    text, spans = "", []
    for a in sentence:
        part = strip_markdown_inline(a.text.strip() if text else without_lead(a.text), keep_code=True)
        spans.append((len(text), len(text) + len(part), a.charge_value != 0))
        text += part + " "
    text = text.rstrip()
    bounds = [0, *instruction_starts(text)[1:], len(text)]
    charged = {
        i
        for start, end, is_charged in spans
        if is_charged
        for i in range(len(bounds) - 1)
        if bounds[i] < end and bounds[i + 1] > start
    }
    return [text[bounds[i] : bounds[i + 1]].strip() for i in sorted(charged)]


def _check_packed_sentences(atoms: list[Atom], filepath: str) -> list[LocalFinding]:
    """Report each sentence read as more than one instruction, naming them."""
    findings: list[LocalFinding] = []
    for sentence in _sentences(atoms):
        instructions = _instructions(sentence)
        if len(instructions) < 2:
            continue
        named = " / ".join(f'"{text}"' for text in instructions)
        findings.append(
            LocalFinding(
                file=filepath,
                line=sentence[0].line,
                severity="warning",
                rule=PACKED_SENTENCE_RULE,
                message=f"This sentence holds {len(instructions)} instructions ({named}) — instructions sharing "
                "a sentence compete, and some of them are not followed.",
                fix="Give each instruction its own sentence.",
                source="client_check",
            )
        )
    return findings


def _check_unformatted_code(
    atoms: list[Atom], filepath: str, source_lines: list[str] | None = None
) -> list[LocalFinding]:
    """Check for code tokens missing backtick formatting.

    An atom's `unformatted_code` can carry the same word twice under different
    casing (a known code word matched case-insensitively, the same text also
    matched by its mixed-case shape) — reported once, by its first-seen casing. A prose name, a token inside a
    link's text or target, and a token inside a URL or import are not reported; a library or
    web-API name is reported only when the file writes it in backticks somewhere.
    """
    findings: list[LocalFinding] = []
    backticked = backticked_words(atoms)
    spans = line_spans("\n".join(source_lines)) if source_lines else []
    for a in atoms:
        written = (source_lines or [])[a.line - 1] if 0 < a.line <= len(source_lines or []) else None
        seen: set[str] = set()
        reportable: list[str] = []
        for code_tok in a.unformatted_code:
            key = code_tok.lower()
            if key in seen or not unformatted_token_is_reportable(
                a, code_tok, backticked, written, spans[a.line - 1] if written is not None else None
            ):
                continue
            seen.add(key)
            reportable.append(_as_written(code_tok, written))
        for code_tok in reportable:
            if _is_part_of_other_name(code_tok, reportable, written or a.text):
                continue
            findings.append(
                LocalFinding(
                    file=filepath,
                    line=a.line,
                    severity="warning",
                    rule="format",
                    message=f"'{code_tok}' should be in backticks — use `{code_tok}`",
                    fix=f"Wrap in backticks: `{code_tok}`",
                    source="client_check",
                )
            )
    return findings


def _as_written(token: str, written: str | None) -> str:
    """The token as the line spells it: the mapper lower-cases the code words it knows."""
    if written is None or token in written:
        return token
    m = re.search(re.escape(token), written, re.IGNORECASE)
    return m.group(0) if m else token


def _is_part_of_other_name(token: str, names: list[str], line: str) -> bool:
    """True when every place `token` occurs in `line` lies inside another reported name.

    `settings.json` is one name: `json` inside it is not a second one.
    """
    longer = [n for n in names if n != token and token.lower() in n.lower()]
    if not longer:
        return False
    rest = line.lower()
    for n in sorted(longer, key=len, reverse=True):
        rest = rest.replace(n.lower(), "")
    return token.lower() not in rest


def _check_bold_patterns(charged: list[Atom], filepath: str) -> list[LocalFinding]:
    """Check for harmful bold emphasis on directive atoms.

    The bold that competes is what the atom already carries in `bold_tokens`: the bold runs of the
    markdown parse, less a title label, a colon-ended label and a negation phrase. Rules of the check
    itself: a `code_block` atom (a fence-cascade directive) carries literal markdown, so its `**` is
    text typed inside a fence, not bold; an atom bold from end to end has no other instruction for
    the bold to compete with; an atom carrying a bold label (`**Label**:`) anywhere is left whole.
    """
    findings: list[LocalFinding] = []
    for a in charged:
        if a.charge_value != +1 or a.format == "code_block" or not a.bold_tokens:
            continue
        if any(run.strong for run in wrapping_runs(a.text)) or has_bold_label(a.text, emphasis_runs(a.text)):
            continue
        terms_str = ", ".join(f"**{t}**" for t in a.bold_tokens[:3])
        findings.append(
            LocalFinding(
                file=filepath,
                line=a.line,
                severity="info",
                rule="bold",
                message=(
                    f"Bold on terms: {terms_str}. "
                    f"Bold competes for attention between instructions — "
                    f"use `backtick` or *italic* instead."
                ),
                fix="Use `backtick` for code tokens or *italic* for emphasis.",
                source="client_check",
            )
        )
    return findings


def _check_broad_scope(charged: list[Atom], filepath: str) -> list[LocalFinding]:
    """Check for overly broad conditional scope terms."""
    findings: list[LocalFinding] = []
    for a in charged:
        if not a.scope_conditional:
            continue
        m = _SCOPE_RE.match(a.text)
        if not m:
            continue
        scope_text = m.group(1).lower()
        broad_matches = sorted({w.group(0).lower() for w in _BROAD_SCOPE_RE.finditer(scope_text)})
        if broad_matches:
            findings.append(
                LocalFinding(
                    file=filepath,
                    line=a.line,
                    severity="warning",
                    rule=BROAD_SCOPE_RULE,
                    message=(
                        f'Broad conditional scope: "{m.group(1)}". '
                        f"Broad terms ({', '.join(broad_matches)}) may trigger unintended behavior."
                    ),
                    fix="Name the specific situation instead of using broad terms, or remove the condition.",
                    source="client_check",
                )
            )
    return findings
