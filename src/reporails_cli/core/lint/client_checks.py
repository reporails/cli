"""Client-side checks — run locally on RulesetMap atoms.

Four checks: unformatted code tokens, bold on
directives, broad scope terms, and sentences holding more than one instruction.
"""

from __future__ import annotations

import re
from pathlib import Path

from reporails_cli.core.mapper.annotate import backticked_words, is_unbacked_library_name
from reporails_cli.core.mapper.classify_lexicon import CONDITION_OPENERS
from reporails_cli.core.mapper.imports import IMPORT_REF_RE
from reporails_cli.core.mapper.instructions import instruction_starts, without_lead
from reporails_cli.core.mapper.markers import strip_markdown_inline
from reporails_cli.core.mapper.md_parser import emphasis_runs, has_bold_label, wrapping_runs
from reporails_cli.core.mapper.prose_split import ends_with_sentence_mark
from reporails_cli.core.mapper.structure import fragment_line_spans, in_any_span, line_spans
from reporails_cli.core.platform.dto.diagnostics import BOLD_CHECK, FORMAT_CHECK, SEVERITY_RANK
from reporails_cli.core.platform.dto.mapping import LineSpans
from reporails_cli.core.platform.dto.models import LocalFinding
from reporails_cli.core.platform.dto.ruleset import RUNNING_TEXT_FORMATS, Atom, RulesetMap
from reporails_cli.core.platform.runtime.merger import normalize_finding_path

_PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-")
# A bare URL (scheme://rest, no whitespace) — a token that sits inside one is left
# unwrapped entirely. The leftward path-run extension stops at the first character
# outside `_PATH_CHARS` (a `:` in a port number, the scheme's own `:`), so wrapping
# only the remainder after that point would backtick a fragment of the URL and leave
# the rest bare, splitting it instead of formatting it.
_URL_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://\S+")
# A small set of well-known technology/product names that read as plain prose in
# running text (not a file, command or identifier this project defines) even though
# their mixed-case spelling matches the code-shape heuristics upstream.
_PROSE_NAMES = frozenset({"javascript", "devtools", "pypi", "git"})


def _is_inside_code(text: str, token: str, spans: LineSpans) -> bool:
    """Check if every occurrence of token in text is inside a code span or an inline HTML tag."""
    return all(
        in_any_span(m.start(), (*spans.code, *spans.html)) for m in re.finditer("(?=" + re.escape(token) + ")", text)
    )


def _without_emphasis_closer(text: str, token: str) -> str:
    """The token without a trailing `_` (and the punctuation before it) that closes an
    underscore emphasis run of `text` ending where the token ends, so the closer stays outside
    the code span."""
    if not token.endswith("_"):
        return token
    trimmed = token.rstrip("_").rstrip(".!?,;:")
    if not trimmed or trimmed == token:
        return token
    at = text.find(token)
    if at < 0 or not any(run.marker.startswith("_") and run.end == at + len(token) for run in emphasis_runs(text)):
        return token
    return trimmed


def wrap_site(text: str, token: str, spans: LineSpans) -> tuple[int, int] | None:
    """The `[start, end)` of `text` to backtick-wrap for the first occurrence of token outside code
    spans, inline HTML tags, markdown link labels/targets (`spans` holds them, as the parse places
    them in `text`), a bare URL, or an `@import` reference; None when there is no such occurrence.

    Extends the wrap leftward over any contiguous relative-path run (letters,
    digits, `_.-/`) immediately preceding the token, so a basename detected inside
    a longer path — `tests/unit/test_parser.py` — backticks the full path instead
    of only the basename. A leading `~` (home-dir shorthand, e.g. `~/.claude/`)
    is absorbed into the same wrap, so `~/.claude/settings.json` wraps whole
    instead of leaving the `~` stranded outside the backticks. An occurrence inside
    a bare URL is left unwrapped entirely instead — wrapping only part of it (the
    leftward run stops at a port's `:` or the scheme's own `:`) would split the URL,
    leaving one part bare and the other backticked. An occurrence inside an `@import`
    reference is left unwrapped too: wrapping it would read the reference as inline
    code and drop it from import resolution, hiding a broken or a live import alike.
    """
    token = _without_emphasis_closer(text, token)
    url_spans = [m.span() for m in _URL_RE.finditer(text)]
    import_spans = [m.span() for m in IMPORT_REF_RE.finditer(text)]
    pattern = re.compile(r"(?<!`)(?<![`\w])" + re.escape(token) + r"(?![`\w])(?!`)")
    for m in pattern.finditer(text):
        if any(m.start() < e and s < m.end() for s, e in (*spans.links, *spans.code, *spans.html)):
            continue
        if in_any_span(m.start(), url_spans) or in_any_span(m.start(), import_spans):
            continue
        start, end = m.start(), m.end()
        while start > 0 and text[start - 1] in _PATH_CHARS and not in_any_span(start - 1, spans.links):
            start -= 1
        if start > 0 and text[start - 1] == "~" and not in_any_span(start - 1, spans.links):
            start -= 1
        if start > 0 and text[start - 1] == "`":
            start = m.start()  # the run reaches a code span's closing backtick: wrap the token alone
        return start, end
    # No word-boundaried occurrence outside a link, code span or HTML tag: nothing safe to wrap. A plain
    # substring fallback would wrap the token mid-word (e.g. `npm` inside `npmrc`),
    # corrupting the line, so there is no site.
    return None


def unformatted_token_is_reportable(
    atom: Atom,
    token: str,
    backticked: frozenset[str],
    source_line: str | None = None,
    source_spans: LineSpans | None = None,
) -> bool:
    """False when `token` is not a formatting defect on this atom's line.

    `source_line` is the line as written in the file and `source_spans` the columns of it the
    markdown parse reads as code or links: the atom's text has its link syntax removed,
    so a token that is link text can only be told apart on the written line.

    A well-known prose name and a token inside a markdown link, a bare URL or an `@import`
    reference are not code to wrap, so they are not reported. A library or web-API name
    (`FastAPI`, `WebSocket`) is reported only when the file writes the same name in backticks
    somewhere (`backticked`). A token in a table row is a real defect: heal leaves the row
    alone (wrapping breaks its column padding), the finding stays.
    """
    if token.lower() in _PROSE_NAMES:
        return False
    if is_unbacked_library_name(token, backticked):
        return False
    written = source_line if source_line is not None and token in source_line else None
    text = written if written is not None else atom.text
    spans = source_spans if written is not None and source_spans is not None else fragment_line_spans(text)
    if token not in text:
        return True
    if _is_inside_code(text, token, spans):
        return False
    if atom.format == "table":
        return True
    return wrap_site(text, token, spans) is not None


_SCOPE_RE = re.compile(
    r"^(?:" + "|".join(re.escape(word) for word in sorted(CONDITION_OPENERS)) + r")\s+(.+?),\s+",
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

BROAD_SCOPE_RULE = "CORE:C:0060"
PACKED_SENTENCE_RULE = "CORE:C:0058"
FORMATTING_RULE = "CORE:E:0003"


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

    findings.sort(key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.line))
    return findings


def _relative_display_path(file_path: str) -> str:
    """Normalize file path for display. Uses merger's normalize_finding_path."""
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


def running_sentences(atoms: list[Atom]) -> list[list[Atom]]:
    """The file's running-text sentences, each as the atoms it was read into.

    Atoms on one line belong to one sentence until one ends with a sentence mark; a prose
    sentence that does not end on its line continues on the next.
    """
    sentences: list[list[Atom]] = []
    for a in atoms:
        if a.kind == "heading" or a.format not in RUNNING_TEXT_FORMATS:
            continue
        prev = sentences[-1][-1] if sentences else None
        continues = (
            prev is not None
            and not ends_with_sentence_mark(strip_markdown_inline(prev.text, keep_code=True))
            and (a.line == prev.line or (a.format == prev.format == "prose" and a.line == prev.line + 1))
        )
        if continues:
            sentences[-1].append(a)
        else:
            sentences.append([a])
    return sentences


def sentence_instructions(sentence: list[Atom]) -> list[str]:
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
    for sentence in running_sentences(atoms):
        instructions = sentence_instructions(sentence)
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
                fix="Give each instruction its own sentence that stands on its own: repeat the subject or object "
                "they share, keep a directive with the bound that limits it, and keep a lead-in with every item "
                "it introduces.",
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
                    rule=FORMATTING_RULE,
                    check_id=FORMAT_CHECK,
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
                rule=FORMATTING_RULE,
                check_id=BOLD_CHECK,
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
