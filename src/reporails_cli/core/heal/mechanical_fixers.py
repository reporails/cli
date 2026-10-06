"""Mechanical fixers for atom-level instruction quality issues.

Each fixer reads raw file content, locates atoms by line number, and
performs surgical text transformations. All fixers are idempotent —
running twice produces no changes on the second run.

Application order per file: format → bold → italic_constraint.
Within each fixer, edits are applied bottom-to-top by line number to
preserve line number stability for subsequent edits.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.mapper.annotate import backticked_words, is_unbacked_library_name
from reporails_cli.core.mapper.imports import IMPORT_REF_RE
from reporails_cli.core.mapper.markers import strip_markdown_inline
from reporails_cli.core.mapper.md_parser import EmphasisRun, emphasis_runs, has_bold_label, replace_spans
from reporails_cli.core.mapper.structure import LineSpans, in_any_span, line_spans, paragraph_lines
from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MechanicalFix:
    """Outcome of a mechanical fix applied to raw file content."""

    fix_type: str  # format | bold | italic_constraint
    file_path: str
    line: int
    description: str
    before: str
    after: str


# ──────────────────────────────────────────────────────────────────
# Fix 1: Unformatted code → backticks
# ──────────────────────────────────────────────────────────────────

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


def _spans_at(spans: list[LineSpans], idx: int) -> LineSpans:
    """The code and link columns of line `idx`; none for a line the parse has no entry for."""
    return spans[idx] if 0 <= idx < len(spans) else LineSpans()


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


def _wrap_site(text: str, token: str, spans: LineSpans) -> tuple[int, int] | None:
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
    spans = source_spans if written is not None and source_spans is not None else LineSpans.of_fragment(text)
    if token not in text:
        return True
    if _is_inside_code(text, token, spans):
        return False
    if atom.format == "table":
        return True
    return _wrap_site(text, token, spans) is not None


def fix_unformatted_code(atoms: list[Atom], lines: list[str]) -> list[MechanicalFix]:
    """Wrap unformatted code tokens in backticks.

    Skips a table row entirely — backtick-wrapping a cell changes its length and
    breaks the row's column padding — and skips a token that is a well-known
    prose name rather than a file, command or identifier (`_PROSE_NAMES`). A library or
    web-API name is wrapped only when the file writes it in backticks somewhere.
    """
    fixes: list[MechanicalFix] = []
    backticked = backticked_words(atoms)
    spans = line_spans("".join(lines))
    for atom in atoms:
        if not atom.unformatted_code or atom.format == "table":
            continue
        idx = atom.line - 1
        if idx < 0 or idx >= len(lines):
            continue
        original = lines[idx]
        for token in atom.unformatted_code:
            if not unformatted_token_is_reportable(atom, token, backticked):
                continue
            site = _wrap_site(lines[idx], token, _spans_at(spans, idx))
            if site is not None:
                begin, end = site
                lines[idx] = f"{lines[idx][:begin]}`{lines[idx][begin:end]}`{lines[idx][end:]}"
                if idx < len(spans):
                    spans[idx] = spans[idx].spliced(begin, 0, 1).spliced(end + 1, 0, 1).with_code((begin, end + 2))
        if lines[idx] != original:
            fixes.append(
                MechanicalFix(
                    fix_type="format",
                    file_path=atom.file_path,
                    line=atom.line,
                    description="Wrapped code tokens in backticks",
                    before=original.rstrip(),
                    after=lines[idx].rstrip(),
                )
            )
    return fixes


# ──────────────────────────────────────────────────────────────────
# Fix 2: Bold on constraints → italic
# ──────────────────────────────────────────────────────────────────


def _standalone(run: EmphasisRun, runs: tuple[EmphasisRun, ...]) -> bool:
    """Whether no other run of the line overlaps or touches `run` (inside it, around it, crossing it or
    sharing an edge with it, where the delimiters would pair with each other)."""
    return not any(other is not run and other.start <= run.end and run.start <= other.end for other in runs)


def _bold_runs_to_soften(tokens: list[str], line: str, spans: LineSpans) -> list[EmphasisRun]:
    """The bold runs of `line` an atom's `bold_tokens` name, each matched by the words it wraps (an
    earlier fixer may have put backticks inside the run since the atom was read), the last matching
    run first (a title label that opens the line repeats a later term's words).

    A run is left when it is the whole text of the line (nothing competes with it) or shares its
    words with another emphasis run (changing one would change how the other pairs).
    """
    named = [strip_markdown_inline(token) for token in tokens]
    chosen = []
    for run in reversed(spans.emphasis):
        term = strip_markdown_inline(line[run.content_start : run.content_end])
        whole = run.start == spans.text and not line[run.end :].strip()
        if run.strong and term in named and not whole and _standalone(run, spans.emphasis):
            named.remove(term)
            chosen.append(run)
    return chosen


def fix_bold_on_constraints(atoms: list[Atom], lines: list[str]) -> list[MechanicalFix]:
    """Replace bold with italic on constraint atoms (charge_value == -1).

    Changes exactly the bold runs the atom's `bold_tokens` names (the bold the lint check
    reports: not a label, not a negation phrase), found on the line through the file's emphasis
    runs. Skips a line carrying a bold label (`**Label**:`), a line that is bold from end to end,
    and a table row (changing a cell's length breaks the row's column padding).
    """
    fixes: list[MechanicalFix] = []
    spans = line_spans("".join(lines))
    for atom in atoms:
        if atom.charge_value != -1 or atom.format == "table" or not atom.bold_tokens:
            continue
        idx = atom.line - 1
        if idx < 0 or idx >= len(lines):
            continue
        original = lines[idx]
        line = _spans_at(spans, idx)
        if has_bold_label(original, line.emphasis):
            continue
        runs = _bold_runs_to_soften(atom.bold_tokens, original, line)
        if not runs:
            continue
        edits = [(run.start, run.end, f"*{original[run.content_start : run.content_end]}*") for run in runs]
        modified = replace_spans(original, edits, lambda edit: edit[2])
        lines[idx] = modified
        if idx < len(spans):
            for run in runs:  # right to left: an edit leaves the columns before it as they are
                spans[idx] = spans[idx].softened(run)
        fixes.append(
            MechanicalFix(
                fix_type="bold",
                file_path=atom.file_path,
                line=atom.line,
                description="Replaced bold with italic on constraint",
                before=original.rstrip(),
                after=modified.rstrip(),
            )
        )
    return fixes


# ──────────────────────────────────────────────────────────────────
# Fix 3: Non-italic constraints → wrap in *...*
# ──────────────────────────────────────────────────────────────────


def _takes_italic(flat: str, start: int, end: int) -> bool:
    """True when `flat[start:end]`, a sentence of the paragraph `flat`, can be wrapped in italic.

    Not when an emphasis run of the parse overlaps it: the sentence already is one (re-wrapping
    stacks another layer), holds one of its own (wrapping nests italic around it), sits inside one
    or crosses its edge. Not when a mark inside the sentence has no partner there, which the
    wrap's closing mark would pair with: the paragraph read with the wrap must hold exactly the
    runs it held before, and the new one. A single-underscore italic needs no look of its own: a
    snake_case name pairs nothing.
    """
    runs = emphasis_runs(flat)
    if any(run.start < end and start < run.end for run in runs):
        return False
    new = EmphasisRun(start, end + 2, start + 1, end + 1, "*")
    moved = [run.shifted(2) if run.start >= end else run for run in runs]
    wrapped = f"{flat[:start]}*{flat[start:end]}*{flat[end:]}"
    return emphasis_runs(wrapped) == tuple(sorted([*moved, new], key=lambda run: (run.start, -run.end)))


_SENTENCE_END_RE = re.compile(r"[.!?]+[*_\"')\]]*(?=\s|$)")
_ABBREVIATION_RE = re.compile(r"(?:\be\.g|\bi\.e|\betc|\bvs|\bcf|\bviz|\bresp)\.$", re.IGNORECASE)
# Marker characters are dropped on both sides when an atom's text is found in the paragraph, whatever
# they pair with: the atom may have been read before an earlier fixer moved a mark.
_NORMALISE_DROP = frozenset("`*_")


@dataclass(frozen=True)
class _Prose:
    """A file's lines with the places the markdown parse reads as plain paragraphs and as code."""

    lines: list[str]
    paragraphs: list[tuple[int, int]]
    spans: list[LineSpans]

    @classmethod
    def read(cls, lines: list[str]) -> _Prose:
        content = "".join(lines)
        return cls(lines, paragraph_lines(content), line_spans(content))

    def bounds(self, idx: int) -> tuple[int, int] | None:
        """First and last line of the plain paragraph holding line `idx`, or None when it is not one."""
        return next(((lo, hi) for lo, hi in self.paragraphs if lo <= idx <= hi), None)

    def is_code(self, line: int, col: int) -> bool:
        return in_any_span(col, _spans_at(self.spans, line).code)


def _flatten(prose: _Prose, lo: int, hi: int) -> tuple[str, list[tuple[int, int]]] | None:
    """Join paragraph lines (one space between them) and map each character to (line, column); the
    text of a line starts where the parse puts it, after a blockquote's `>` markers. None when the
    parse has no text start for a line."""
    chars: list[str] = []
    where: list[tuple[int, int]] = []
    for n in range(lo, hi + 1):
        raw = prose.lines[n].rstrip("\r\n")
        start = _spans_at(prose.spans, n).text
        if start is None:
            return None
        content = raw[start:].rstrip()
        if n > lo:
            chars.append(" ")
            where.append((n, len(raw)))
        for col, ch in enumerate(content, start):
            chars.append(ch)
            where.append((n, col))
    return "".join(chars), where


def _find_atom_text(flat: str, text: str, line_range: tuple[int, int]) -> tuple[int, int] | None:
    """Span of the atom's text in the flattened paragraph, when it starts in `line_range`.

    Code-span backticks and emphasis marks are ignored on both sides, so a line another
    fixer already touched still matches. None when the text is missing or ambiguous.
    """
    keep = [i for i, ch in enumerate(flat) if ch not in _NORMALISE_DROP]
    norm = "".join(flat[i] for i in keep)
    words = "".join(ch for ch in text if ch not in _NORMALISE_DROP).split()
    if not words:
        return None
    pattern = re.compile(r"\s+".join(re.escape(w) for w in words))
    hits = [m for m in pattern.finditer(norm) if line_range[0] <= keep[m.start()] < line_range[1]]
    if len(hits) != 1:
        return None
    return keep[hits[0].start()], keep[hits[0].end() - 1] + 1


def _sentence_spans(flat: str, in_code: list[bool]) -> list[tuple[int, int]] | None:
    """[start, end) of each sentence in the flattened paragraph; None when a boundary is unclear.

    A full stop inside a code span is not a boundary. An abbreviation such as `e.g.` makes
    the boundary unclear, so the paragraph is left alone.
    """
    spans: list[tuple[int, int]] = []
    start = 0
    for m in _SENTENCE_END_RE.finditer(flat):
        if in_code[m.start()]:
            continue
        if _ABBREVIATION_RE.search(flat[: m.start() + 1]):
            return None
        spans.append((start, m.end()))
        start = m.end()
    if flat[start:].strip():
        spans.append((start, len(flat)))
    out = []
    for a, b in spans:
        while a < b and flat[a].isspace():
            a += 1
        while b > a and flat[b - 1].isspace():
            b -= 1
        if a < b:
            out.append((a, b))
    return out


_Span = tuple[tuple[int, int], tuple[int, int]]


class _Located(NamedTuple):
    """A paragraph flattened to one string, the (line, column) of each character and the
    [start, end) of the atom's sentence in it."""

    flat: str
    where: list[tuple[int, int]]
    start: int
    end: int


def _locate_sentence(atom: Atom, prose: _Prose) -> _Located | None:
    """The paragraph text, its (line, column) map and the [start, end) of the atom's sentence in it."""
    bounds = prose.bounds(atom.line - 1)
    if bounds is None:
        return None
    flattened = _flatten(prose, bounds[0], bounds[1])
    if flattened is None:
        return None
    flat, where = flattened
    on_line = [i for i, (n, _) in enumerate(where) if n == atom.line - 1]
    if not on_line:
        return None
    in_code = [prose.is_code(n, col) for n, col in where]
    found = _find_atom_text(flat, atom.text, (on_line[0], on_line[-1] + 1))
    sentences = _sentence_spans(flat, in_code)
    if found is None or sentences is None:
        return None
    holding = [sp for sp in sentences if sp[0] <= found[0] and found[1] <= sp[1]]
    if len(holding) != 1:
        return None
    return _Located(flat, where, holding[0][0], holding[0][1])


def _constraint_sentence(atom: Atom, prose: _Prose) -> _Span | None:
    """Start and end (line, column) of the sentence holding a constraint, or None when unsure.

    The end is exclusive. None when the paragraph, the atom's text or a sentence boundary
    cannot be located with certainty, or the sentence cannot take the italic wrap (`_takes_italic`).
    """
    located = _locate_sentence(atom, prose)
    if located is None:
        return None
    flat, where, a, b = located
    if not _takes_italic(flat, a, b):
        return None
    return where[a], (where[b - 1][0], where[b - 1][1] + 1)


def _wrap_spans(found: dict[_Span, Atom], lines: list[str]) -> list[MechanicalFix]:
    """Insert the italic markers for each located sentence, bottom to top.

    Sentences that share a line are reported as one fix, whose text shows the whole edit.
    """
    groups: list[list[_Span]] = []
    for span in sorted(found):
        if groups and span[0][0] <= max(sp[1][0] for sp in groups[-1]):
            groups[-1].append(span)
        else:
            groups.append([span])

    fixes: list[MechanicalFix] = []
    for group in reversed(groups):
        first = min(sp[0][0] for sp in group)
        last = max(sp[1][0] for sp in group)
        before = "".join(lines[first : last + 1]).rstrip()
        for (sl, sc), (el, ec) in sorted(group, reverse=True):
            lines[el] = lines[el][:ec] + "*" + lines[el][ec:]
            lines[sl] = lines[sl][:sc] + "*" + lines[sl][sc:]
        fixes.append(
            MechanicalFix(
                fix_type="italic_constraint",
                file_path=found[group[0]].file_path,
                line=first + 1,
                description="Wrapped constraint in full-sentence italic",
                before=before,
                after="".join(lines[first : last + 1]).rstrip(),
            )
        )
    fixes.reverse()
    return fixes


def fix_italic_constraints(atoms: list[Atom], lines: list[str]) -> list[MechanicalFix]:
    """Wrap the sentence of each constraint atom (charge_value == -1) in italic.

    Wraps the prohibition's own sentence, never the raw line: a plain directive in front of it
    stays outside the italic, and a sentence broken over two lines is wrapped as one run.
    Skips a list item — italicising a whole bullet reads as heavier styling than the line
    warrants — a table row, where changing a cell's length breaks the row's column padding,
    and any sentence whose start and end cannot be located with certainty in the raw text.
    """
    found: dict[_Span, Atom] = {}
    prose = _Prose.read(lines)
    for atom in atoms:
        if atom.charge_value != -1:
            continue
        if atom.kind == "heading" or atom.format in ("list", "numbered", "table"):
            continue
        if not 0 <= atom.line - 1 < len(lines):
            continue
        span = _constraint_sentence(atom, prose)
        if span is not None:
            found.setdefault(span, atom)
    return _wrap_spans(found, lines)


# ──────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────


def apply_mechanical_fixes(
    ruleset_map: RulesetMap,
    scan_root: Path,  # noqa: ARG001
    *,
    dry_run: bool = False,
    fix_types: set[str] | None = None,
    allowed_files: set[Path] | None = None,
    suppressed: dict[Path, set[int]] | None = None,
) -> list[MechanicalFix]:
    """Apply all mechanical fixes to files in the ruleset map.

    Returns the list of fixes applied. When dry_run is True, computes
    fixes but does not write files. When `allowed_files` is given (resolved
    paths), a mapped file outside it is skipped — the write set is bounded to
    the scoped heal files, so a file whose real path escapes the heal target
    is never rewritten. When `suppressed` (resolved path -> line numbers) is
    given, atoms on those lines are skipped — a line the author annotated with
    an `ails-disable-line` directive is reviewed, so heal leaves it unmodified.
    A config-format file (settings, hooks, MCP, plugin) is not instruction text and
    gets no fix: it is the surface the formatting rule is not applied to.
    """
    all_fixes: list[MechanicalFix] = []

    # Group atoms by file
    atoms_by_file: dict[str, list[Atom]] = {}
    for atom in ruleset_map.atoms:
        atoms_by_file.setdefault(atom.file_path, []).append(atom)

    allowed = fix_types or {"format", "bold", "italic_constraint"}

    from reporails_cli.core.lint.suppression import finding_surface

    for file_path, atoms in atoms_by_file.items():
        path = Path(file_path)
        if not path.is_file() or finding_surface(file_path) == "config":
            continue
        resolved = safe_resolve(path)
        if allowed_files is not None and resolved not in allowed_files:
            continue
        sup_lines = suppressed.get(resolved, set()) if suppressed else set()
        active = [a for a in atoms if a.line not in sup_lines] if sup_lines else atoms
        all_fixes.extend(_fix_one_file(path, active, allowed, dry_run))

    return all_fixes


_LINE_BREAK = re.compile(r"(\r\n|\r|\n)")


def _read_lines(path: Path) -> tuple[list[str], list[str]]:
    """The file's lines (each ends in `\n` where the parse breaks a line) and the ending each was written with."""
    with path.open(encoding="utf-8", newline="") as handle:
        pieces = _LINE_BREAK.split(handle.read())
    lines = [f"{text}\n" for text in pieces[0:-1:2]] + ([pieces[-1]] if pieces[-1] else [])
    return lines, pieces[1::2]


def _write_lines(path: Path, lines: list[str], endings: list[str]) -> None:
    """Write `lines` back, each with the ending it was read with."""
    out = "".join(line.removesuffix("\n") + endings[i] if i < len(endings) else line for i, line in enumerate(lines))
    path.write_text(out, encoding="utf-8", newline="")


def _fix_one_file(path: Path, atoms: list[Atom], allowed: set[str], dry_run: bool) -> list[MechanicalFix]:
    """Apply the enabled fixers to one file's atoms; write unless dry_run. Returns its fixes."""
    try:
        lines, endings = _read_lines(path)
    except UnicodeDecodeError:
        logger.warning("%s is not UTF-8 text, so heal left it unchanged.", path)
        return []
    from reporails_cli.core.mapper.imports import expand_imports

    content = "".join(lines)
    try:  # a file whose @imports expand is skipped: atom.line is import-expanded, a write would mis-target
        if expand_imports(content, path) != content:
            return []
    except Exception as exc:  # any import-resolution error: skip this file, never abort the heal pass
        logger.warning("Skipping mechanical fix for %s: import-expansion failed: %s", path, exc)
        return []

    fixers = (
        ("format", fix_unformatted_code),
        ("bold", fix_bold_on_constraints),
        ("italic_constraint", fix_italic_constraints),
    )
    file_fixes: list[MechanicalFix] = []
    for name, fixer in fixers:
        if name in allowed:
            file_fixes.extend(fixer(atoms, lines))

    if file_fixes and not dry_run:
        _write_lines(path, lines, endings)
    return file_fixes
