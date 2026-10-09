"""`@path` inline import expansion.

Claude Code, Gemini CLI, Antigravity, and Cursor (`@file`) splice imported file
content at the reference position before the model sees it. The mapper must see
the same expanded content to produce accurate atom counts and
classification.

Public entry point: `expand_imports(content, source_path)`.
"""

from __future__ import annotations

import re
from pathlib import Path

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.mapper.md_parser import line_offsets
from reporails_cli.core.mapper.structure import code_ranges, in_any_span

# Match @path references in instruction files.
# Claude Code: @README, @docs/guide.md, @~/path, @./relative
# Antigravity CLI: @./path.md, @../path.md, @/absolute/path.md
# Must NOT match: email@addr, @mentions in code blocks, inline `@code`
IMPORT_REF_RE = re.compile(
    r"(?<![`\w@])"  # not inside backtick or after word char/@ (email)
    r"@("
    r"~[\w./_-]+"  # ~/home/path
    r"|\.\.?/[\w./_-]+"  # ./relative or ../parent
    r"|[\w][\w./_-]*/[\w./_-]+"  # path/with/slash (must have at least one /)
    r"|[\w][\w._-]*\.m(?:d|dc)"  # bare file.md or file.mdc
    r"|[A-Z][\w._-]*"  # UPPERCASE bare filename (README, AGENTS, CHANGELOG)
    r")"
)

# Markdown-compatible extensions that ARE expanded. Everything else — including
# binary/non-text formats (`.png`, `.pdf`, `.svg`, `.zip`, `.jpg`, …) that a
# deny-list would otherwise miss one-by-one — is left as a literal reference.
# Empty suffix covers bare filenames (`README`, `AGENTS`, `CHANGELOG`).
_EXPANDABLE_EXT = frozenset({"", ".md", ".mdc", ".markdown", ".mdx"})

_MAX_IMPORT_DEPTH = 5


def import_refs_with_lines(content: str) -> list[tuple[str, int]]:
    """The `(path, line)` pairs `content` imports with `@path`, in order, lines counted from 1; a
    reference inside a fenced or indented code block or a code span, as the markdown parse reads
    them, is documentation, not an import."""
    matches = list(IMPORT_REF_RE.finditer(content))
    if not matches:
        return []
    ranges = code_ranges(content)
    return [(m.group(1), content.count("\n", 0, m.start()) + 1) for m in matches if not in_any_span(m.start(), ranges)]


def import_refs(content: str) -> list[str]:
    """The paths `content` imports with `@path`, in order (see `import_refs_with_lines`)."""
    return [ref for ref, _ in import_refs_with_lines(content)]


def import_target(ref: str, source_path: Path) -> Path:
    """Where an `@path` reference in `source_path` points: `~` expands to the home folder, any other
    path resolves against the folder of the file that holds it (an absolute path is taken as is)."""
    return Path(ref).expanduser() if ref.startswith("~") else source_path.parent / ref


def _resolve_import_target(
    ref: str,
    source_path: Path,
    visited: set[str],
) -> Path | None:
    """Resolve an @path reference to a file path.

    Returns the resolved Path if it should be expanded, or None if it should
    be left as-is (non-markdown ext, circular, broken, etc.).
    """
    target = import_target(ref, source_path)
    try:
        target = target.resolve(strict=False)
    except (OSError, RuntimeError):
        return None  # circular or broken symlink
    if target.suffix.lower() not in _EXPANDABLE_EXT:
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

    Claude Code, Gemini CLI, Antigravity, and Cursor (@file) use @path syntax
    for inline expansion — the file content is spliced in at the reference
    position before the model sees it. The mapper must see the same expanded
    content.

    - Resolves paths relative to the importing file's directory
    - Expands ~/... to home directory
    - Recursively expands up to MAX_IMPORT_DEPTH (5 hops)
    - Detects circular imports via a per-path-chain (ancestors currently being
      expanded), not a global visited set — a file may be imported twice as
      siblings (both expand) but never inside its own expansion chain (cycle)
    - Only expands markdown-compatible files
    - Skips @references inside fenced code blocks or inline code spans
    """
    if depth >= _MAX_IMPORT_DEPTH:
        return content
    if visited is None:
        visited = {str(safe_resolve(source_path))}

    ranges = code_ranges(content) if IMPORT_REF_RE.search(content) else []

    def _replace(match: re.Match[str]) -> str:
        if in_any_span(match.start(), ranges):
            return match.group(0)
        target = _resolve_import_target(match.group(1), source_path, visited)
        if target is None:
            return match.group(0)
        try:
            imported = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return match.group(0)
        # Add for the duration of this target's own expansion (ancestor-chain
        # membership), then remove — a LATER sibling reference to the same
        # target must expand too; only an ancestor still on the stack (a real
        # cycle) should be rejected by `_resolve_import_target`.
        visited.add(str(target))
        try:
            return expand_imports(imported, target, depth=depth + 1, visited=visited)
        finally:
            visited.discard(str(target))

    return IMPORT_REF_RE.sub(_replace, content)


# Where one expanded line's text is written: the imported file it comes from (`None` for
# the file being expanded itself) and its 1-based line in that file.
LineOrigin = tuple[Path | None, int]
_Line = tuple[str, LineOrigin]


def _expand_file_lines(content: str, source_path: Path, depth: int, visited: set[str]) -> list[_Line]:
    """Every line of one file's `content` with its imports expanded, each carrying its origin.

    `depth` 0 is the file being expanded itself, whose lines carry a `None` origin path;
    an imported file's lines carry its own path. Past the depth cap a file's lines are
    kept as they are, references included, exactly as `expand_imports` keeps them.
    """
    lines = content.split("\n")
    origin_path = source_path if depth else None
    if depth >= _MAX_IMPORT_DEPTH:
        return [(line, (origin_path, idx + 1)) for idx, line in enumerate(lines)]
    ranges = code_ranges(content) if IMPORT_REF_RE.search(content) else []
    out: list[_Line] = []
    for idx, (line, line_start) in enumerate(zip(lines, line_offsets(lines), strict=True)):
        out.extend(_expand_one_line(line, line_start, (origin_path, idx + 1), source_path, visited, ranges, depth))
    return out


def _expand_one_match(match: re.Match[str], source_path: Path, visited: set[str], depth: int) -> list[_Line] | None:
    """Resolve and expand one `@import` match into its lines, or `None` when it stays a literal reference.

    Adds `target` to `visited` only for the duration of its own expansion
    (ancestor-chain membership — see `expand_imports`), so a sibling reference
    to the same target elsewhere still expands.
    """
    target = _resolve_import_target(match.group(1), source_path, visited)
    if target is None:
        return None
    try:
        imported = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    visited.add(str(target))
    try:
        return _expand_file_lines(imported, target, depth + 1, visited)
    finally:
        visited.discard(str(target))


def _expand_one_line(
    line: str,
    line_start: int,
    origin: LineOrigin,
    source_path: Path,
    visited: set[str],
    ranges: list[tuple[int, int]],
    depth: int,
) -> list[_Line]:
    """Expand every non-code-block `@import` match on one source line.

    Returns the output line(s) this source line contributes — usually one, more
    when a match's expansion spans multiple lines.
    """
    matches = [m for m in IMPORT_REF_RE.finditer(line) if not in_any_span(line_start + m.start(), ranges)]
    if not matches:
        return [(line, origin)]
    expansions = [_expand_one_match(m, source_path, visited, depth) for m in matches]
    return _splice(line, origin, matches, expansions)


def _splice(
    line: str,
    origin: LineOrigin,
    matches: list[re.Match[str]],
    expansions: list[list[_Line] | None],
) -> list[_Line]:
    """Put each reference's expansion in its place on `line`; a reference that did not expand stays as written.

    A line that holds nothing but its references gives each line its expansion produces
    the imported text's own origin; a line with text of its own keeps its origin on the
    lines that text is spliced into.
    """
    only_refs = not IMPORT_REF_RE.sub("", line).strip()
    out: list[_Line] = []
    pending, pending_origin, imported = "", origin, False
    pos_in_line = 0
    for m, expansion in zip(matches, expansions, strict=True):
        pending += line[pos_in_line : m.start()]
        pos_in_line = m.end()
        if expansion is None:
            pending += m.group(0)
            continue
        pending += expansion[0][0]
        if only_refs and not imported:
            pending_origin, imported = expansion[0][1], True
        if len(expansion) > 1:
            out.append((pending, pending_origin))
            out.extend(expansion[1:-1])
            pending = expansion[-1][0]
            pending_origin, imported = (expansion[-1][1], True) if only_refs else (origin, False)
    out.append((pending + line[pos_in_line:], pending_origin))
    return out


def expand_imports_with_origins(
    content: str,
    source_path: Path,
) -> tuple[str, list[int], list[tuple[Path, int] | None]]:
    """Expand @path imports in `content`; return `(expanded_content, line_map, origins)`.

    `line_map[i]` (0-based) is the 1-based line number in `content` — the
    importing file's OWN source — that expanded-content line `i + 1` is
    attributed to. A line untouched by any import keeps its own line number.
    A line produced by (possibly nested) import expansion has no line of its
    own in the importing file, so it is attributed to the line of the
    `@import` reference in `content` that pulled it in.

    `origins[i]` names where that line's text is written when it comes from an
    imported file: the file (at any import depth) and its 1-based line there;
    `None` for the importing file's own lines. Depth cap and circular-import
    detection mirror `expand_imports`.
    """
    visited: set[str] = {str(safe_resolve(source_path))}
    ranges = code_ranges(content) if IMPORT_REF_RE.search(content) else []
    orig_lines = content.split("\n")

    out_lines: list[str] = []
    line_map: list[int] = []
    origins: list[tuple[Path, int] | None] = []
    for idx, (line, line_start) in enumerate(zip(orig_lines, line_offsets(orig_lines), strict=True)):
        for text, (path, line_no) in _expand_one_line(
            line, line_start, (None, idx + 1), source_path, visited, ranges, 0
        ):
            out_lines.append(text)
            line_map.append(idx + 1)
            origins.append(None if path is None else (path, line_no))
    return "\n".join(out_lines), line_map, origins


def expand_imports_with_line_map(
    content: str,
    source_path: Path,
) -> tuple[str, list[int]]:
    """Expand @path imports in `content` and return `(expanded_content, line_map)`.

    The line map of :func:`expand_imports_with_origins`, for a caller that needs
    only the importing file's own line of each expanded line.
    """
    expanded, line_map, _origins = expand_imports_with_origins(content, source_path)
    return expanded, line_map
