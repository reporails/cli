"""Stage 0 — `@path` inline import expansion.

Claude Code and Gemini CLI splice imported file content at the reference
position before the model sees it. The mapper must see the same expanded
content to produce accurate atom counts and downstream classification.

Public entry point: `expand_imports(content, source_path)`.
"""

from __future__ import annotations

import re
from pathlib import Path

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
    target = Path(ref).expanduser() if ref.startswith("~") else source_path.parent / ref
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
