"""File classification engine — typed file targeting for rules.

Replaces the template variable system. Agent configs declare file_types
with glob patterns and properties. Rules declare match criteria. The
classification engine resolves files to types and matches rules to files.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path, PurePosixPath

import yaml

from reporails_cli.core.models import ClassifiedFile, FileMatch, FileTypeDeclaration
from reporails_cli.core.utils import load_yaml_file

logger = logging.getLogger(__name__)


def load_file_types(
    agent: str,
    rules_paths: list[Path] | None = None,
) -> list[FileTypeDeclaration]:
    """Load file_types from agent config.yml.

    Searches rules_paths first, then falls back to default config path.

    Args:
        agent: Agent identifier (e.g., "claude")
        rules_paths: Optional rules directories to search first

    Returns:
        List of FileTypeDeclaration, empty if no config found
    """
    from reporails_cli.core.bootstrap import get_agent_config_path

    candidates: list[Path] = []
    if rules_paths:
        candidates.extend(rules_dir / agent / "config.yml" for rules_dir in rules_paths)
    candidates.append(get_agent_config_path(agent))

    for config_path in candidates:
        if not config_path.exists():
            continue
        try:
            data = load_yaml_file(config_path)
            if not data:
                logger.warning("Agent config is empty: %s", config_path)
                continue
            file_types_data = data.get("file_types", {})
            if not file_types_data:
                continue
            return _parse_file_types(file_types_data)
        except (yaml.YAMLError, OSError) as exc:
            logger.warning("Failed to parse agent file_types %s: %s", config_path, exc)
            continue
    return []


def _parse_file_types(data: dict[str, object]) -> list[FileTypeDeclaration]:
    """Parse file_types dict from agent config into FileTypeDeclaration list.

    Supports both v0.3.0 (patterns + properties nested) and v0.5.0
    (scopes with patterns, properties flattened) schema versions.
    """
    from reporails_cli.core.agents import _extract_patterns
    from reporails_cli.core.agents import _extract_properties as _agent_props

    declarations: list[FileTypeDeclaration] = []
    for name, spec in data.items():
        if not isinstance(spec, dict):
            continue
        patterns = _extract_patterns(spec)
        # v0.3.0: properties nested; v0.5.0: flattened at file type level
        raw_props = spec.get("properties")
        if isinstance(raw_props, dict):
            props = _extract_properties(raw_props)
        else:
            props = _extract_properties(_agent_props(spec))
        declarations.append(
            FileTypeDeclaration(
                name=name,
                patterns=tuple(str(p) for p in patterns),
                required=spec.get("required", False),
                properties=props,
            )
        )
    return declarations


def _extract_properties(props: dict[str, object] | None) -> dict[str, str | list[str]]:
    """Extract properties from config. Preserves lists for multi-valued properties."""
    if not props:
        return {}
    result: dict[str, str | list[str]] = {}
    for k, v in props.items():
        if v is None:
            continue
        if isinstance(v, list):
            result[k] = [str(item) for item in v]
        else:
            result[k] = str(v)
    return result


def _strip_fenced_blocks(text: str) -> tuple[str, set[str]]:
    """Remove fenced code/data block interiors, return (text_outside, block_types).

    Detects code_block and data_block while building a version of the text
    with fence interiors removed, so downstream detectors (table, list, prose,
    inline formats) don't false-positive on content inside examples.
    """
    _data_langs = {"mermaid", "yaml", "yml", "json", "toml", "xml", "csv"}
    block_types: set[str] = set()
    lines = text.split("\n")
    outside_lines: list[str] = []
    in_fence = False
    fence_marker = ""

    for line in lines:
        m = re.match(r"^(`{3,}|~{3,})(\S*)", line)
        if m and not in_fence:
            # Opening fence
            fence_marker = m.group(1)
            lang = m.group(2).lower().strip()
            block_types.add("data_block" if lang in _data_langs else "code_block")
            in_fence = True
            continue
        if in_fence:
            # Check for closing fence: same char, at least as many repeats
            cm = re.match(r"^(`{3,}|~{3,})\s*$", line)
            if cm and cm.group(1)[0] == fence_marker[0] and len(cm.group(1)) >= len(fence_marker):
                in_fence = False
                fence_marker = ""
            continue
        outside_lines.append(line)

    return "\n".join(outside_lines), block_types


def _has_prose(text_outside: str) -> bool:
    """Check if text contains non-trivial prose paragraphs outside structural elements."""
    for line in text_outside.split("\n"):
        line = line.strip()
        if not line:
            continue
        if line.startswith(("#", "|", "-", "*", "+", ">", "`", "~")):
            continue
        if re.match(r"^\d+\.\s", line):
            continue
        if len(line) > 10:
            return True
    return False


def detect_content_format(text: str) -> list[str]:
    """Detect which content region types are present in markdown text.

    Content format is intrinsic to freeform (markdown) files — not agent-specific.
    Returns the list of content_format values found.

    Block-level values:
      prose: natural language paragraphs
      heading: markdown section headers
      code_block: fenced code blocks
      data_block: structured data/visualization (mermaid, yaml, json, toml)
      table: markdown tables
      list: ordered/unordered lists
      blockquote: lines starting with >

    Inline values (detected outside code blocks):
      inline_code: backtick-delimited inline code spans
      bold: **text** or __text__ emphasis
      link: [text](url) or [text][ref] hyperlinks
    """
    formats: set[str] = set()

    # Strip frontmatter before analysis
    stripped = re.sub(r"\A---\s*\n.*?\n---\s*\n", "", text, count=1, flags=re.DOTALL)

    # heading: lines starting with # (markdown headers) — valid outside code blocks
    # (headings inside fenced blocks are stripped below)
    # We detect on full text first, then refine with text_outside
    # Actually, detect on text_outside to avoid false positives
    text_outside, block_types = _strip_fenced_blocks(stripped)
    formats.update(block_types)

    # heading: on text outside fences
    if re.search(r"(?m)^#{1,6}\s+\S", text_outside):
        formats.add("heading")

    # table: markdown tables (lines with | delimiters and separator row)
    if re.search(r"(?m)^\|.*\|.*\n\|[\s:|-]+\|", text_outside):
        formats.add("table")

    # list: lines starting with -, *, +, or 1. (after optional whitespace)
    if re.search(r"(?m)^[ \t]*[-*+]\s+\S", text_outside) or re.search(r"(?m)^[ \t]*\d+\.\s+\S", text_outside):
        formats.add("list")

    # blockquote: lines starting with >
    if re.search(r"(?m)^>\s", text_outside):
        formats.add("blockquote")

    if _has_prose(text_outside):
        formats.add("prose")

    # Inline modes: detected outside code blocks to avoid false positives
    # bold: **text** or __text__
    if re.search(r"\*\*[^*]+\*\*|__[^_]+__", text_outside):
        formats.add("bold")

    # inline_code: `text` (single backtick, not triple)
    if re.search(r"(?<!`)`(?!`)[^`\n]+`(?!`)", text_outside):
        formats.add("inline_code")

    # link: [text](url) or [text][ref]
    if re.search(r"\[[^\]]+\]\([^)]+\)|\[[^\]]+\]\[[^\]]*\]", text_outside):
        formats.add("link")

    return sorted(formats)


def classify_files(
    scan_root: Path,
    files: list[Path],
    file_types: list[FileTypeDeclaration],
) -> list[ClassifiedFile]:
    """Classify files against type declarations. First pattern match wins.

    For freeform files, content_format is detected from file content.

    Args:
        scan_root: Project root for computing relative paths
        files: Files to classify
        file_types: Type declarations from agent config

    Returns:
        List of ClassifiedFile for matched files
    """
    classified: list[ClassifiedFile] = []
    for file_path in files:
        try:
            rel = str(file_path.relative_to(scan_root))
        except ValueError:
            rel = str(file_path)

        for ft in file_types:
            if _matches_any_pattern(rel, ft.patterns):
                props = dict(ft.properties)
                # Detect content_format for freeform files
                fmt = props.get("format")
                is_freeform = fmt == "freeform" or (isinstance(fmt, list) and "freeform" in fmt)
                if is_freeform and "content_format" not in props:
                    try:
                        text = file_path.read_text(encoding="utf-8", errors="replace")
                        cf = detect_content_format(text)
                        if cf:
                            props["content_format"] = cf
                    except OSError:
                        pass
                classified.append(
                    ClassifiedFile(
                        path=file_path,
                        file_type=ft.name,
                        properties=props,
                    )
                )
                break  # First match wins
    return classified


def match_files(
    classified: list[ClassifiedFile],
    match: FileMatch,
) -> list[ClassifiedFile]:
    """Filter classified files by property match. None properties are wildcards.

    Args:
        classified: Previously classified files
        match: Match criteria (None fields match everything)

    Returns:
        Filtered list of ClassifiedFile
    """
    return [cf for cf in classified if file_matches(cf, match)]


def resolve_match_to_paths(
    classified: list[ClassifiedFile],
    match: FileMatch | None,
    scan_root: Path,
) -> list[str]:
    """Resolve match criteria to relative path strings for the regex runner.

    Args:
        classified: Previously classified files
        match: Match criteria, or None for all files
        scan_root: Project root for relative paths

    Returns:
        List of relative path strings
    """
    targets = classified if match is None else match_files(classified, match)

    paths: list[str] = []
    for cf in targets:
        try:
            paths.append(str(cf.path.relative_to(scan_root)))
        except ValueError:
            paths.append(str(cf.path))
    return paths


def _prop_matches(match_val: list[str] | str | None, actual: list[str] | str | None) -> bool:
    """Check a property match criterion against an actual property value.

    Both sides can be scalar or list:
    - match=None: wildcard (always matches)
    - match=str vs actual=str: exact equality
    - match=str vs actual=list: match_val in actual (file has the property)
    - match=list vs actual=str: actual in match_val (rule accepts the value)
    - match=list vs actual=list: sets intersect (any overlap)
    """
    if match_val is None:
        return True
    if actual is None:
        return False
    if isinstance(match_val, list) and isinstance(actual, list):
        return bool(set(match_val) & set(actual))
    if isinstance(match_val, list):
        return actual in match_val
    if isinstance(actual, list):
        return match_val in actual
    return actual == match_val


def file_matches(cf: ClassifiedFile, match: FileMatch) -> bool:
    """Check if a classified file matches the given criteria."""
    if not _prop_matches(match.type, cf.file_type):
        return False
    for prop in (
        "scope",
        "format",
        "content_format",
        "cardinality",
        "lifecycle",
        "maintainer",
        "vcs",
        "loading",
        "precedence",
    ):
        if not _prop_matches(getattr(match, prop), cf.properties.get(prop)):
            return False
    return True


def _matches_any_pattern(rel_path: str, patterns: tuple[str, ...]) -> bool:
    """Check if a relative path matches any glob pattern.

    Uses PurePosixPath.match() for glob matching. Handles ``**`` as
    zero-or-more directory components by generating collapsed variants
    (e.g. ``a/**/b`` also tries ``a/b``).
    """
    p = PurePosixPath(rel_path)
    for pattern in patterns:
        clean = pattern.removeprefix("./")
        for variant in _expand_doublestar(clean):
            if p.match(variant):
                return True
    return False


def _expand_doublestar(pattern: str) -> list[str]:
    """Expand a glob pattern into variants where each ``**/`` matches zero dirs.

    ``a/**/b/*.md`` yields:
      - ``a/**/b/*.md``   (original — ** matches 1+ dirs)
      - ``a/b/*.md``      (** collapsed — zero dirs)

    Multiple ``**/`` segments produce one variant per collapse.
    """
    parts = pattern.split("/")
    star_indices = [i for i, p in enumerate(parts) if p == "**"]
    if not star_indices:
        return [pattern]
    # Build variants: original + one collapsed version per ** segment
    variants = [pattern]
    for idx in star_indices:
        collapsed = [p for i, p in enumerate(parts) if i != idx]
        if collapsed:
            variants.append("/".join(collapsed))
    return variants
