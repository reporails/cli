"""Per-agent memory entry locator — config-driven adapter that enumerates memory entries per agent."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.agent_discovery import (
    glob_file_type_patterns,
    load_config_file_types,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MemoryEntry:
    """One enumerable memory record per agent's memory locator.

    `path` is the file holding the entry (always a real Path). `section`
    is the markdown heading whose body holds the entry (None for
    file_set agents like claude). `body` is the entry text — for
    file_set agents this is the file content; for file_section agents
    this is the section content within the file.
    """

    agent: str
    path: Path
    section: str | None
    body: str


def memory_entries_for_agent(agent: str, project_root: Path) -> list[MemoryEntry]:
    """Enumerate memory entries declared by an agent's config.

    Returns `[]` when the agent has no memory surface OR the surface
    exists but holds no entries. Callers should treat empty lists as
    "nothing to validate", not "agent unknown" — `discover_from_config`
    handles agent presence detection separately.
    """
    file_types = load_config_file_types(agent)
    if not file_types:
        return []
    entries: list[MemoryEntry] = []
    for capability in ("memory", "subagent_memory"):
        spec = file_types.get(capability)
        if not isinstance(spec, dict):
            continue
        entries.extend(_entries_from_spec(agent, capability, spec, project_root))
    return entries


def _entries_from_spec(
    agent: str,
    capability: str,
    spec: dict[str, Any],
    project_root: Path,
) -> list[MemoryEntry]:
    """Dispatch on locator type — `file_section` (gemini) vs scopes (claude)."""
    locator = spec.get("locator")
    if isinstance(locator, dict) and locator.get("type") == "file_section":
        return _entries_from_file_section(agent, locator)
    return _entries_from_directory_globs(agent, capability, spec, project_root)


def _entries_from_file_section(agent: str, locator: dict[str, Any]) -> list[MemoryEntry]:
    """Extract section content from a single file (gemini shape).

    `file` is the path to read (supports `~/` expansion). `section` is
    the literal section heading (e.g. `"## Gemini Added Memories"`).
    Returns a single MemoryEntry with the section body when the section
    exists and is non-empty; otherwise an empty list.
    """
    file_str = str(locator.get("file") or "")
    section_str = str(locator.get("section") or "")
    if not file_str or not section_str:
        return []
    path = Path(file_str).expanduser()
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.debug("memory_locator: cannot read %s: %s", path, exc)
        return []
    body = _extract_section(text, section_str)
    if not body.strip():
        return []
    return [MemoryEntry(agent=agent, path=path, section=section_str, body=body)]


def _extract_section(text: str, section_heading: str) -> str:
    """Return the body of `section_heading` — up to the next heading of equal/higher level.

    Treats Markdown ATX headings (`#`, `##`, etc.). Match is line-anchored
    against the literal `section_heading` string; case-sensitive.
    """
    lines = text.splitlines(keepends=True)
    heading_level = _heading_level(section_heading)
    if heading_level == 0:
        return ""
    in_section = False
    out: list[str] = []
    target = section_heading.strip()
    for line in lines:
        if not in_section:
            if line.strip() == target:
                in_section = True
            continue
        # Stop at the next equal-or-higher level heading
        next_level = _heading_level(line)
        if 0 < next_level <= heading_level:
            break
        out.append(line)
    return "".join(out)


def _heading_level(line: str) -> int:
    match = re.match(r"^(#{1,6})\s+\S", line)
    return len(match.group(1)) if match else 0


def _entries_from_directory_globs(
    agent: str,
    capability: str,
    spec: dict[str, Any],
    project_root: Path,
) -> list[MemoryEntry]:
    """Enumerate `*.md` files inside directory-glob patterns (claude shape).

    Reuses `agent_discovery.glob_file_type_patterns` so the file
    enumeration matches what the classifier surfaces — single source of
    truth for which paths the agent treats as memory entries.
    """
    scopes = spec.get("scopes")
    if not isinstance(scopes, dict):
        return []
    patterns: list[str] = []
    for scope in scopes.values():
        if not isinstance(scope, dict):
            continue
        ps = scope.get("patterns")
        if isinstance(ps, list):
            patterns.extend(str(p) for p in ps)
    if not patterns:
        return []
    # Pass empty properties — directory-glob dispatch in glob_file_type_patterns
    # only needs the patterns themselves for trailing-slash enumeration.
    paths = glob_file_type_patterns(project_root, patterns, properties={})
    entries: list[MemoryEntry] = []
    for path in paths:
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        entries.append(MemoryEntry(agent=agent, path=path, section=None, body=body))
    # Log capability provenance so debugging can attribute entries to the right surface
    logger.debug("memory_locator: %s/%s -> %d entries", agent, capability, len(entries))
    return entries
