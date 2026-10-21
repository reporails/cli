"""Per-agent memory entry locator — config-driven adapter that enumerates memory entries per agent."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from reporails_cli.core.discovery.agent_config import load_config_file_types
from reporails_cli.core.discovery.agent_discovery import MEMORY_SURFACES, glob_file_type_patterns
from reporails_cli.core.discovery.exclusions import RunExclusions
from reporails_cli.core.platform.contract.json_value import JsonObject, as_object, pattern_list

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MemoryEntry:
    """One enumerable memory record per agent's memory locator.

    `path` is the file holding the entry (always a real Path). `body` is
    the entry text: the file content.
    """

    agent: str
    path: Path
    body: str


def memory_entries_for_agent(agent: str, project_root: Path, exclusions: RunExclusions) -> list[MemoryEntry]:
    """Enumerate memory entries declared by an agent's config.

    Returns `[]` when the agent has no memory surface OR the surface
    exists but holds no entries. Callers should treat empty lists as
    "nothing to validate", not "agent unknown" — `discover_from_config`
    handles agent presence detection separately. `exclusions` holds the folders the walk
    does not enter.
    """
    file_types = load_config_file_types(agent)
    if not file_types:
        return []
    entries: list[MemoryEntry] = []
    for capability in sorted(MEMORY_SURFACES):
        spec = file_types.get(capability)
        if not isinstance(spec, dict):
            continue
        entries.extend(_entries_from_directory_globs(agent, capability, spec, project_root, exclusions))
    return entries


def _entries_from_directory_globs(
    agent: str,
    capability: str,
    spec: JsonObject,
    project_root: Path,
    exclusions: RunExclusions,
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
        patterns.extend(pattern_list(as_object(scope).get("patterns")))
    if not patterns:
        return []
    # Pass empty properties — directory-glob dispatch in glob_file_type_patterns
    # only needs the patterns themselves for trailing-slash enumeration.
    paths = glob_file_type_patterns(project_root, patterns, {}, exclusions)
    entries: list[MemoryEntry] = []
    for path in paths:
        try:
            body = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        entries.append(MemoryEntry(agent=agent, path=path, body=body))
    # Log capability provenance so debugging can attribute entries to the right surface
    logger.debug("memory_locator: %s/%s -> %d entries", agent, capability, len(entries))
    return entries
