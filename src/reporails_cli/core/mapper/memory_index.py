"""What a memory folder's `MEMORY.md` index brings into context: the topic files it links within the part
Claude Code loads, and the type a topic file declares."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from reporails_cli.core.discovery.agent_discovery import MEMORY_INDEX_FILENAME
from reporails_cli.core.mapper.structure import link_targets, strip_anchor
from reporails_cli.core.platform.contract.json_value import as_object
from reporails_cli.core.platform.utils.utils import read_frontmatter_file

# The part of `MEMORY.md` Claude Code loads: the first 200 lines or the first 25 KB, whichever ends first.
MEMORY_LOAD_LINES = 200
MEMORY_LOAD_BYTES = 25 * 1024


def memory_type(topic: Path) -> str | None:
    """The type a memory topic file declares in its frontmatter (`type`, else `metadata.type`)."""
    read = read_frontmatter_file(topic)
    data = read.data if read is not None else None
    if data is None:
        return None
    declared = data.get("type", as_object(data.get("metadata")).get("type"))
    return declared.strip() or None if isinstance(declared, str) else None


@lru_cache(maxsize=32)
def _window_links(index: str, _modified_ns: int) -> frozenset[str]:
    """The normalised paths the first `MEMORY_LOAD_LINES` lines and `MEMORY_LOAD_BYTES` bytes of `index` link to.
    `_modified_ns` keys the cache to the file's last change."""
    with Path(index).open("rb") as handle:
        raw = handle.read(MEMORY_LOAD_BYTES)
    window = "\n".join(raw.decode("utf-8", errors="replace").splitlines()[:MEMORY_LOAD_LINES])
    folder = os.path.dirname(index)
    targets = (strip_anchor(target) for _line, target in link_targets(window))
    return frozenset(os.path.normpath(os.path.join(folder, t)) for t in targets if t and "://" not in t)


def is_linked(topic: Path) -> bool:
    """Whether the `MEMORY.md` beside a memory topic file links it within the part Claude Code loads;
    false when the folder has no index."""
    index = topic.parent / MEMORY_INDEX_FILENAME
    try:
        modified_ns = index.stat().st_mtime_ns
        links = _window_links(str(index), modified_ns)
    except OSError:
        return False
    return os.path.normpath(topic) in links
