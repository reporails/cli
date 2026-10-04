"""The session's preservation snapshots, one per briefed file, keyed by normalized path.

A snapshot is taken from the file as it stands when its rewrite brief is served; the rewrite
check (`core.heal.preservation.compare`) later judges the file against it.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from reporails_cli.core.heal.preservation import Snapshot, compare, take_snapshot
from reporails_cli.core.platform.adapters.project_environment import LocalProjectEnvironment

logger = logging.getLogger(__name__)

_snapshots: dict[str, Snapshot] = {}


def clear_snapshots() -> None:
    """Drop every stored snapshot."""
    _snapshots.clear()


def _key(file_path: Path | str) -> str:
    return os.path.normcase(os.path.normpath(str(file_path)))


def snapshot_file(file_path: Path, ruleset_map: Any, score: float | None, relation_lines: Any = ()) -> None:
    """Take (or replace) the snapshot of `file_path` from its content and `ruleset_map`. A file
    that cannot be read gets none, so no rewrite check runs against a made-up original."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("No rewrite baseline for %s: %s", file_path, exc)
        return
    _snapshots[_key(file_path)] = take_snapshot(str(file_path), text, ruleset_map, score, relation_lines)


def get_snapshot(file_path: Path) -> Snapshot | None:
    """The stored snapshot for `file_path`, or `None` when it was never briefed (or is stale —
    superseded by a later brief for a different location covering the same file)."""
    return _snapshots.get(_key(file_path))


def has_snapshot(file_path: Path) -> bool:
    return _key(file_path) in _snapshots


def forget_snapshot(file_path: Path) -> None:
    """Drop the snapshot of `file_path`, if any."""
    _snapshots.pop(_key(file_path), None)


def sibling_texts(snapshot: Snapshot, scan_root: Path | None) -> tuple[str, ...]:
    """The original text of every other briefed file under the same project root — a relation
    remedy moves an instruction between them, and the construct it carries is not invented."""
    root = Path(_key(scan_root)) if scan_root is not None else None
    return tuple(
        s.text
        for s in _snapshots.values()
        if s is not snapshot and (root is None or Path(_key(s.file_path)).is_relative_to(root))
    )


def check_rewrite(
    snapshot: Snapshot, file_path: Path, ruleset_map: Any, new_text: str, score: float | None, scan_root: Path | None
) -> dict[str, Any]:
    """The `preservation` block for `file_path`: its rewritten `new_text` and `ruleset_map` judged
    against `snapshot`, with the project on disk answering which names and paths exist."""
    environment = LocalProjectEnvironment(scan_root, file_path.parent)
    return compare(snapshot, ruleset_map, new_text, score, environment, sibling_texts(snapshot, scan_root))
