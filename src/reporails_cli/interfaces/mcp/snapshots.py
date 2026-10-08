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
# Per briefed file, how many findings each rule had when the brief was served.
_rule_counts: dict[str, dict[str, int]] = {}


def clear_snapshots() -> None:
    """Drop every stored snapshot."""
    _snapshots.clear()
    _rule_counts.clear()


def _key(file_path: Path | str) -> str:
    return os.path.normcase(os.path.normpath(str(file_path)))


def file_rule_counts(payload: dict[str, Any]) -> dict[str, int]:
    """How many findings each rule has in a single-file run's `payload` (its per-file findings)."""
    counts: dict[str, int] = {}
    for entry in (payload.get("files") or {}).values():
        for finding in entry.get("findings") or ():
            rule = str(finding.get("rule") or "")
            counts[rule] = counts.get(rule, 0) + 1
    return counts


def introduced_count(file_path: Path, payload: dict[str, Any]) -> int:
    """The findings `payload` (a single-file run of `file_path`) has beyond the ones the file had
    when its brief was served: for each rule, the growth in its count, a rule that fell adding
    nothing. 0 for a file with no recorded counts."""
    before = _rule_counts.get(_key(file_path), {})
    return sum(max(0, n - before.get(rule, 0)) for rule, n in file_rule_counts(payload).items())


def snapshot_file(
    file_path: Path,
    ruleset_map: Any,
    score: float | None,
    relation_lines: Any = (),
    rule_counts: dict[str, int] | None = None,
) -> None:
    """Take (or replace) the snapshot of `file_path` from its content and `ruleset_map`, with the
    per-rule finding counts the brief's own run found. A file that cannot be read gets none, so
    no rewrite check runs against a made-up original."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        logger.warning("No rewrite baseline for %s: %s", file_path, exc)
        return
    _snapshots[_key(file_path)] = take_snapshot(str(file_path), text, ruleset_map, score, relation_lines)
    _rule_counts[_key(file_path)] = dict(rule_counts or {})


def get_snapshot(file_path: Path) -> Snapshot | None:
    """The stored snapshot for `file_path`, or `None` when it was never briefed (or is stale —
    superseded by a later brief for a different location covering the same file)."""
    return _snapshots.get(_key(file_path))


def has_snapshot(file_path: Path) -> bool:
    return _key(file_path) in _snapshots


def forget_snapshot(file_path: Path) -> None:
    """Drop the snapshot of `file_path`, if any."""
    _snapshots.pop(_key(file_path), None)
    _rule_counts.pop(_key(file_path), None)


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
