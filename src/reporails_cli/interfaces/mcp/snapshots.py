"""The session's preservation snapshots, one per briefed file, keyed by normalized path.

A snapshot is taken from the file as it stands when its rewrite brief is served; the rewrite
check (`core.heal.preservation.compare`) later judges the file against it.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from pathlib import Path

from reporails_cli.core.heal.conformance import check_plan
from reporails_cli.core.heal.file_io import split_lines
from reporails_cli.core.heal.preservation import check_rewrite as judge_rewrite
from reporails_cli.core.heal.preservation import take_snapshot
from reporails_cli.core.lint.content_queries import atoms_for_file
from reporails_cli.core.platform.contract.json_value import JsonObject, JsonValue, as_list, as_object
from reporails_cli.core.platform.dto.heal import Snapshot
from reporails_cli.core.platform.dto.heal_plan import Plan
from reporails_cli.core.platform.dto.ruleset import RulesetMap
from reporails_cli.core.platform.runtime.merger import normalize_finding_path

logger = logging.getLogger(__name__)

_snapshots: dict[str, Snapshot] = {}
# Per briefed file, how many findings each rule had when the brief was served.
_rule_counts: dict[str, dict[str, int]] = {}
# Per briefed file, the plan (edits and slots) its brief listed.
_plans: dict[str, Plan] = {}
# Briefed files whose baseline a project `validate` released while they were settled: the next brief re-snapshots them.
_released: set[str] = set()
# Per briefed file, the text a `validate` reply last judged accepted: a release counts the file settled at it.
_accepted_text: dict[str, str] = {}


def _key(file_path: Path | str) -> str:
    return os.path.normcase(os.path.normpath(str(file_path)))


def file_rule_counts(payload: JsonObject, file: str | None = None) -> dict[str, int]:
    """How many findings each rule has in `payload`'s per-file findings: a single-file run's, or just
    those of the project-relative `file` in a project run."""
    counts: dict[str, int] = {}
    for name, entry in as_object(payload.get("files")).items():
        if file is not None and name != file:
            continue
        for finding in as_list(as_object(entry).get("findings")):
            rule = str(as_object(finding).get("rule") or "")
            counts[rule] = counts.get(rule, 0) + 1
    return counts


def introduced_count(file_path: Path, payload: JsonObject) -> int:
    """The findings `payload` (a single-file run of `file_path`) has beyond the ones the file had
    when its brief was served: for each rule, the growth in its count, a rule that fell adding
    nothing. 0 for a file with no recorded counts."""
    before = _rule_counts.get(_key(file_path), {})
    return sum(max(0, n - before.get(rule, 0)) for rule, n in file_rule_counts(payload).items())


def snapshot_file(
    file_path: Path,
    ruleset_map: RulesetMap | None,
    score: float | None,
    relation_lines: Iterable[int] = (),
    *,
    rule_counts: dict[str, int] | None = None,
    plan: Plan | None = None,
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
    _plans[_key(file_path)] = plan or Plan()
    _released.discard(_key(file_path))
    _accepted_text.pop(_key(file_path), None)


def record_accepted(file_path: Path, text: str) -> None:
    """Remember `text` as what a `validate` reply last judged accepted for `file_path`."""
    _accepted_text[_key(file_path)] = text


def kept_files(root: Path) -> list[str]:
    """The project-relative paths of the briefed files under `root` still at the text a `validate` last accepted."""
    base = Path(_key(root))
    kept: list[str] = []
    for key, text in _accepted_text.items():
        path = Path(key)
        if not path.is_relative_to(base):
            continue
        try:
            current = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if current == text:
            kept.append(path.relative_to(base).as_posix())
    return kept


def held_brief(file_path: Path, current_text: str) -> tuple[str, Plan] | None:
    """The original text and the plan an earlier brief of `file_path` stored, when the file has changed
    since — a repeated brief for it keeps that baseline instead of replacing it with the half-edited file.
    `None` when the file was never briefed, has not changed, or its baseline was released."""
    key = _key(file_path)
    snap, plan = _snapshots.get(key), _plans.get(key)
    if snap is None or plan is None or snap.text == current_text or key in _released:
        return None
    return snap.text, plan


def release_holds(root: Path) -> None:
    """Release the baseline of every briefed file under `root` that is settled: its text on disk is its
    snapshot text or the text last judged accepted. A later brief of a released file takes a new snapshot;
    a file in any other state, or one that cannot be read, keeps its baseline and plan."""
    base = Path(_key(root))
    for key, snap in _snapshots.items():
        if not Path(key).is_relative_to(base):
            continue
        try:
            text = Path(key).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if text in (snap.text, _accepted_text.get(key)):
            _released.add(key)


def get_snapshot(file_path: Path) -> Snapshot | None:
    """The stored snapshot for `file_path`, or `None` when it was never briefed (or is stale —
    superseded by a later brief for a different location covering the same file)."""
    return _snapshots.get(_key(file_path))


def has_snapshot(file_path: Path) -> bool:
    """Whether `file_path` has a stored snapshot."""
    return _key(file_path) in _snapshots


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
    snapshot: Snapshot,
    file_path: Path,
    ruleset_map: RulesetMap | None,
    new_text: str,
    *,
    score: float | None,
    scan_root: Path | None,
) -> JsonObject:
    """The `preservation` block for `file_path`: its rewritten `new_text` and `ruleset_map` judged
    against `snapshot`, with the project on disk answering which names and paths exist."""
    return judge_rewrite(
        snapshot,
        file_path,
        ruleset_map,
        new_text,
        score=score,
        scan_root=scan_root,
        siblings=sibling_texts(snapshot, scan_root),
    )


def get_plan(file_path: Path) -> Plan | None:
    """The plan the brief listed for `file_path`, or `None` when it was never briefed."""
    return _plans.get(_key(file_path))


def check_conformance(
    file_path: Path, ruleset_map: RulesetMap | None, new_text: str, scan_root: Path | None
) -> JsonObject | None:
    """The `conformance` block for `file_path`: its current `new_text` and `ruleset_map` judged
    against the plan its brief listed, `{ok, deviations}`. `None` when the file was never briefed."""
    snap = get_snapshot(file_path)
    plan = get_plan(file_path)
    if snap is None or plan is None:
        return None
    key = snap.file_path
    atoms = atoms_for_file(ruleset_map, key) if ruleset_map is not None else []
    found = check_plan(plan, {key: split_lines(snap.text)[0]}, {key: split_lines(new_text)[0]}, {key: atoms})
    deviations: list[JsonValue] = [
        {
            "file": normalize_finding_path(d.file, scan_root) if scan_root is not None else d.file,
            "line": d.line,
            "op": d.op,
            "rule": d.rule,
            "expected": d.expected,
            "found": d.found,
        }
        for d in found
    ]
    return {"ok": not deviations, "deviations": deviations}
