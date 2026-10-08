"""`ails check --heal` at the places findings name: build ops from the run, plan them, write, then check the write."""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.heal.conformance import check_plan
from reporails_cli.core.heal.file_io import imports_expand, read_lines
from reporails_cli.core.heal.plan import apply_edits, build_plan
from reporails_cli.core.heal.preservation import check_rewrite, failed_checks, take_snapshot
from reporails_cli.core.platform.dto.diagnostics import walk_findings
from reporails_cli.core.platform.dto.heal_plan import Edit, Plan, PlanOp
from reporails_cli.core.platform.dto.ruleset import Atom

logger = logging.getLogger(__name__)

_DESCRIPTIONS = {
    "code": "Wrapped code in backticks",
    "unbold": "Replaced bold with italic",
    "italic": "Wrapped the constraint in italic",
    "split": "Gave each instruction its own sentence",
    "direct": "Dropped the hedge",
    "negation-form": "Rewrote Never as Do not",
    "move": "Moved the line",
    "dedupe": "Removed the repeated line",
}


@dataclass
class KeyedResult:
    """What a keyed heal pass did: fixes written, places left to a decision, files put back."""

    fixes: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    put_back: list[dict[str, Any]] = field(default_factory=list)


def _aliases(path: str, target: Path) -> set[str]:
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    p = Path(path)
    out = {path, str(safe_resolve(p)), normalize_finding_path(path)}
    with contextlib.suppress(ValueError):
        out.add(str(p.relative_to(target)))
    return out


def mapped_path_resolver(files: Iterable[str], target: Path) -> Callable[[object], str | None]:
    """A function from any spelling of a mapped file's path (absolute, project-relative) to the mapped path."""
    table = {alias: f for f in files for alias in _aliases(f, target)}

    def resolve(name: object) -> str | None:
        if not isinstance(name, str):
            return None
        return table.get(name) or table.get(str(safe_resolve(target / name)))

    return resolve


def resolve_expect(expect: Mapping[str, Any], resolve: Callable[[object], str | None]) -> dict[str, list[object]]:
    """`expect` with the file each coordinate names spelled as the mapped path."""
    out: dict[str, list[object]] = {}
    for key, value in expect.items():
        if isinstance(value, list | tuple) and value:
            head = resolve(value[0])
            out[key] = [head if head is not None else value[0], *value[1:]]
    return out


def build_ops(
    workflow: Any,
    atoms_by_file: Mapping[str, list[Atom]],
    target: Path,
) -> tuple[list[PlanOp], set[tuple[str, int, int | None, str]]]:
    """The ops of the workflow: every finding, member and relation that carries an `op`, as the server sent it,
    and their keys (the places a decision may be asked)."""
    resolve = mapped_path_resolver(atoms_by_file, target)
    ops: list[PlanOp] = []
    for loc in getattr(workflow, "locations", ()) or ():
        for f in walk_findings(loc.findings):
            file = resolve(f.file)
            if file is not None and f.op:
                ops.append(PlanOp(f.rule, file, f.line, f.pi, f.op, resolve_expect(f.expect, resolve)))
        for r in loc.relations:
            file = resolve(r.file)
            if file is None or not r.op:
                continue
            expect = resolve_expect(r.expect, resolve)
            partner = resolve(r.partner_file)
            if "keep" not in expect and partner is not None and r.partner_line:
                expect["keep"] = [partner, r.partner_line]
            ops.append(PlanOp(r.rule, file, r.line, None, r.op, expect))
    return ops, {(o.file, o.line, o.pi, o.op) for o in ops}


def _text(lines: list[str], endings: list[str], new: list[str], where: Mapping[int, int]) -> str:
    """The new lines joined, each with the ending of the original line it came from."""
    back = {n: o for o, n in where.items()}
    default = endings[0] if endings else "\n"
    unterminated = len(endings) < len(lines)
    out = []
    for i, line in enumerate(new):
        old = back.get(i)
        end = endings[old] if old is not None and old < len(endings) else default
        if i == len(new) - 1 and unterminated and old == len(lines) - 1:
            end = ""
        out.append(line + end)
    return "".join(out)


def _group(atoms: Iterable[Atom]) -> dict[str, list[Atom]]:
    out: dict[str, list[Atom]] = {}
    for a in atoms:
        out.setdefault(a.file_path, []).append(a)
    return out


def _partners(atoms_by_file: Mapping[str, list[Atom]]) -> dict[tuple[str, int], Atom]:
    return {(f, a.line): a for f, atoms in atoms_by_file.items() for a in atoms}


def _drop_suppressed(plan: Plan, suppressed: Mapping[str, set[int]]) -> Plan:
    from reporails_cli.core.heal.plan import _touched

    kept = tuple(e for e in plan.edits if not (_touched(e) & suppressed.get(e.file, set())))
    return Plan(kept, plan.slots, plan.refused)


def _readable(path: Path) -> tuple[list[str], list[str]] | None:
    try:
        lines, endings = read_lines(path)
    except (UnicodeDecodeError, OSError):
        logger.warning("%s is not readable UTF-8 text, so heal left it unchanged.", path)
        return None
    return (lines, endings) if not imports_expand(path, "".join(lines)) else None


def keyed_heal(
    ruleset_map: Any,
    target: Path,
    workflow: Any,
    *,
    dry_run: bool,
    allowed_files: set[Path] | None,
    suppressed: Mapping[Path, set[int]] | None,
    remap: Callable[[list[Path]], Any],
) -> KeyedResult:
    """Fix each finding at its own place, list the places left to a decision, and put back a file whose result
    departs from its plan (a re-map of the touched files is read; `dry_run` writes and checks nothing)."""
    result = KeyedResult()
    raw, sup = _eligible(_group(ruleset_map.atoms), allowed_files, suppressed or {})
    eligible = {f: a for f, a in _group(ruleset_map.atoms).items() if f in raw}
    ops, workflow_keys = build_ops(workflow, eligible, target)
    ops = [o for o in ops if o.file in raw and o.line not in sup[o.file]]
    plan = _drop_suppressed(build_plan(ops, eligible, {f: r[0] for f, r in raw.items()}, _partners(eligible)), sup)
    result.decisions = [
        {"file": s.file, "line": s.line, "op": s.op, "rule": s.rule}
        for s in plan.slots
        if (s.file, s.line, s.pi, s.op) in workflow_keys
    ]
    originals = {} if dry_run else _write(plan, raw)
    result.put_back = _put_back(plan, raw, remap, originals, ruleset_map, target) if originals else []
    result.fixes = [_fix(e) for e in plan.edits if e.file not in {b["file"] for b in result.put_back}]
    return result


def _eligible(
    atoms_by_file: Mapping[str, list[Atom]], allowed_files: set[Path] | None, suppressed: Mapping[Path, set[int]]
) -> tuple[dict[str, tuple[list[str], list[str]]], dict[str, set[int]]]:
    """The mapped files heal may write, with their lines and endings, and the suppressed lines of each."""
    from reporails_cli.core.lint.suppression import finding_surface

    raw: dict[str, tuple[list[str], list[str]]] = {}
    sup: dict[str, set[int]] = {}
    for file in atoms_by_file:
        path = Path(file)
        if not path.is_file() or finding_surface(file) == "config":
            continue
        resolved = safe_resolve(path)
        if allowed_files is not None and resolved not in allowed_files:
            continue
        read = _readable(path)
        if read is not None:
            raw[file] = read
            sup[file] = suppressed.get(resolved, set())
    return raw, sup


def _write(plan: Plan, raw: Mapping[str, tuple[list[str], list[str]]]) -> dict[str, bytes]:
    """Write each file's edits; the original bytes of every file written."""
    originals: dict[str, bytes] = {}
    for file in sorted({e.file for e in plan.edits}):
        lines, endings = raw[file]
        body, where = apply_edits(lines, [e for e in plan.edits if e.file == file])
        originals[file] = Path(file).read_bytes()
        Path(file).write_bytes(_text(lines, endings, body, where).encode("utf-8"))
    return originals


def _fix(edit: Edit) -> dict[str, Any]:
    return {
        "rule_id": edit.rule,
        "file_path": edit.file,
        "line": edit.line,
        "description": _DESCRIPTIONS.get(edit.op, edit.op),
    }


def _first_line(block: Mapping[str, Any], check: str) -> int:
    """The line of the first entry a failing preservation check lists (0 when it lists none)."""
    value = block.get(check)
    entries = value if isinstance(value, list) else []
    return int(entries[0].get("line", 0)) if entries and isinstance(entries[0], dict) else 0


def _rewrite_failure(file: str, original: bytes, ruleset_map: Any, fresh: Any, target: Path) -> dict[str, Any] | None:
    """The put-back entry for `file` when the preservation check fails its written text against its original."""
    text = original.decode("utf-8", errors="replace")
    snapshot = take_snapshot(file, text, ruleset_map, None)
    written = Path(file).read_text(encoding="utf-8", errors="replace")
    block = check_rewrite(snapshot, Path(file), fresh, written, None, target)
    failed = failed_checks(block)
    if not failed:
        return None
    return {
        "file": file,
        "op": "",
        "rule": "",
        "line": _first_line(block, failed[0]),
        "check": f"preservation:{failed[0]}",
    }


def _put_back(
    plan: Plan,
    raw: Mapping[str, tuple[list[str], list[str]]],
    remap: Callable[[list[Path]], Any],
    originals: Mapping[str, bytes],
    ruleset_map: Any,
    target: Path,
) -> list[dict[str, Any]]:
    """Re-map the written files, check each against its plan and with the rewrite check an agent's rewrite
    passes, and restore the original bytes of any that fail either; the entry names the check."""
    touched = sorted(originals)
    fresh_map = remap([Path(f) for f in touched])
    fresh = _group(fresh_map.atoms)
    out: list[dict[str, Any]] = []
    for file in touched:
        one = Plan(tuple(e for e in plan.edits if e.file == file), tuple(s for s in plan.slots if s.file == file))
        written, _ = read_lines(Path(file))
        found = check_plan(one, {file: raw[file][0]}, {file: written}, {file: fresh.get(file, ())})
        failure = (
            {"file": file, "op": found[0].op, "rule": found[0].rule, "line": found[0].line, "check": "conformance"}
            if found
            else _rewrite_failure(file, originals[file], ruleset_map, fresh_map, target)
        )
        if failure is not None:
            Path(file).write_bytes(originals[file])
            out.append(failure)
    return out
