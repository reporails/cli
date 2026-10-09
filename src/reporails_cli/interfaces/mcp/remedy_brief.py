"""The `remedy_brief` MCP tool: the rewrite brief for one workflow location, as its plan.

`build_remedy_brief` turns the location's findings and relations into ops, builds the heal plan
from them (`core.heal.plan.build_plan`) and hands the exact edits, the few slots that need a
decision, each slot rule's own guide and one instruction per op to
`formatters.mcp.remedy_brief_payload`. For each of the location's files it runs the single-file
pipeline — the same internal path `validate(path=<file>)` runs — via `tools.run_pipeline_for_path`.
Only once every file of the location has built successfully does it snapshot them, with each
file's plan, all at once, for the later `validate(path=<file>)` preservation and conformance
checks — a location whose brief is never delivered (`brief_unavailable`) must never overwrite an
earlier file's existing snapshot.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from reporails_cli.core.heal.file_io import imports_expand
from reporails_cli.core.heal.keyed import mapped_path_resolver, resolve_expect
from reporails_cli.core.heal.op_guide import change_lines, op_lines
from reporails_cli.core.heal.plan import PartnerKey, apply_edits, build_plan
from reporails_cli.core.platform.adapters.workflow_wire import _opt_int
from reporails_cli.core.platform.dto.diagnostics import subtree_tier_rank, walk_findings
from reporails_cli.core.platform.dto.heal_plan import Edit, Plan, PlanOp, Refusal
from reporails_cli.core.platform.dto.ruleset import Atom
from reporails_cli.interfaces.mcp import snapshots

# The ideal-instruction rule ids, in the fixed order `remedy_brief` presents them.
IDEAL_INSTRUCTION_RULE_IDS = (
    "CORE:C:0053",
    "CORE:E:0004",
    "CORE:E:0003",
    "CORE:E:0006",
    "CORE:C:0042",
    "CORE:C:0043",
    "CORE:D:0003",
    "CORE:D:0002",
    "CORE:C:0047",
    "CORE:S:0039",
    "CORE:C:0058",
)


def resolve_from_root(rel: str, scan_root: Path) -> Path:
    """Resolve a `validate`-payload path (project-relative, or `~/…`) back to an absolute
    path against `scan_root` — the mirror of `normalize_finding_path`."""
    if rel.startswith("~/"):
        return (Path.home() / rel[2:]).resolve()
    p = Path(rel)
    return p if p.is_absolute() else (scan_root / p).resolve()


def _ideal_instruction_entry(rule_id: str, guides: dict[str, Any], by_id: dict[str, Any]) -> dict[str, Any]:
    """One `ideal_instruction[]` entry: title/pass/antipatterns from its guide, statement from
    the rule description body before its first `##` sub-heading."""
    from reporails_cli.core.lint.rule_pages import load_rule_description

    guide = guides.get(rule_id, {})
    rule = by_id.get(rule_id)
    description = load_rule_description(rule) if rule is not None else None
    statement = (description or "").split("\n## ", 1)[0].strip()
    return {
        "id": rule_id,
        "title": guide.get("title", rule.title if rule is not None else ""),
        "statement": statement,
        "pass": guide.get("pass", ""),
        "antipatterns": guide.get("antipatterns", ""),
    }


def ideal_instruction_guide() -> list[dict[str, Any]]:
    """The ideal-instruction rules, in their fixed order: id, title, statement (the rule
    description body before its first `##` sub-heading, trimmed), pass example, antipatterns."""
    from reporails_cli.core.lint.rule_pages import load_rule_guides
    from reporails_cli.core.platform.adapters.rules_query import load_all_rules

    guides = load_rule_guides(list(IDEAL_INSTRUCTION_RULE_IDS))
    by_id = {r.id: r for r in load_all_rules()}
    return [_ideal_instruction_entry(rule_id, guides, by_id) for rule_id in IDEAL_INSTRUCTION_RULE_IDS]


def _without_title_line(statement: str) -> str:
    """`statement` without the `# Title` line a rule description opens with — the rendered guide
    already heads each rule with its title."""
    first, _, rest = statement.partition("\n")
    return rest.strip() if first.startswith("# ") else statement


def ideal_instruction_markdown() -> str:
    """The ideal-instruction guide (`ideal_instruction_guide`) as Markdown, the same content
    for a remedy agent definition to carry: per rule, in `IDEAL_INSTRUCTION_RULE_IDS` order, a
    `### <Title> (<ID>)` heading, the statement, then the pass example and the antipatterns.
    The same rules always give the same text."""
    sections = []
    for entry in ideal_instruction_guide():
        parts = [
            f"### {entry['title']} ({entry['id']})",
            _without_title_line(entry["statement"]),
            f"**Pass example**\n\n{entry['pass']}",
            f"**Antipatterns**\n\n{entry['antipatterns']}",
        ]
        sections.append("\n\n".join(p for p in parts if p.strip()))
    return "\n\n".join(sections) + "\n"


def _finding_sort_key(f: dict[str, Any]) -> tuple[int, str, int]:
    return (subtree_tier_rank(f), str(f.get("file") or ""), int(f.get("line") or 0))


def _sorted_findings(findings: list[Any]) -> list[Any]:
    """`findings`, weakest-first by the heaviest `impact_tier` in each finding and its members
    (gate_mover -> conditional -> cosmetic -> ""), then by file then line — a stable order, used
    for the `feedback` list."""
    return sorted(findings, key=_finding_sort_key)


def _relation_lines(rel: str, relations: list[Any]) -> list[Any]:
    """The lines of this file that a relation names as true duplicates: the only lines its
    preservation checks treat as deletable."""
    return [r.get("line") for r in relations if r.get("file") == rel]


# The generic cause when a pipeline run yields no map and no more specific reason is on the
# payload — a single named constant, so the caller that wraps it in a sentence never repeats it.
_NO_MAP_FALLBACK = "its pipeline run produced no map"


def _pipeline_failure_reason(payload: dict[str, Any]) -> str:
    """The best available cause string from a pipeline `payload` that yielded no map:
    the mapper's own swallowed exception text (`mapper_error` — see
    `interfaces/mcp/tools.py::_build_map`) when there is one, else the payload's own
    `message` / `error` field (discovery's `needs_install` / unknown-agent / path-not-found
    payloads), else `_NO_MAP_FALLBACK` naming nothing more specific."""
    reason = payload.get("mapper_error") or payload.get("message") or payload.get("error")
    return str(reason) if reason else _NO_MAP_FALLBACK


def _brief_unavailable_message(rel: str, reason: str) -> str:
    """The `brief_unavailable` message for `rel`, naming `reason` exactly once — `reason` already
    reads as a full cause. Wrapping it inside a second "produced no map" clause, when `reason`
    already IS `_NO_MAP_FALLBACK`, printed that same sentence twice; this keeps the specific-cause
    sentence (`"... — its pipeline run produced no map: <cause>"`) for a real cause and drops the
    redundant clause when there is none more specific than the fallback itself."""
    if reason == _NO_MAP_FALLBACK:
        return f"Could not build the rewrite brief for {rel} — {reason}."
    return f"Could not build the rewrite brief for {rel} — its pipeline run produced no map: {reason}"


@dataclass(frozen=True)
class _BuiltFile:
    """One briefed file: where it is, its map, and what the snapshot needs."""

    rel: str
    abs_file: Path
    ruleset_map: Any
    score: float | None
    rule_counts: dict[str, int]
    lines: list[str]
    text: str


def _build_file(rel: str, scan_root: Path) -> _BuiltFile | str:
    """The built file for `rel`, or the reason its pipeline run produced no map — the underlying
    cause, never a bare sentinel."""
    from reporails_cli.interfaces.mcp.tools import run_pipeline_for_path

    abs_file = resolve_from_root(rel, scan_root)
    payload, ruleset_map, score = run_pipeline_for_path(str(abs_file), True)
    if ruleset_map is None:
        return _pipeline_failure_reason(payload)
    try:
        text = abs_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""  # no lines to plan on; the snapshot step reports the unreadable file
    return _BuiltFile(
        rel, abs_file, ruleset_map, score, snapshots.file_rule_counts(payload), text.splitlines(keepends=True), text
    )


def _build_files(location: dict[str, Any], scan_root: Path) -> list[_BuiltFile] | dict[str, Any]:
    """Every real file of the location built — or the structured `brief_unavailable` error naming
    the file, when any of them yields no map. A `files[]` entry that names a directory — a folder
    that only groups skills and has no `SKILL.md` of its own — has no pipeline of its own to run:
    it is skipped, so the location's real files still brief. When EVERY file is such a directory,
    the error names that cause once. Snapshotting stays the caller's job: this builds every real
    file first, so a reply that is never delivered never commits a partial set of snapshots."""
    built: list[_BuiltFile] = []
    directories: list[str] = []
    for rel in location.get("files") or []:
        if resolve_from_root(rel, scan_root).is_dir():
            directories.append(rel)
            continue
        result = _build_file(rel, scan_root)
        if isinstance(result, str):
            return {"error": "brief_unavailable", "message": _brief_unavailable_message(rel, result)}
        built.append(result)
    if not built and directories:
        element = location.get("element") or directories[0]
        return {
            "error": "brief_unavailable",
            "message": (
                f"Could not build the rewrite brief for {element} — every one of its files is a "
                "directory with no SKILL.md of its own."
            ),
        }
    return built


def _location_ops(location: dict[str, Any], scan_root: Path, files: list[str]) -> tuple[list[PlanOp], dict[str, str]]:
    """One `PlanOp` per finding (owners and members alike, `together` skipped) and per relation of
    the location that names an op, with the file as an absolute path; and each op file's
    project-relative display name. A repeat of one rule, place and op is one op."""
    ops: dict[tuple[Any, ...], PlanOp] = {}
    names: dict[str, str] = {}
    resolve = mapped_path_resolver(files, scan_root)
    rows = [*walk_findings(location.get("findings") or ()), *(location.get("relations") or ())]
    for row in rows:
        op = str(row.get("op") or "")
        rel = str(row.get("file") or "")
        if not op or op == "together" or not rel:
            continue
        abs_name = str(resolve_from_root(rel, scan_root))
        names[abs_name] = rel
        raw = row.get("expect")
        expect = resolve_expect(raw, resolve) if isinstance(raw, dict) else {}
        plan_op = PlanOp(
            str(row.get("rule") or ""), abs_name, int(row.get("line") or 0), _opt_int(row.get("pi")), op, expect
        )
        ops.setdefault((plan_op.rule, plan_op.file, plan_op.line, plan_op.pi, plan_op.op), plan_op)
    return list(ops.values()), names


def _partner_atoms(ops: list[PlanOp], scan_root: Path, maps: list[Any]) -> dict[PartnerKey, Atom]:
    """The atom each dedupe or keep-cut op's `expect["keep"]` names, looked up in `maps` (the
    project map first)."""
    from reporails_cli.core.heal.transforms import atoms_at
    from reporails_cli.core.lint.content_queries import atoms_for_file

    out: dict[PartnerKey, Atom] = {}
    for op in ops:
        keep = op.expect.get("keep") or []
        if len(keep) != 2:
            continue
        try:
            file, line = str(keep[0]), int(str(keep[1]))
        except ValueError:
            continue
        abs_name = str(resolve_from_root(file, scan_root))
        for ruleset_map in maps:
            found = atoms_at(atoms_for_file(ruleset_map, abs_name), line, None)
            if found:
                out[(file, line)] = found[0]
                break
    return out


def _block(edits: list[Edit], lines: list[str]) -> tuple[int, int, str, str]:
    """`(line_start, line_end, before, after)` for edits that share one contiguous block of `lines`."""
    first = min(min(e.line, e.move_after or e.line) for e in edits)
    last = max(max(e.line + e.span - 1, e.move_after or 0) for e in edits)
    sub = [line.rstrip("\r\n") for line in lines[first - 1 : last]]
    shifted = [
        Edit(
            e.file,
            e.line - first + 1,
            e.before,
            e.after,
            e.op,
            e.rule,
            None if e.move_after is None else e.move_after - first + 1,
        )
        for e in edits
    ]
    after, _ = apply_edits(sub, shifted)
    before_text = "\n".join(sub)
    if not after:
        # A block deleted whole takes its line break with it, or a literal replace leaves an empty line.
        raw = lines[last - 1]
        before_text += raw[len(raw.rstrip("\r\n")) :]
    return first, last, before_text, "\n".join(after)


def _widened(
    start: int, end: int, before: str, after: str, lines: list[str], blocked: list[tuple[int, int]]
) -> tuple[int, int, str, str]:
    """The block with neighbouring lines added, before and after alike, until `before` occurs once in the
    file (so a literal replace hits it alone). It never reaches into another block of the same file, whose
    own edit changes those lines."""
    body = [line.rstrip("\r\n") for line in lines]
    text = "\n".join(body) + "\n"

    def free(n: int) -> bool:
        return 1 <= n <= len(body) and not any(lo <= n <= hi for lo, hi in blocked)

    while text.count(before) > 1:
        if free(start - 1):
            start -= 1
            before, after = f"{body[start - 1]}\n{before}", f"{body[start - 1]}\n{after}"
        elif free(end + 1):
            end += 1
            glue = "" if before.endswith("\n") else "\n"
            before, after = f"{before}{glue}{body[end - 1]}", f"{after}{glue if after else ''}{body[end - 1]}"
        else:
            break
    return start, end, before, after


def _edit_entries(plan: Plan, lines_by_file: dict[str, list[str]], names: dict[str, str]) -> list[dict[str, Any]]:
    """The plan's edits as single contiguous block replacements, bottom to top within each file. Edits
    whose blocks meet or overlap (a move spans the lines between its two places) share one block. Each
    block's `before` is unique in its file."""
    out: list[dict[str, Any]] = []
    for file in sorted({e.file for e in plan.edits}):
        out.extend(_file_edit_entries(file, _edit_groups(plan, file), lines_by_file[file], names))
    return out


def _edit_groups(plan: Plan, file: str) -> list[tuple[int, int, list[Edit]]]:
    """One file's edits as line spans, merging those whose spans meet or overlap."""
    spans = sorted(
        (
            (min(e.line, e.move_after or e.line), max(e.line + e.span - 1, e.move_after or 0), e)
            for e in plan.edits
            if e.file == file
        ),
        key=lambda t: t[0],
    )
    groups: list[tuple[int, int, list[Edit]]] = []
    for start, end, edit in spans:
        if groups and start <= groups[-1][1]:
            groups[-1] = (groups[-1][0], max(groups[-1][1], end), [*groups[-1][2], edit])
        else:
            groups.append((start, end, [edit]))
    return groups


def _file_edit_entries(
    file: str, groups: list[tuple[int, int, list[Edit]]], lines: list[str], names: dict[str, str]
) -> list[dict[str, Any]]:
    """One file's block replacements, bottom to top, each widened until its `before` is unique."""
    out: list[dict[str, Any]] = []
    for index, (_lo, _hi, group) in reversed(list(enumerate(groups))):
        start, end, before, after = _block(group, lines)
        others = [(a, b) for i, (a, b, _) in enumerate(groups) if i != index]
        start, end, before, after = _widened(start, end, before, after, lines, others)
        lead = group[0]
        out.append(
            {
                "file": names.get(file, file),
                "path": file,
                "line_start": start,
                "line_end": end,
                "op": lead.op,
                "rule": lead.rule,
                "before": before,
                "after": after,
            }
        )
    return out


def _coordinate(value: Any, scan_root: Path) -> list[Any] | None:
    """An `expect` `[file, line]` pair with the file as an absolute path; None when it is not one."""
    if not isinstance(value, list) or len(value) < 2 or not isinstance(value[0], str):
        return None
    return [str(resolve_from_root(value[0], scan_root)), value[1]]


def _slot_entries(
    plan: Plan, names: dict[str, str], ops: list[PlanOp], scan_root: Path, lines_by_file: dict[str, list[str]]
) -> list[dict[str, Any]]:
    """The plan's slots. A slot whose op names a target (`expect["to"]`) or a partner
    (`expect["also"]`) carries them as `to` (absolute path) and `also` (`[absolute path, line]`). A slot's
    `line` is its line once the plan's edits are applied: the brief's edits come first, then the slots."""
    moved = {
        file: apply_edits(lines_by_file[file], [e for e in plan.edits if e.file == file])[1]
        for file in {e.file for e in plan.edits}
    }
    expects = {(o.rule, o.file, o.line, o.pi, o.op): o.expect for o in ops}
    out: list[dict[str, Any]] = [
        {
            "file": names.get(s.file, s.file),
            "path": s.file,
            "line": moved.get(s.file, {}).get(s.line - 1, s.line - 1) + 1,
            "pi": s.pi,
            "op": s.op,
            "rule": s.rule,
            "text": s.text,
            "bound": s.bound,
        }
        for s in plan.slots
    ]
    for entry, slot in zip(out, plan.slots, strict=True):
        expect = expects.get((slot.rule, slot.file, slot.line, slot.pi, slot.op), {})
        to, also = _coordinate(expect.get("to"), scan_root), _coordinate(expect.get("also"), scan_root)
        if slot.change:
            entry["change"] = slot.change
        if to:
            entry["to"] = to[0]
        if also:
            entry["also"] = also
    return out


def _refused_entries(plan: Plan, names: dict[str, str]) -> list[dict[str, Any]]:
    return [
        {
            "file": names.get(r.op.file, r.op.file),
            "line": r.op.line,
            "op": r.op.op,
            "rule": r.op.rule,
            "reason": r.reason,
        }
        for r in plan.refused
    ]


def _guides(rule_ids: set[str]) -> dict[str, dict[str, str]]:
    """Each rule's title and its own Pass and Fail examples."""
    from reporails_cli.core.lint.rule_pages import load_rule_examples, rule_title
    from reporails_cli.core.platform.adapters.rules_query import find_rule_by_id

    out: dict[str, dict[str, str]] = {}
    for rule_id in sorted(rule_ids):
        rule = find_rule_by_id(rule_id)
        examples = load_rule_examples(rule) if rule is not None else {}
        out[rule_id] = {
            "title": rule_title(rule_id),
            "pass": examples.get("pass") or "",
            "fail": examples.get("fail") or "",
        }
    return out


def build_remedy_brief(location: dict[str, Any], scan_root: Path, project_map: Any = None) -> dict[str, Any]:
    """Build the `remedy_brief` reply for one already-resolved workflow `location` (a location dict
    from the stored full `validate` payload, so its findings and relations are already
    relative-pathed): the plan's exact edits, the slots that need a decision with each slot rule's
    guide and one line per op, the refused ops, and the preservation contract. `project_map` is
    the project's ruleset map, where a dedupe or keep-cut op finds its partner line. A structured
    `brief_unavailable` error, naming the file, when any of the location's files yields no map.

    Runs the location's own file pipeline, and commits the preservation snapshots with each
    file's plan, exactly once.

    The reply's `location` carries `root`: the absolute project root the location's relative
    `file` names resolve against; every edit and slot carries its file's absolute `path` beside the
    relative `file`. A rewrite or a `validate(path=<file>)` check must use `path`, never `file`."""
    from reporails_cli.core.heal.preservation import PRESERVATION_CONTRACT
    from reporails_cli.core.lint.content_queries import atoms_for_file
    from reporails_cli.formatters.mcp import remedy_brief_payload

    built = _build_files(location, scan_root)
    if isinstance(built, dict):
        return built
    ops, names = _location_ops(location, scan_root, [str(f.abs_file) for f in built])
    # A file whose `@imports` expand has atom lines that count the imported lines: no exact edit
    # can be placed on it, so its ops are refused. A file already briefed and edited since keeps
    # its stored baseline and plan, shown against the text they were made from.
    expanding = {str(f.abs_file) for f in built if imports_expand(f.abs_file, f.text)}
    held = {str(f.abs_file): h for f in built if (h := snapshots.held_brief(f.abs_file, f.text)) is not None}
    skipped = expanding | set(held)
    atoms_by_file = {str(f.abs_file): atoms_for_file(f.ruleset_map, str(f.abs_file)) for f in built}
    lines_by_file = {str(f.abs_file): f.lines for f in built}
    lines_by_file.update({name: text.splitlines(keepends=True) for name, (text, _) in held.items()})
    maps = [m for m in (project_map, *(f.ruleset_map for f in built)) if m is not None]
    planned = build_plan(
        [o for o in ops if o.file not in skipped], atoms_by_file, lines_by_file, _partner_atoms(ops, scan_root, maps)
    )
    stored = [plan for _, plan in held.values()]
    plan = Plan(
        tuple(sorted((*planned.edits, *(e for p in stored for e in p.edits)), key=lambda e: (e.file, e.line))),
        tuple(
            sorted((*planned.slots, *(s for p in stored for s in p.slots)), key=lambda s: (s.file, s.line, s.pi or 0))
        ),
        (
            *planned.refused,
            *(Refusal(o, "imports_expand") for o in ops if o.file in expanding),
        ),
    )
    names.update({str(f.abs_file): f.rel for f in built})

    # Every file built: commit the snapshots together, so a brief that IS delivered is the
    # only thing that ever replaces an earlier baseline.
    relations = location.get("relations") or []
    for f in built:
        own = Plan(
            tuple(e for e in plan.edits if e.file == str(f.abs_file)),
            tuple(s for s in plan.slots if s.file == str(f.abs_file)),
        )
        if str(f.abs_file) in held:
            continue
        snapshots.snapshot_file(
            f.abs_file, f.ruleset_map, f.score, _relation_lines(f.rel, relations), f.rule_counts, own
        )

    slots = _slot_entries(plan, names, ops, scan_root, lines_by_file)
    location_out = {
        **{k: location[k] for k in ("order", "element", "kind", "loading", "importance", "files") if k in location},
        "root": str(scan_root),
    }
    return remedy_brief_payload(
        location=location_out,
        edits=_edit_entries(plan, lines_by_file, names),
        slots=slots,
        guides=_guides({s["rule"] for s in slots}),
        ops={**op_lines({s["op"] for s in slots}), **change_lines({s["change"] for s in slots if "change" in s})},
        refused=_refused_entries(plan, names),
        preservation_contract=PRESERVATION_CONTRACT,
    )
