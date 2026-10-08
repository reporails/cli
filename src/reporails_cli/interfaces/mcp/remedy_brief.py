"""The `remedy_brief` MCP tool: the full rewrite brief for one workflow location.

`build_remedy_brief` builds the whole, unpaged brief once (per-file instruction inventory,
artifact rules, findings/relations) and hands it to
`formatters.mcp.remedy_brief_payload` for assembly. For each of the location's files it runs
the single-file pipeline — the same internal path `validate(path=<file>)` runs — via
`tools.run_pipeline_for_path`. Only once every file of the location has built successfully
does it snapshot them, all at once, for the later `validate(path=<file>)` preservation check —
a location whose brief is never delivered (`brief_unavailable`) must never overwrite an
earlier file's existing snapshot. Paging that one build across a client's output cap
(`remedy_brief_paging.page_reply`) is a separate step a caller repeats as many times as it
likes — never a reason to build again; `remedy_brief_tool` builds and pages one part in a
single call for a caller with nowhere to keep the build between calls, while
`server._serve_remedy_brief` builds once and keeps it for every later part of the same
location.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from reporails_cli.core.platform.dto.diagnostics import subtree_tier_rank, walk_findings
from reporails_cli.interfaces.mcp import snapshots
from reporails_cli.interfaces.mcp.remedy_brief_paging import page_reply

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


def _matches_capability(rule: Any, targets: set[str]) -> bool:
    """Whether `rule.match.type` names one of `targets` — a universal rule (no `match.type`)
    never matches, so it is never an artifact rule."""
    if rule.match is None or rule.match.type is None:
        return False
    rule_types = rule.match.type if isinstance(rule.match.type, list) else [rule.match.type]
    return any(t in targets for t in rule_types)


def _artifact_rule_entry(rule: Any) -> dict[str, Any]:
    from reporails_cli.core.lint.rule_pages import load_rule_examples

    examples = load_rule_examples(rule)
    return {
        "id": rule.id,
        "title": rule.title,
        "pass_example": examples.get("pass") or "",
        "fail_example": examples.get("fail") or "",
    }


def artifact_rules_for_kind(kind: str, agents: list[str] | None = None) -> dict[str, Any] | None:
    """The `artifact_rules` block for a location's `kind` (its files' config type): only rules
    whose `match.type` names that type — universal rules (no `match.type`) are never artifact
    rules — in authoring order, filtered to CORE plus `agents`' own namespaces (the location's
    files' `FileRecord.agent`, the same agent resolution `validate` uses for the project), so
    the rewrite agent never sees another agent's pass/fail examples. `agents=None` (or empty)
    loads every known agent's namespace, for a caller that has none to name. `None` when no
    rule names the type, so the caller omits the block."""
    from reporails_cli.core.platform.adapters.rules_query import (
        capability_file_types,
        load_all_rules,
        sort_rules_for_authoring,
    )

    targets = capability_file_types(kind)
    matched = [r for r in load_all_rules(agents=agents or None) if _matches_capability(r, targets)]
    if not matched:
        return None
    entries = [_artifact_rule_entry(r) for r in sort_rules_for_authoring(matched)]
    return {"capability": kind, "rules": entries}


def _file_loading(ruleset_map: Any, abs_file: Path, fallback: str) -> str:
    """The file's own `FileRecord.loading`, falling back to `fallback` (the location's) when
    the map holds no record for it."""
    from reporails_cli.core.lint.content_queries import _norm_key

    key = _norm_key(str(abs_file))
    record = next((fr for fr in ruleset_map.files if _norm_key(fr.path) == key), None)
    return record.loading if record is not None else fallback


def _file_agent(ruleset_map: Any, abs_file: Path) -> str:
    """The file's own `FileRecord.agent`, or `""` when the map holds no record for it."""
    from reporails_cli.core.lint.content_queries import _norm_key

    key = _norm_key(str(abs_file))
    record = next((fr for fr in ruleset_map.files if _norm_key(fr.path) == key), None)
    return record.agent if record is not None else ""


def _finding_sort_key(f: dict[str, Any]) -> tuple[int, str, int]:
    return (subtree_tier_rank(f), str(f.get("file") or ""), int(f.get("line") or 0))


def _sorted_findings(findings: list[Any]) -> list[Any]:
    """`findings`, weakest-first by the heaviest `impact_tier` in each finding and its members
    (gate_mover → conditional → cosmetic → ""), then by file then line — a stable order so the
    same findings always brief in the same sequence."""
    return sorted(findings, key=_finding_sort_key)


def _targeted_instructions(instructions: list[dict[str, Any]], rel: str, findings: list[Any]) -> list[dict[str, Any]]:
    """`instructions` (already in file order), each carrying `targets`: the rule ids of every
    finding of `rel` that addresses its own line — so the agent can see, instruction by
    instruction, which ones a finding actually targets and how weak (`_finding_sort_key`
    order) each target is. An instruction no finding targets is left unchanged (no `targets`
    key)."""
    by_line: dict[int, list[str]] = {}
    for f in walk_findings(findings):
        if f.get("file") == rel and f.get("line") is not None:
            by_line.setdefault(int(f["line"]), []).append(str(f.get("rule") or ""))
    return [{**e, "targets": by_line[e["line"]]} if e["line"] in by_line else e for e in instructions]


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


def _headings_with_polarity(headings: list[dict[str, Any]], ruleset_map: Any, abs_file: Path) -> list[dict[str, Any]]:
    """`headings` with a `polarity` on each one that is an instruction itself (`## Never Push
    Directly to Main`), so the rewrite sees what the heading holds. A plain topic heading and a
    bare negative heading (`## Don'ts`) gain none."""
    from reporails_cli.core.heal.preservation import is_instruction_heading
    from reporails_cli.core.lint.content_queries import atoms_for_file

    charged = {
        (a.line, a.text): a.charge_value
        for a in atoms_for_file(ruleset_map, str(abs_file))
        if a.kind == "heading" and is_instruction_heading(a)
    }
    return [
        {**h, "polarity": charged[(h["line"], h["text"])]} if (h["line"], h["text"]) in charged else h for h in headings
    ]


def _brief_file_entry(
    rel: str, location: dict[str, Any], scan_root: Path, relations: list[Any], findings: list[Any]
) -> tuple[dict[str, Any], str, _PendingSnapshot] | str:
    """`(files[] entry, the file's agent, snapshot args)` for `rel`: score, instruction/heading
    inventory, its own `loading` (falling back to the location's). Does NOT snapshot the file —
    the caller commits every file's snapshot together, only once every file of the location has
    built successfully (all-or-nothing: a brief never delivered must not overwrite an earlier
    snapshot). A failure reason string when the file's pipeline run produced no map (a
    pipeline error or an offline server must not silently ship an empty-inventory entry) — the
    underlying cause (`_pipeline_failure_reason`), never a bare sentinel, so the caller's
    `brief_unavailable` can name it."""
    from reporails_cli.core.lint.content_queries import instruction_inventory
    from reporails_cli.interfaces.mcp.tools import run_pipeline_for_path

    abs_file = resolve_from_root(rel, scan_root)
    payload, ruleset_map, score = run_pipeline_for_path(str(abs_file), True)
    if ruleset_map is None:
        return _pipeline_failure_reason(payload)

    entries = instruction_inventory(ruleset_map, str(abs_file))
    relation_lines = _relation_lines(rel, relations)
    instructions = _targeted_instructions([e for e in entries if "depth" not in e], rel, findings)
    entry = {
        "file": rel,
        "path": str(abs_file),
        "loading": _file_loading(ruleset_map, abs_file, location.get("loading", "")),
        "score": score,
        "instructions": instructions,
        "headings": _headings_with_polarity([e for e in entries if "depth" in e], ruleset_map, abs_file),
    }
    return (
        entry,
        _file_agent(ruleset_map, abs_file),
        (
            abs_file,
            ruleset_map,
            score,
            relation_lines,
            snapshots.file_rule_counts(payload),
        ),
    )


_PendingSnapshot = tuple[Path, Any, "float | None", list[Any], dict[str, int]]


def _build_files(
    location: dict[str, Any], scan_root: Path, relations: list[Any], findings: list[Any]
) -> tuple[list[dict[str, Any]], set[str], list[_PendingSnapshot]] | dict[str, Any]:
    """Every real file's brief entry, its agent, and its (not-yet-committed) snapshot args — or
    the structured `brief_unavailable` error naming the file, when any of the location's real
    files yields no map. A `files[]` entry that names a directory — a folder that only
    groups skills and has no `SKILL.md` of its own — has no pipeline of its own to run: it
    is skipped here rather than run through the single-file pipeline (which only ever reports
    "nothing here" for a bare directory), so the location's real files still brief. The
    directory's own cause, if any, already lives in the location's `findings`, untouched. When
    EVERY one of the location's files turns out to be such a directory, the reply names that
    cause once, instead of shipping an empty `files[]` that reads as "there is genuinely
    nothing here". Snapshotting stays the caller's job: this builds every real file first, so a
    reply that is never delivered never commits a partial set of snapshots."""
    files_out: list[dict[str, Any]] = []
    agents: set[str] = set()
    pending_snapshots: list[_PendingSnapshot] = []
    directories: list[str] = []
    for rel in location.get("files") or []:
        if resolve_from_root(rel, scan_root).is_dir():
            directories.append(rel)
            continue
        result = _brief_file_entry(rel, location, scan_root, relations, findings)
        if isinstance(result, str):
            return {"error": "brief_unavailable", "message": _brief_unavailable_message(rel, result)}
        entry, agent, snapshot_args = result
        files_out.append(entry)
        pending_snapshots.append(snapshot_args)
        if agent:
            agents.add(agent)
    if not files_out and directories:
        element = location.get("element") or directories[0]
        return {
            "error": "brief_unavailable",
            "message": (
                f"Could not build the rewrite brief for {element} — every one of its files is a "
                "directory with no SKILL.md of its own."
            ),
        }
    return files_out, agents, pending_snapshots


def _commit_snapshots(pending: list[_PendingSnapshot]) -> None:
    """Snapshot every file together — called only once every file of the location has built
    successfully, so a brief that is never delivered never overwrites an earlier snapshot."""
    for abs_file, ruleset_map, score, relation_lines, rule_counts in pending:
        snapshots.snapshot_file(abs_file, ruleset_map, score, relation_lines, rule_counts)


# A character that, written right before or right after a code span, makes the span cover only
# part of a name (`tests/unit/`x.py``).
_NAME_CHAR_BEFORE = re.compile(r"[\w/.\\-]")
_NAME_CHAR_AFTER = re.compile(r"[\w/\\-]")
_ASTERISK_RUN = re.compile(r"\*+")


def _has_partial_code_span(text: str) -> bool:
    """True when a code span in `text` is glued to a word or path character on either side, so it
    covers only part of a name."""
    from reporails_cli.core.mapper.md_parser import code_spans

    return any(
        (start > 0 and _NAME_CHAR_BEFORE.match(text[start - 1]))
        or (end < len(text) and _NAME_CHAR_AFTER.match(text[end]))
        for start, end, _content in code_spans(text)
    )


def _max_asterisk_run(text: str) -> int:
    """The longest run of consecutive `*` in `text`, outside code spans — `0` when there is none."""
    from reporails_cli.core.mapper.md_parser import replace_code_spans

    outside = replace_code_spans(text, "")
    return max((len(run) for run in _ASTERISK_RUN.findall(outside)), default=0)


def _well_formed(before: str, after: str) -> bool:
    """A fix whose result reads as intended: no new code span covering only part of a name, no
    bold left inside a line it wraps in italics, and no run of 3 or more `*` longer than the
    longest run `before` already had — the italic fixer re-wrapping a line already wrapped
    once, or a bold-to-italic fix landing on an already-bolded line, stacks another layer of
    `*` onto the last one instead of replacing it; a legitimate italic wrap or bold-to-italic
    fix never needs a run that long."""
    from reporails_cli.core.mapper.md_parser import emphasis_runs

    if _has_partial_code_span(after) and not _has_partial_code_span(before):
        return False
    runs = emphasis_runs(after)
    wrapped_in_italics = any(not run.strong and run.end == len(after.rstrip()) for run in runs)
    if wrapped_in_italics and any(run.strong for run in runs):
        return False
    after_run = _max_asterisk_run(after)
    return not (after_run >= 3 and after_run > _max_asterisk_run(before))


def _drop_chained_after_withheld(fixes: list[Any]) -> list[Any]:
    """Fixes in the order they were built, keeping only those whose line never had an
    earlier withheld fix. `apply_mechanical_fixes(dry_run=True)` runs its fixers in sequence
    on the same in-memory lines, so a later fix on a line has the earlier fix's output as its
    `before`. Once a fix on a line is withheld (`_well_formed` says no), that line's text
    never actually changes, so every later fix chained onto the same line is built on text
    the file never has and is withheld too."""
    withheld_lines: set[int] = set()
    kept: list[Any] = []
    for fix in fixes:
        if fix.line in withheld_lines:
            continue
        if not _well_formed(fix.before, fix.after):
            withheld_lines.add(fix.line)
            continue
        kept.append(fix)
    return kept


def mechanical_fixes_for(pending: list[_PendingSnapshot], scan_root: Path) -> list[dict[str, Any]]:
    """The deterministic line fixes for the location's files — backticks around a bare code
    name, italics for a bolded prohibition — each `{file, path, line, fix, before, after}`,
    computed without writing anything. Only the location's own files are fixed, a line the
    author annotated with an `ails-disable-line` directive gets none, a fix whose result would
    not read as intended (`_well_formed`) is left to the rewrite, and so is every later fix
    chained onto the same line (`_drop_chained_after_withheld`)."""
    from reporails_cli.core.heal.mechanical_fixers import apply_mechanical_fixes
    from reporails_cli.core.lint.suppression import suppressed_lines
    from reporails_cli.core.platform.runtime.merger import normalize_finding_path

    out: list[dict[str, Any]] = []
    for abs_file, ruleset_map, *_rest in pending:
        if ruleset_map is None:
            continue
        suppressed = {Path(k).resolve(): v for k, v in suppressed_lines([str(abs_file)], scan_root).items()}
        fixes = apply_mechanical_fixes(
            ruleset_map, scan_root, dry_run=True, allowed_files={abs_file.resolve()}, suppressed=suppressed
        )
        out.extend(
            {
                "file": normalize_finding_path(str(abs_file), scan_root),
                "path": str(abs_file),
                "line": fix.line,
                "fix": fix.description,
                "before": fix.before,
                "after": fix.after,
            }
            for fix in _drop_chained_after_withheld(fixes)
        )
    return out


# The unpaged build for one location: the whole reply plus the two pieces `page_reply` needs
# to slice it (`files_out`, `location_out`) — a caller that wants more than one part keeps this
# and pages it repeatedly instead of building again.
_BuiltBrief = tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any]]


def build_remedy_brief(location: dict[str, Any], scan_root: Path) -> _BuiltBrief | dict[str, Any]:
    """Build the unpaged `remedy_brief` reply for one already-resolved workflow `location` (a
    location dict from the stored full `validate` payload, so its `findings` / `relations` are
    already relative-pathed). A structured `brief_unavailable` error, naming the file, when any
    of the location's files yields no map — never a reply with an empty-inventory entry for it.

    Runs the location's own file pipeline, and commits the preservation snapshots, exactly
    once — the caller pages the returned `(full, files_out, location_out)` (`page_reply`) as
    many times as it likes without calling this again, and without any of those later calls
    touching the file pipeline or the snapshot at all.

    The reply's `location` carries `root`: the absolute project root the location's relative
    `file` names resolve against. Each `files[]` entry carries its own absolute `path` beside
    the relative `file` display name (the same resolution `resolve_from_root` does). A rewrite
    or a `validate(path=<file>)` preservation check must use `path`, never `file` — the healed
    project may not be the caller's own working directory, so a relative name alone would be
    ambiguous.

    `findings` is sorted weakest-first (`_sorted_findings`) before it reaches either the reply
    or each file's `instructions[].targets` — so the agent meets a location's most load-bearing
    findings first, whichever file they land in."""
    from reporails_cli.core.heal.preservation import PRESERVATION_CONTRACT
    from reporails_cli.formatters.mcp import remedy_brief_payload

    relations = location.get("relations") or []
    findings = _sorted_findings(location.get("findings") or [])
    built = _build_files(location, scan_root, relations, findings)
    if isinstance(built, dict):
        return built
    files_out, agents, pending_snapshots = built
    artifact_rules = artifact_rules_for_kind(location.get("kind", ""), sorted(agents) or None)
    procedure = {
        "mechanical_fixes": mechanical_fixes_for(pending_snapshots, scan_root),
        "rules": [entry["id"] for entry in (artifact_rules or {}).get("rules", [])],
    }

    # Every file built: commit the snapshots together, so a brief that IS delivered is the
    # only thing that ever replaces an earlier baseline.
    _commit_snapshots(pending_snapshots)

    location_out = {
        **{k: location[k] for k in ("order", "element", "kind", "loading", "importance", "files") if k in location},
        "root": str(scan_root),
    }
    full = remedy_brief_payload(
        location=location_out,
        files=files_out,
        findings=findings,
        relations=relations,
        artifact_rules=artifact_rules,
        procedure=procedure,
        preservation_contract=PRESERVATION_CONTRACT,
    )
    return full, files_out, location_out


def remedy_brief_tool(location: dict[str, Any], scan_root: Path, part: int = 1) -> dict[str, Any]:
    """Build (`build_remedy_brief`) and page (`remedy_brief_paging.page_reply`) the
    `remedy_brief` reply for one already-resolved workflow `location`, in one call — a
    convenience for a caller that wants exactly one part and has nowhere to keep the build
    between calls. `part` (1-based) selects which part this call returns. A reply that fits in
    one part carries no `part` / `total_parts` fields at all, so a caller ignoring paging
    entirely sees no change.

    A caller serving more than one part of the SAME brief (`server._serve_remedy_brief`) calls
    `build_remedy_brief` once instead and pages the result itself — calling this function again
    per part would re-run the location's file pipeline and re-commit its preservation snapshot
    on every part, which is never what a multi-part fetch needs."""
    built = build_remedy_brief(location, scan_root)
    if isinstance(built, dict):
        return built
    full, files_out, location_out = built
    return page_reply(full, files_out, location_out, part)
