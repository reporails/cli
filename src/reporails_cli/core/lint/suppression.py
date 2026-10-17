"""Post-merge finding filters — inline-directive suppression, the run's rule set and surface-scoped mutation.

Three filters run at the same chokepoint (after merge, before display and strict gating):

1. Inline per-line suppression — an author marks a single reviewed finding as intentional
   with a rule-named inline directive on the offending line; the rule stays armed on every
   other line. Directive form (inline HTML comment, invisible when the file renders):

       Some instruction here.  <!-- ails-disable-line CORE:C:0049 -->

   The directive must name at least one rule (space- or comma-separated for several); a
   bare directive with no rule names nothing.

2. Surface-scoped mutation — a content-quality rule that critiques instruction-authoring
   quality (formatting regime, charge ordering, diagram usage) mis-fires on an agent-written
   memory index, which is a list of `- [Title](file.md) — hook` pointers, not a human-authored
   instruction file. Such a rule declares `surface_mutations: {memory: {applies: false}}` in
   its frontmatter; `apply_surface_mutations` reads that declaration and drops the rule's
   findings on memory-surface files. Filtering post-merge covers both locally-computed and
   server-emitted findings uniformly.

3. Run rule set — a rule the run does not report (disabled, excluded by an agent, gated out
   by its capabilities or superseded) loses its findings, hints, cross-file rows and
   remediation rows (`apply_rule_set`).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from reporails_cli.core.classify.file_tags import classify_file
from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.mapper.imports import expand_imports_with_origins
from reporails_cli.core.platform.adapters.rules_query import rule_slug
from reporails_cli.core.platform.config.config import get_project_config
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import (
    FindingBase,
    FindingItem,
    ListedFinding,
    LocationFinding,
    LocationRelation,
    RemediationWorkflow,
    WorkflowLocation,
    subtree_tier_rank,
    walk_findings,
    workflow_summary,
)
from reporails_cli.core.platform.dto.models import Rule
from reporails_cli.core.platform.runtime.merger import (
    CombinedResult,
    drop_findings,
    normalize_finding_path,
    rebuild_cross_file_stats,
)
from reporails_cli.core.platform.utils.directives import parse_directives
from reporails_cli.core.platform.utils.utils import matches_any_glob


class SuppressionIndex(dict[tuple[str, int], set[str]]):
    """(file, line) -> rule names the author chose to silence on that line of that file.

    A directive written in a file brought in by an `@path` import is not keyed by the
    importing file's line: it is kept in `imported`, by the imported file (as the importing
    file's directory reaches it) and the line it is written on there, so it silences its
    rule for the instruction on that line and for nothing else. `import_lines` holds the
    importing file's `@path` lines that bring in such a directive, and `import_rules` the
    rules all of them name, for a finding that carries no position.
    """

    def __init__(self) -> None:
        super().__init__()
        self.imported: dict[tuple[str, str, int], set[str]] = {}
        self.import_lines: set[tuple[str, int]] = set()
        self.import_rules: dict[tuple[str, int], set[str]] = {}

    def __bool__(self) -> bool:
        return bool(len(self) or self.imported)


# (file, position index) -> (imported file, line there) for each instruction an `@path` import brings in.
ImportedPlaces = Mapping[tuple[str, int], tuple[str, int]]


def _index_file(index: SuppressionIndex, rel: str, path: Path) -> None:
    """Read `path`, expand its imports and record each directive into `index`.

    A directive written in the file itself is keyed under `rel` and its source line;
    one written inside an imported file is keyed under `rel`, the imported file and
    its own line.
    """
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    try:
        text, line_map, origins = expand_imports_with_origins(raw, path)
    except (OSError, UnicodeDecodeError, RecursionError):
        text, line_map, origins = raw, list(range(1, len(raw.split("\n")) + 1)), []
    for lineno, rules in parse_directives(text).items():
        idx = lineno - 1
        source_line = line_map[idx] if 0 <= idx < len(line_map) else lineno
        origin = origins[idx] if 0 <= idx < len(origins) else None
        if origin is None:
            index.setdefault((rel, source_line), set()).update(rules)
            continue
        imported_from = Path(os.path.relpath(origin[0], safe_resolve(path).parent)).as_posix()
        index.imported.setdefault((rel, imported_from, origin[1]), set()).update(rules)
        index.import_lines.add((rel, source_line))
        index.import_rules.setdefault((rel, source_line), set()).update(rules)


def build_index(
    finding_files: Iterable[str],
    project_root: Path | None,
) -> SuppressionIndex:
    """Scan each finding-bearing file for directives and key them by (file, line).

    `@import` expansion can shift a directive onto a different EXPANDED line than
    the one it is written on. Directives are parsed from the expanded content and
    then translated back to the importing file's own SOURCE line, the coordinate
    atom and finding line numbers use. A directive written in the importing file
    (including on its `@path` line) is keyed there and merged with any other on the
    same line; a directive written inside an imported file is keyed by that file and
    its own line, so several of them all stay in force.
    """
    index = SuppressionIndex()
    for rel in set(finding_files):
        path = resolve_finding_path(rel, project_root)
        if path is not None:
            _index_file(index, rel, path)
    return index


def suppressed_lines(
    finding_files: Iterable[str],
    project_root: Path | None,
) -> dict[str, set[int]]:
    """Per-file set of lines carrying any suppression directive (for the heal write path).

    Heal must not mechanically rewrite a line the author explicitly annotated as
    reviewed with an `ails-disable-line` directive; this surfaces those lines keyed
    by the same source-line coordinate space the atoms use.
    """
    out: dict[str, set[int]] = {}
    index = build_index(finding_files, project_root)
    for rel, lineno in (*index, *index.import_lines):
        out.setdefault(rel, set()).add(lineno)
    return out


# A rule a suppression directive may also name by its short token, as it has always been written.
SHORT_TOKEN = {"CORE:S:0039": "heading_instruction"}


def rule_aliases(rule: str) -> set[str]:
    """Every name a suppression directive may use for a rule: its id, its slug and its short token."""
    names = {rule}
    if rule in SHORT_TOKEN:
        names.add(SHORT_TOKEN[rule])
    slug = rule_slug(rule)
    if slug:
        names.add(slug)
    return names


def is_suppressed(
    finding: FindingBase | LocationFinding,
    index: SuppressionIndex,
    imported: ImportedPlaces | None = None,
    pi: int | None = None,
) -> bool:
    """True when a directive on the finding's line names the finding's rule.

    A finding on an instruction an `@path` import brings in (`imported` maps its file and
    position index to where it is written) is also silenced by a directive on that
    instruction's own line of the imported file. `pi` is the finding's instruction position,
    `None` for a finding that has none.
    """
    named = set(index.get((finding.file, finding.line)) or ())
    place = imported.get((finding.file, pi)) if imported and pi is not None else None
    if place is not None:
        named |= index.imported.get((finding.file, place[0], place[1])) or set()
    elif pi is None:
        # A finding with no position cannot be told apart per imported line: every directive
        # under the import line counts.
        named |= index.import_rules.get((finding.file, finding.line)) or set()
    if not named:
        return False
    return bool(named & rule_aliases(finding.rule))


def renumbered(locations: Sequence[WorkflowLocation]) -> list[WorkflowLocation]:
    """`locations` numbered from 1 in their order."""
    return [replace(loc, order=i) for i, loc in enumerate(locations, start=1)]


def renumbered_json(locations: Sequence[JsonObject]) -> list[JsonObject]:
    """`locations`, each a serialized workflow location, numbered from 1 in their order."""
    return [{**loc, "order": i} for i, loc in enumerate(locations, start=1)]


def _location_files(location: WorkflowLocation) -> set[str]:
    return {x.file for x in walk_findings(location.findings)} | {r.file for r in location.relations}


def _row_key(f: LocationFinding) -> tuple[int, str, int, int, str]:
    """The order a location's rows keep: heaviest tier in the row's subtree, then file, line, instruction, rule."""
    return (subtree_tier_rank(f), f.file, f.line, -1 if f.pi is None else f.pi, f.rule)


def _surviving(f: LocationFinding, gone: Callable[[LocationFinding], bool]) -> list[LocationFinding]:
    """The rows `f` leaves behind once its suppressed findings are removed.

    A suppressed finding releases its members as rows. A kept finding whose members all stand
    is returned as it is. A kept instruction owner that loses members down to one is replaced
    by it and with none is dropped; a kept sentence owner stands with whatever members remain.
    """
    members = tuple(row for m in f.members for row in _surviving(m, gone))
    if gone(f):
        return list(members)
    if members == f.members:
        return [f]
    if f.pi is not None and len(members) <= 1:
        return list(members)
    return [replace(f, members=members)]


def _row_coordinate(f: LocationFinding | FindingItem, norm: Callable[[str], str]) -> tuple[str, str, int, int | None]:
    """The (file, rule, line, instruction) a finding or served row is told apart by."""
    return (norm(f.file), f.rule, f.line, f.pi)


def _listed_without(
    workflow: RemediationWorkflow, dropped: Sequence[FindingItem | ListedFinding], kept: Sequence[FindingItem]
) -> tuple[ListedFinding, ...]:
    """`workflow.listed` without the rules whose findings were all removed.

    An entry whose rule lost a finding and has none left is removed; every other entry keeps
    the count the service sent.
    """
    left = {f.rule for f in kept}
    removed = {f.rule for f in dropped} - left
    return tuple(entry for entry in workflow.listed if entry.rule not in removed)


def _pruned_location(
    loc: WorkflowLocation,
    gone: Callable[[LocationFinding], bool],
    relation_gone: Callable[[LocationRelation], bool] | None,
    norm: Callable[[str], str],
) -> WorkflowLocation | None:
    """`loc` without the rows `gone` and the relations `relation_gone` name, a file it listed
    only for them dropped; `loc` itself when nothing is removed, `None` when nothing is left."""
    rows = [row for f in loc.findings for row in _surviving(f, gone)]
    relations = tuple(r for r in loc.relations if relation_gone is None or not relation_gone(r))
    if tuple(rows) == loc.findings and relations == loc.relations:
        return loc
    findings = tuple(sorted(rows, key=_row_key))
    if not findings and not relations:
        return None
    still = {norm(x) for x in _location_files(replace(loc, findings=findings, relations=relations))}
    files = tuple(x for x in loc.files if norm(x) in still)
    return replace(loc, findings=findings, relations=relations, files=files)


def prune_workflow(
    workflow: RemediationWorkflow,
    gone: Callable[[LocationFinding], bool],
    norm: Callable[[str], str],
    *,
    dropped: Sequence[FindingItem | ListedFinding] = (),
    kept_findings: Sequence[FindingItem] = (),
    relation_gone: Callable[[LocationRelation], bool] | None = None,
) -> RemediationWorkflow:
    """`workflow` without the rows `gone` and the relations `relation_gone` name and the findings
    `dropped`; every field agrees.

    Removal applies to a finding's members as to the rows themselves (`_surviving`). A
    location left with neither findings nor relations is removed and the rest are
    numbered again from 1; a location that loses a finding also drops a file it listed
    only for that finding. `listed` loses a rule whose findings are all dropped and the summary is written
    again for the locations kept, so no field names a location or finding that is gone.
    """
    changed = False
    kept: list[WorkflowLocation] = []
    for loc in workflow.locations:
        pruned = _pruned_location(loc, gone, relation_gone, norm)
        changed = changed or pruned is not loc
        if pruned is not None:
            kept.append(pruned)
    listed = _listed_without(workflow, dropped, kept_findings)
    if listed != workflow.listed:
        changed = True
    if not changed:
        return workflow
    locations = tuple(renumbered(kept))
    return replace(workflow, locations=locations, listed=listed, summary=workflow_summary(locations, listed))


CONFIG_LISTED_REASON = "config-file"


def _is_config_location(loc: WorkflowLocation, norm: Callable[[str], str]) -> bool:
    files = _location_files(loc) or set(loc.files)
    return bool(files) and all(finding_surface(norm(x)) == "config" for x in files)


def list_config_locations(workflow: RemediationWorkflow, norm: Callable[[str], str]) -> RemediationWorkflow:
    """`workflow` with each location made only of config-format files moved into `listed`.

    Settings, hook and MCP config files take no rewrite location: each rule that fired there
    is listed once with its summed row count (added to an entry the rule already has), the
    kept locations are numbered again from 1 and the summary is written for them.
    """
    moved = [loc for loc in workflow.locations if _is_config_location(loc, norm)]
    if not moved:
        return workflow
    counts: dict[str, int] = {}
    for loc in moved:
        for rule in (*(f.rule for f in walk_findings(loc.findings)), *(r.rule for r in loc.relations)):
            counts[rule] = counts.get(rule, 0) + 1
    listed = list(workflow.listed)
    for rule, n in counts.items():
        at = next((i for i, e in enumerate(listed) if e.rule == rule), None)
        if at is None:
            listed.append(ListedFinding(rule=rule, reason=CONFIG_LISTED_REASON, count=n))
        else:
            listed[at] = replace(listed[at], count=listed[at].count + n)
    kept = tuple(renumbered([loc for loc in workflow.locations if loc not in moved]))
    return replace(workflow, locations=kept, listed=tuple(listed), summary=workflow_summary(kept, listed))


HEAL_EXCLUDED_REASON = "excluded"


def list_heal_excluded(
    workflow: RemediationWorkflow, excluded: Callable[[str], bool], norm: Callable[[str], str]
) -> RemediationWorkflow:
    """`workflow` with the findings and relations on `excluded` files moved into `listed`.

    The rows leave their location (`prune_workflow`: a location left with nothing is dropped,
    the rest are numbered again from 1). Each rule that fired on an excluded file is listed once
    with its row count.
    """
    counts: dict[str, int] = {}
    for loc in workflow.locations:
        rows = (*((f.file, f.rule) for f in walk_findings(loc.findings)), *((r.file, r.rule) for r in loc.relations))
        for file, rule in rows:
            if excluded(norm(file)):
                counts[rule] = counts.get(rule, 0) + 1
    if not counts:
        return workflow
    pruned = prune_workflow(
        workflow, lambda f: excluded(norm(f.file)), norm, relation_gone=lambda r: excluded(norm(r.file))
    )
    listed = (
        *pruned.listed,
        *(ListedFinding(rule=rule, reason=HEAL_EXCLUDED_REASON, count=n) for rule, n in counts.items()),
    )
    return replace(pruned, listed=listed, summary=workflow_summary(pruned.locations, listed))


def apply_config_listing(result: CombinedResult, project_root: Path | None = None) -> CombinedResult:
    """`result` whose workflow lists config-format files' findings, and those of files in the
    project's `heal_exclude`, instead of locating them. Findings, scores and stats stay as they are."""
    workflow = result.reply.workflow
    if workflow is None:
        return result

    def norm(file: str) -> str:
        return normalize_finding_path(file, project_root)

    projected = list_config_locations(workflow, norm)
    patterns = get_project_config(project_root).heal_exclude if project_root is not None else []
    if patterns and project_root is not None:
        projected = list_heal_excluded(
            projected, lambda rel: matches_any_glob(project_root / rel, patterns, project_root), norm
        )
    return result if projected is workflow else replace(result, reply=replace(result.reply, workflow=projected))


def _workflow_files(workflow: RemediationWorkflow, norm: Callable[[str], str]) -> list[str]:
    return [norm(f.file) for loc in workflow.locations for f in walk_findings(loc.findings)]


def apply_suppressions(
    result: CombinedResult,
    project_root: Path | None = None,
    imported: ImportedPlaces | None = None,
) -> CombinedResult:
    """Return `result` with directive-suppressed findings removed and stats rebuilt.

    The same suppressions apply to the findings the result's remediation `workflow` lists
    under its locations.
    """

    def norm(file: str) -> str:
        return normalize_finding_path(file, project_root)

    workflow = result.reply.workflow
    if not result.findings and workflow is None:
        return result
    files = [f.file for f in result.findings]
    if workflow is not None:
        files += _workflow_files(workflow, norm)
    index = build_index(files, project_root)
    if not index:
        return result
    kept_list: list[FindingItem] = []
    dropped: list[FindingItem] = []
    for f in result.findings:
        (dropped if is_suppressed(f, index, imported, f.pi) else kept_list).append(f)
    kept = tuple(kept_list)
    if workflow is not None:

        def _gone(f: LocationFinding) -> bool:
            return is_suppressed(replace(f, file=norm(f.file)), index, imported, f.pi)

        workflow = prune_workflow(workflow, _gone, norm, dropped=dropped, kept_findings=kept)
    if len(kept) == len(result.findings) and (workflow is None or workflow is result.reply.workflow):
        return result
    result = drop_findings(result, kept)
    return replace(
        result,
        reply=replace(result.reply, workflow=workflow if workflow is not None else result.reply.workflow),
    )


def apply_rule_set(
    result: CombinedResult, resolved: Collection[str], known: Collection[str], project_root: Path | None = None
) -> CombinedResult:
    """Return `result` without the findings of a rule the run does not report.

    A finding whose rule is one of the `known` rules but not among the `resolved` ones (a
    disabled rule, one an agent excludes, one its capabilities gate out or a superseded one) is
    dropped with its remediation `workflow` rows and listed entries, and leaves the source
    counts as if it never ran. The same goes for its hints and cross-file rows, and the
    cross-file counts follow what is kept. A rule name no known rule carries (a classifier or
    memory check's own label) is kept.
    """

    def out(rule: str) -> bool:
        return rule in known and rule not in resolved

    kept = [f for f in result.findings if not out(f.rule)]
    dropped = [f for f in result.findings if out(f.rule)]
    result = drop_findings(result, kept)
    cross_file = tuple(row for row in result.cross_file if not out(row.rule))
    coordinates = tuple(row for row in result.cross_file_coordinates if not out(row.rule))
    hints = tuple(hint for hint in result.hints if not out(hint.diagnostic_type))
    if (cross_file, coordinates, hints) != (result.cross_file, result.cross_file_coordinates, result.hints):
        result = replace(
            result,
            cross_file=cross_file,
            cross_file_coordinates=coordinates,
            hints=hints,
            stats=rebuild_cross_file_stats(result.stats, cross_file, coordinates),
        )
    workflow = result.reply.workflow
    if workflow is None:
        return result

    def norm(file: str) -> str:
        return normalize_finding_path(file, project_root)

    listed_out = [entry for entry in workflow.listed if out(entry.rule)]
    pruned = prune_workflow(
        workflow,
        lambda row: out(row.rule),
        norm,
        dropped=[*dropped, *listed_out],
        kept_findings=kept,
        relation_gone=lambda relation: out(relation.rule),
    )
    return result if pruned is workflow else replace(result, reply=replace(result.reply, workflow=pruned))


def finding_surface(file: str) -> str:
    """Resolve a finding's file path to the surface tag a `surface_mutations` block keys on.

    Delegates to the shared core `classify_file` (base tag, dropping any `:name` suffix), so the
    structural-directory precedence is applied exactly once: a skill / agent / rule markdown file
    merely nested under a memory directory classifies as its own kind, NOT `memory`, and its
    content-quality findings are not surface-suppressed. `classify_file` recognizes every
    memory-surface directory name derived from the config `memory` + `subagent_memory` scope
    patterns, so this covers the auto-memory index (`~/.claude/projects/*/memory/`) AND the
    subagent-memory scopes (`agent-memory/` user+project, `agent-memory-local/` local) uniformly.
    """
    return classify_file(file).split(":")[0]


def _surface_excluded(rule: Rule | None, surface: str) -> bool:
    """True when `rule` declares `surface_mutations: {<surface>: {applies: false}}`.

    `surface` is always a non-empty tag (`finding_surface` falls back to `file`); an unknown
    surface simply misses `mutations.get(surface)` and returns False, so no empty-string guard
    is needed.
    """
    mutations = rule.surface_mutations if rule is not None else None
    if not mutations:
        return False
    entry = mutations.get(surface)
    return isinstance(entry, dict) and entry.get("applies") is False


def _finding_surface_excluded(
    finding: FindingItem,
    surface: str,
    rules_by_id: Mapping[str, Rule],
) -> bool:
    """True when the finding's rule declares the surface non-applicable."""
    return _surface_excluded(rules_by_id.get(finding.rule), surface)


def apply_surface_mutations(
    result: CombinedResult,
    rules_by_id: Mapping[str, Rule],
    project_root: Path | None = None,
) -> CombinedResult:
    """Return `result` with findings dropped on a surface their rule marks non-applicable.

    A finding survives unless its rule declares the finding's surface non-applicable via
    `surface_mutations`. The total, per-severity and per-source counts drop with the dropped
    findings, and the remediation `workflow` loses the same findings.
    """
    if not result.findings:
        return result
    kept_list: list[FindingItem] = []
    dropped: list[FindingItem] = []
    for f in result.findings:
        excluded = _finding_surface_excluded(f, finding_surface(f.file), rules_by_id)
        (dropped if excluded else kept_list).append(f)
    if not dropped:
        return result
    kept = tuple(kept_list)
    workflow = result.reply.workflow
    if workflow is not None:

        def norm(file: str) -> str:
            return normalize_finding_path(file, project_root)

        gone_rows = {_row_coordinate(f, norm) for f in dropped}
        workflow = prune_workflow(
            workflow, lambda row: _row_coordinate(row, norm) in gone_rows, norm, dropped=dropped, kept_findings=kept
        )
    result = drop_findings(result, kept)
    return replace(result, reply=replace(result.reply, workflow=workflow))


def resolve_finding_path(rel: str, project_root: Path | None) -> Path | None:
    """Reconstruct an absolute path from a normalized finding path."""
    if rel.startswith("~/"):
        return Path.home() / rel[2:]
    p = Path(rel)
    if p.is_absolute():
        return p
    if project_root is None:
        return p
    return project_root / p
