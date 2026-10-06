"""Post-merge finding filters — inline-directive suppression and surface-scoped mutation.

Two filters run at the same chokepoint (after merge, before display and strict gating):

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
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from reporails_cli.core.discovery.walk import safe_resolve
from reporails_cli.core.platform.dto.diagnostics import (
    ListedFinding,
    subtree_tier_rank,
    walk_findings,
    workflow_summary,
)
from reporails_cli.core.platform.runtime.merger import normalize_finding_path, rebuild_severity_stats

# Canonical form is an inline HTML comment, invisible when the file renders.
_DIRECTIVE_RE = re.compile(r"<!--\s*ails-disable-line\b(?P<rules>[^>]*?)-->")
_RULE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._-]*$")


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


def _rule_tokens(captured: str) -> set[str]:
    """Pull valid rule names out of a directive's body, dropping separators."""
    return {tok for tok in re.split(r"[,\s]+", captured.strip()) if _RULE_TOKEN_RE.match(tok)}


def parse_directives(text: str) -> dict[int, set[str]]:
    """Map 1-based line number to the set of rule names suppressed on that line."""
    out: dict[int, set[str]] = {}
    for lineno, line in enumerate(text.split("\n"), start=1):
        for match in _DIRECTIVE_RE.finditer(line):
            rules = _rule_tokens(match.group("rules"))
            if rules:
                out.setdefault(lineno, set()).update(rules)
    return out


def strip_directives(content: str) -> str:
    """Remove suppression-directive comments so they never reach classification.

    Replaces each directive comment with an equal run of spaces, preserving
    every newline and column offset so atom line numbers stay exact.
    """
    return _DIRECTIVE_RE.sub(lambda m: " " * (m.end() - m.start()), content)


def _index_file(index: SuppressionIndex, rel: str, path: Path) -> None:
    """Read `path`, expand its imports and record each directive into `index`.

    A directive written in the file itself is keyed under `rel` and its source line;
    one written inside an imported file is keyed under `rel`, the imported file and
    its own line.
    """
    from reporails_cli.core.mapper.imports import expand_imports_with_origins

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


def is_suppressed(
    finding: Any,
    index: SuppressionIndex,
    alias_fn: Callable[[str], set[str]] | None = None,
    imported: ImportedPlaces | None = None,
) -> bool:
    """True when a directive on the finding's line names the finding's rule.

    A finding on an instruction an `@path` import brings in (`imported` maps its file and
    position index to where it is written) is also silenced by a directive on that
    instruction's own line of the imported file.
    """
    named = set(index.get((finding.file, finding.line)) or ())
    place = imported.get((finding.file, finding.pi)) if imported and getattr(finding, "pi", None) is not None else None
    if place is not None:
        named |= index.imported.get((finding.file, place[0], place[1])) or set()
    elif getattr(finding, "pi", None) is None:
        # A finding with no position cannot be told apart per imported line: every directive
        # under the import line counts.
        named |= index.import_rules.get((finding.file, finding.line)) or set()
    if not named:
        return False
    aliases = alias_fn(finding.rule) if alias_fn else {finding.rule}
    return bool(named & aliases)


def renumbered(locations: Sequence[Any]) -> list[Any]:
    """`locations` numbered from 1 in their order, whether each is a dict or a dataclass."""
    return [
        {**loc, "order": i} if isinstance(loc, dict) else replace(loc, order=i)
        for i, loc in enumerate(locations, start=1)
    ]


def _location_files(location: Any) -> set[str]:
    return {x.file for x in (*walk_findings(location.findings), *location.relations)}


def _row_key(f: Any) -> tuple[int, str, int, int, str]:
    """The order a location's rows keep: heaviest tier in the row's subtree, then file, line, instruction, rule."""
    return (subtree_tier_rank(f), f.file, f.line, -1 if f.pi is None else f.pi, f.rule)


def _surviving(f: Any, gone: Callable[[Any], bool]) -> list[Any]:
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


def _row_coordinate(f: Any, norm: Callable[[str], str]) -> tuple[str, str, int, int | None]:
    """The (file, rule, line, instruction) a finding or served row is told apart by."""
    return (norm(f.file), f.rule, f.line, f.pi)


def _listed_without(workflow: Any, dropped: Sequence[Any], kept: Sequence[Any]) -> tuple[Any, ...]:
    """`workflow.listed` without the rules whose findings were all removed.

    An entry whose rule lost a finding and has none left is removed; every other entry keeps
    the count the service sent.
    """
    left = {f.rule for f in kept}
    removed = {f.rule for f in dropped} - left
    return tuple(entry for entry in workflow.listed if entry.rule not in removed)


def prune_workflow(
    workflow: Any,
    gone: Callable[[Any], bool],
    norm: Callable[[str], str],
    dropped: Sequence[Any] = (),
    kept_findings: Sequence[Any] = (),
) -> Any:
    """`workflow` without the rows `gone` names and the findings `dropped`; every field agrees.

    Removal applies to a finding's members as to the rows themselves (`_surviving`). A
    location left with neither findings nor relations is removed and the rest are
    numbered again from 1; a location that loses a finding also drops a file it listed
    only for that finding. `listed` loses a rule whose findings are all dropped and the summary is written
    again for the locations kept, so no field names a location or finding that is gone.
    """
    changed = False
    kept: list[Any] = []
    for loc in workflow.locations:
        rows = [row for f in loc.findings for row in _surviving(f, gone)]
        if tuple(rows) == loc.findings:
            kept.append(loc)
            continue
        changed = True
        findings = tuple(sorted(rows, key=_row_key))
        if not findings and not loc.relations:
            continue
        still = {norm(x) for x in _location_files(replace(loc, findings=findings))}
        files = tuple(x for x in loc.files if norm(x) in still)
        kept.append(replace(loc, findings=findings, files=files))
    listed = _listed_without(workflow, dropped, kept_findings)
    if listed != workflow.listed:
        changed = True
    if not changed:
        return workflow
    locations = tuple(renumbered(kept))
    return replace(workflow, locations=locations, listed=listed, summary=workflow_summary(locations, listed))


CONFIG_LISTED_REASON = "config-file"
CONFIG_LISTED_WHY = (
    "Settings, hook and MCP config files are not rewritten automatically; "
    "review these findings and edit the file by hand."
)


def _is_config_location(loc: Any, norm: Callable[[str], str]) -> bool:
    files = _location_files(loc) or set(loc.files)
    return bool(files) and all(finding_surface(norm(x)) == "config" for x in files)


def list_config_locations(workflow: Any, norm: Callable[[str], str]) -> Any:
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
        for f in (*walk_findings(loc.findings), *loc.relations):
            counts[f.rule] = counts.get(f.rule, 0) + 1
    listed = list(workflow.listed)
    for rule, n in counts.items():
        at = next((i for i, e in enumerate(listed) if e.rule == rule), None)
        if at is None:
            listed.append(ListedFinding(rule=rule, reason=CONFIG_LISTED_REASON, count=n, why=CONFIG_LISTED_WHY))
        else:
            listed[at] = replace(listed[at], count=listed[at].count + n)
    kept = tuple(renumbered([loc for loc in workflow.locations if loc not in moved]))
    return replace(workflow, locations=kept, listed=tuple(listed), summary=workflow_summary(kept, listed))


def apply_config_listing(result: Any, project_root: Path | None = None) -> Any:
    """`result` whose workflow lists config-format files' findings instead of locating them."""
    workflow = result.workflow
    if getattr(workflow, "locations", None) is None:
        return result

    def norm(file: str) -> str:
        return normalize_finding_path(file, project_root)

    projected = list_config_locations(workflow, norm)
    return result if projected is workflow else replace(result, workflow=projected)


def _workflow_files(workflow: Any, norm: Callable[[str], str]) -> list[str]:
    return [norm(f.file) for loc in workflow.locations for f in walk_findings(loc.findings)]


def apply_suppressions(
    result: Any,
    project_root: Path | None = None,
    alias_fn: Callable[[str], set[str]] | None = None,
    imported: ImportedPlaces | None = None,
) -> Any:
    """Return `result` with directive-suppressed findings removed and stats rebuilt.

    The same suppressions apply to the findings the result's remediation `workflow` lists
    under its locations.
    """

    def norm(file: str) -> str:
        return normalize_finding_path(file, project_root)

    workflow = result.workflow if getattr(result.workflow, "locations", None) is not None else None
    if not result.findings and workflow is None:
        return result
    files = [f.file for f in result.findings]
    if workflow is not None:
        files += _workflow_files(workflow, norm)
    index = build_index(files, project_root)
    if not index:
        return result
    kept_list: list[Any] = []
    dropped: list[Any] = []
    for f in result.findings:
        (dropped if is_suppressed(f, index, alias_fn, imported) else kept_list).append(f)
    kept = tuple(kept_list)
    if workflow is not None:

        def _gone(f: Any) -> bool:
            return is_suppressed(replace(f, file=norm(f.file)), index, alias_fn, imported)

        workflow = prune_workflow(workflow, _gone, norm, dropped, kept)
    if len(kept) == len(result.findings) and (workflow is None or workflow is result.workflow):
        return result
    stats = rebuild_severity_stats(result.stats, kept) if len(kept) != len(result.findings) else result.stats
    return replace(result, findings=kept, stats=stats, workflow=workflow if workflow is not None else result.workflow)


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
    from reporails_cli.core.classify.file_tags import classify_file

    return classify_file(file).split(":")[0]


def _surface_excluded(rule: Any, surface: str) -> bool:
    """True when `rule` declares `surface_mutations: {<surface>: {applies: false}}`.

    `surface` is always a non-empty tag (`finding_surface` falls back to `file`); an unknown
    surface simply misses `mutations.get(surface)` and returns False, so no empty-string guard
    is needed.
    """
    mutations = getattr(rule, "surface_mutations", None)
    if not mutations:
        return False
    entry = mutations.get(surface)
    return isinstance(entry, dict) and entry.get("applies") is False


def _finding_surface_excluded(
    finding: Any,
    surface: str,
    rules_by_id: dict[str, Any],
    alias_fn: Callable[[str], set[str]] | None,
) -> bool:
    """True when any name the finding's rule is known by declares the surface non-applicable.

    Client-side findings carry a raw token (`format`, `heading_instruction`, `scope`) that aliases to a
    canonical `CORE:*` id; server findings carry the canonical id directly. Resolving through
    `alias_fn` (the same resolver `apply_suppressions` uses) lets a `surface_mutations` block on
    the canonical rule suppress the raw-token finding too.
    """
    names = alias_fn(finding.rule) if alias_fn else {finding.rule}
    return any(_surface_excluded(rules_by_id.get(name), surface) for name in names)


def apply_surface_mutations(
    result: Any,
    rules_by_id: dict[str, Any],
    alias_fn: Callable[[str], set[str]] | None = None,
    project_root: Path | None = None,
) -> Any:
    """Return `result` with findings dropped on a surface their rule marks non-applicable.

    A finding survives unless its rule (resolved through `alias_fn` to every name it is known
    by) declares the finding's surface non-applicable via `surface_mutations`. Stats are rebuilt
    over the kept findings, mirroring `apply_suppressions`, and the remediation `workflow`
    loses the same findings.
    """
    if not result.findings:
        return result
    kept_list: list[Any] = []
    dropped: list[Any] = []
    for f in result.findings:
        excluded = _finding_surface_excluded(f, finding_surface(f.file), rules_by_id, alias_fn)
        (dropped if excluded else kept_list).append(f)
    if not dropped:
        return result
    kept = tuple(kept_list)
    workflow = result.workflow
    if getattr(workflow, "locations", None) is not None:

        def norm(file: str) -> str:
            return normalize_finding_path(file, project_root)

        gone_rows = {_row_coordinate(f, norm) for f in dropped}
        workflow = prune_workflow(workflow, lambda row: _row_coordinate(row, norm) in gone_rows, norm, dropped, kept)
    return replace(result, findings=kept, stats=rebuild_severity_stats(result.stats, kept), workflow=workflow)


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
