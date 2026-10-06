"""MCP output shaping — bounds the `validate` payload, assembles `remedy_brief`, and
renders the `explain` text.

Three live surfaces: `bound_validate_payload` caps a `validate` JSON payload to a
top-N-per-file / workflow-first envelope so a large repo stays under the client's
per-tool-result token cap, `remedy_brief_payload` assembles the `remedy_brief` reply from
its already-shaped parts, and `format_rule` renders one rule as readable text for
`explain`. All three build from plain dicts; no domain model is imported here.
"""

from __future__ import annotations

from typing import Any, NamedTuple

from reporails_cli.core.mapper.md_parser import file_lines
from reporails_cli.core.mapper.parse import parse_blocks
from reporails_cli.core.platform.dto.diagnostics import walk_findings

# ---------------------------------------------------------------------------
# Envelope — bound the validate payload
# ---------------------------------------------------------------------------

# Envelope defaults for the `validate` response. The full per-file finding set on a
# large repo blew a single-line JSON result past the harness per-tool-result token cap;
# the bounded default keeps the aggregate signal (stats + surface_health + level) whole
# and caps the enumerated findings, with a `full=true` opt-in for the complete set.
#
# A reply that carries a `workflow` zeroes these out below (the location
# index is the surface, not this raw top-N view). A reply without a `workflow` has no
# location index, so these defaults are the whole size bar for it on a large project.
_ENVELOPE_PER_FILE_LIMIT = 2
_ENVELOPE_MAX_FILES = 25
# The `cross_file` / `cross_file_coordinates` rows are enumeration too: one row per shared or
# repeated instruction, so a surface with many overlapping pairs grows them past everything
# else in the reply. They get the finding treatment — a top slice without a workflow, withheld
# behind `full=true` beside one — while `stats` keeps the pair counts. Unpaid tiers get
# `cross_file_coordinates` (file-pair + count, no line numbers) instead of `cross_file`; the two
# never both appear on one reply, but both are bounded the same way.
_ENVELOPE_CROSS_FILE_LIMIT = 8
_ENVELOPE_CROSS_FILE_COORD_LIMIT = 8

# What a `validate` reply's location index carries per location — no findings/relations (those
# come with `remedy_brief(path, location)`), just enough to route the next call.
_LOCATION_INDEX_KEYS = ("order", "element", "kind", "loading", "files", "importance")

# A targeted workflow keeps each kept location's findings/relations in the reply only when
# it kept this many locations or fewer — a broad target (e.g. every `skills` location in a
# project with dozens of skills) would otherwise re-grow the reply the index exists to bound.
_TARGETED_DETAIL_MAX_LOCATIONS = 3


# ---------------------------------------------------------------------------
# Rule labels — title + docs link for every rule id named in the reply
# ---------------------------------------------------------------------------


def _collect_rule_ids(node: Any, out: set[str]) -> None:
    """Walk a JSON-shaped `validate` payload, collecting every string value found under a
    `rule` key — per-file findings, `top_rules`, workflow findings/relations, and
    `workflow.listed` all name their rule this way."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "rule" and isinstance(value, str) and value:
                out.add(value)
            else:
                _collect_rule_ids(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_rule_ids(item, out)


def rules_block(payload: dict[str, Any]) -> dict[str, dict[str, str]]:
    """`{<canonical rule id>: {"title": ..., "url": ...}}` for every rule id named anywhere in
    `payload`, once each. A raw client-check token (`format`, `bold`, ...) is mapped through
    `display_rule_id` first, so the key matches the canonical id the rest of the reply already
    shows. A rule id with neither a resolvable title nor a docs url is omitted. The key set is
    sorted for stability.
    """
    from reporails_cli.formatters.text.display_constants import display_rule_id, rule_label

    raw_ids: set[str] = set()
    _collect_rule_ids(payload, raw_ids)
    rules: dict[str, dict[str, str]] = {}
    for raw in raw_ids:
        canon = display_rule_id(raw)
        if canon in rules:
            continue
        label = rule_label(canon)
        if label:
            rules[canon] = label
    return dict(sorted(rules.items()))


def with_rule_labels(payload: dict[str, Any]) -> dict[str, Any]:
    """Add a top-level `rules` map (title + docs url, once per rule id) to a `validate`
    reply. A no-op when `payload` carries no rule id to label (error / needs_install
    shapes, or an empty result)."""
    if not isinstance(payload, dict):
        return payload
    rules = rules_block(payload)
    if not rules:
        return payload
    return {**payload, "rules": rules}


def _group_listed(listed: Any) -> Any:
    """`workflow.listed` grouped by its `why` text, one group per distinct `why` in
    first-seen order: `{"why": <text>, "rules": [{"rule": <id>, "count": <n>}, ...]}`.
    `reason` is dropped — the bounded view's user-facing explanation is `why`; `reason`
    keeps riding on the ungrouped shape everywhere else (`-f json`, `full=true`). Several
    rules commonly share one `why` sentence word for word, so grouping them removes the
    repeated text instead of repeating it once per rule."""
    if not isinstance(listed, list):
        return listed
    order: list[str] = []
    groups: dict[str, dict[str, Any]] = {}
    for entry in listed:
        if not isinstance(entry, dict):
            continue
        why = entry.get("why") or entry.get("reason") or ""
        if why not in groups:
            groups[why] = {"why": why, "rules": []}
            order.append(why)
        groups[why]["rules"].append({"rule": entry.get("rule", ""), "count": entry.get("count", 0)})
    return [groups[why] for why in order]


def _workflow_index(workflow: Any) -> Any:
    """The workflow as an index: each location without its findings/relations (those come with
    `remedy_brief(path, location)`), each with a true `finding_count`, and `listed` grouped by
    its shared `why` text (`_group_listed`) instead of repeated once per rule. A workflow with
    no location list keeps its other keys as they are, with `listed` grouped the same way.

    A targeted workflow (`workflow.targets` present — `validate(path, targets=...)` already
    kept only the locations holding a targeted file) keeps each location's `findings` and
    `relations` too, but only while that kept set is small (at most
    `_TARGETED_DETAIL_MAX_LOCATIONS` locations); a broader targeted view behaves like the
    untargeted index instead."""
    if not isinstance(workflow, dict):
        return workflow
    if not isinstance(workflow.get("locations"), list):
        if "listed" not in workflow:
            return workflow
        return {**workflow, "listed": _group_listed(workflow["listed"])}
    raw_locations = workflow["locations"]
    targeted = "targets" in workflow and len(raw_locations) <= _TARGETED_DETAIL_MAX_LOCATIONS
    locations = []
    for loc in raw_locations:
        if not isinstance(loc, dict):
            locations.append(loc)
            continue
        entry = {k: loc[k] for k in _LOCATION_INDEX_KEYS if k in loc}
        entry["finding_count"] = sum(1 for _ in walk_findings(loc.get("findings") or ())) + len(
            loc.get("relations") or ()
        )
        if targeted:
            if "findings" in loc:
                entry["findings"] = loc["findings"]
            if "relations" in loc:
                entry["relations"] = loc["relations"]
        locations.append(entry)
    index = {k: v for k, v in workflow.items() if k != "locations"}
    index["locations"] = locations
    if "listed" in index:
        index["listed"] = _group_listed(index["listed"])
    return index


def _truncated_block(
    *,
    findings: tuple[int, int],
    files: tuple[int, int],
    cross_file: tuple[int, int],
    cross_file_coordinates: tuple[int, int],
    workflow_present: bool,
) -> dict[str, Any]:
    """The `truncated` marker: true counts + the `full=true` hint (workflow-first when a workflow is present).

    Each `(shown, total)` pair covers one bounded list — findings, files, `cross_file`,
    `cross_file_coordinates` — so a growing envelope's cut lists add a pair, not a new
    parameter apiece.
    """
    findings_shown, findings_total = findings
    files_shown, files_total = files
    cross_file_shown, cross_file_total = cross_file
    coord_shown, coord_total = cross_file_coordinates
    hint = (
        "Workflow view: call remedy_brief(path, location) for each location in `workflow.locations`, "
        "one kind at a time, then validate(path=<file>) after rewriting a location's files. Per-finding "
        "detail is behind validate(path, full=true)."
        if workflow_present
        else "Bounded view. Call validate(path, full=true) for every finding and location."
    )
    block = {
        "findings_shown": findings_shown,
        "findings_total": findings_total,
        "files_shown": files_shown,
        "files_total": files_total,
        "cross_file_shown": cross_file_shown,
        "cross_file_total": cross_file_total,
        "hint": hint,
    }
    if coord_total:
        block["cross_file_coordinates_shown"] = coord_shown
        block["cross_file_coordinates_total"] = coord_total
    return block


def _bound_files(files: dict[str, Any], *, per_file_limit: int, max_files: int) -> tuple[dict[str, Any], int]:
    """Top-N findings per file over the first `max_files` files; returns `(kept, findings_shown)`."""
    kept: dict[str, Any] = {}
    shown = 0
    for index, (file_path, entry) in enumerate(files.items()):
        if index >= max_files:
            break
        findings = entry.get("findings", [])
        if len(findings) > per_file_limit:
            entry = {**entry, "findings": findings[:per_file_limit]}
        shown += len(entry.get("findings", []))
        kept[file_path] = entry
    return kept, shown


class _BoundList(NamedTuple):
    """A capped enumeration list plus its shown/total counts, as one local instead of three —
    `bound_validate_payload` holds one of these per capped list (`cross_file`,
    `cross_file_coordinates`) rather than a `kept`/`shown`/`total` name apiece."""

    kept: list[Any]
    shown: int
    total: int


def _bound_list(items: Any, limit: int) -> _BoundList:
    """Top-`limit` slice of an enumeration list (`cross_file` / `cross_file_coordinates`)."""
    full = items or []
    kept = full[:limit]
    return _BoundList(kept, len(kept), len(full))


def _set_or_drop_cut_list(bounded: dict[str, Any], key: str, bl: _BoundList) -> None:
    """After a cap, set `bounded[key]` to the kept slice, drop the key when the cap emptied
    it, or leave it as the payload's original full list (already present via the `{**payload,
    ...}` spread) when nothing was actually cut."""
    if bl.shown < bl.total:
        if bl.kept:
            bounded[key] = bl.kept
        else:
            del bounded[key]


def bound_validate_payload(
    payload: dict[str, Any],
    *,
    per_file_limit: int = _ENVELOPE_PER_FILE_LIMIT,
    max_files: int = _ENVELOPE_MAX_FILES,
    cross_file_limit: int = _ENVELOPE_CROSS_FILE_LIMIT,
    cross_file_coord_limit: int = _ENVELOPE_CROSS_FILE_COORD_LIMIT,
) -> dict[str, Any]:
    """Bound a `validate` JSON payload to a top-N-per-file / top-files envelope.

    Keeps every aggregate field (`stats`, `surface_health`, `level`, `tier`, `quality`,
    `pro`) untouched — those drive the slash-command opening move and the fix-walk pacing —
    and caps the enumerated `files` findings, `cross_file` and `cross_file_coordinates` rows.
    Each retained file keeps its true `count`, so a consumer sees how many findings exist
    even when the list is truncated. A `truncated` block signals when the view is bounded and
    names the `full=true` opt-in, with a `cross_file_coordinates_shown`/`_total` pair added
    whenever that list itself was cut. Error / needs-install payloads (no `files` map) pass
    through.

    The paid `workflow` (when present) is an index: every location — order, tier, element,
    kind, loading, files, importance, and a true `finding_count` — with no findings or
    relations; `remedy_brief(path, location)` serves those. `listed` is grouped by its
    shared `why` text (`{"why", "rules": [{"rule", "count"}, ...]}`) instead of repeating
    the same explanation once per rule; `reason` is dropped from this bounded shape (it
    stays on the ungrouped `-f json` / `full=true` shape).

    Every reply also carries a top-level `rules` map (`with_rule_labels`) — a title + docs
    link for every rule id still named anywhere in the (possibly bounded) reply, so a coding
    agent never has to show a bare rule code.
    """
    files = payload.get("files")
    if not isinstance(files, dict) or not (files or payload.get("cross_file") or payload.get("cross_file_coordinates")):
        # A targeted reply can legitimately have no `files` content and no `cross_file` /
        # `cross_file_coordinates` (every targeted file is clean) while still carrying a
        # `workflow` with more locations than the small-reply budget allows — the index still
        # applies so those locations drop their `findings`/`relations`, same as the
        # non-early-return path below.
        indexed_workflow = _workflow_index(payload.get("workflow"))
        if indexed_workflow is payload.get("workflow"):
            return with_rule_labels(payload)
        return with_rule_labels({**payload, "workflow": indexed_workflow})

    workflow = _workflow_index(payload.get("workflow"))
    # A paid response carries the remediation `workflow` — the location index the coding
    # agent walks one kind at a time. The per-finding enumeration is then the `ails check -v`
    # shape riding along beside it, and it dominated the envelope. With a workflow present
    # each file keeps its true `count` (+ `regime`) and drops its finding list; the
    # enumeration stays one `full=true` call away.
    workflow_present = isinstance(workflow, dict) and bool(workflow.get("locations"))
    # Workflow-first: the enumerated findings and cross-file rows are withheld (each
    # surviving file row keeps its true `count` + `regime`), and the file-row cap still
    # applies — the rows are ordered by finding count, so the first `max_files` are the
    # top-N and a large surface cannot grow the reply linearly with its file count.
    # `cross_file_coordinates` never rides beside a paid `workflow` in practice (the two are
    # tier-exclusive), but it is zeroed here too so a payload carrying both is never the one
    # shape this leaves uncapped.
    if workflow_present:
        per_file_limit = cross_file_limit = cross_file_coord_limit = 0

    kept, findings_shown = _bound_files(files, per_file_limit=per_file_limit, max_files=max_files)
    findings_total = sum(len(entry.get("findings", [])) for entry in files.values())
    cross_file = _bound_list(payload.get("cross_file"), cross_file_limit)
    coordinates = _bound_list(payload.get("cross_file_coordinates"), cross_file_coord_limit)

    if (
        findings_shown == findings_total
        and len(kept) == len(files)
        and workflow is payload.get("workflow")
        and cross_file.shown == cross_file.total
        and coordinates.shown == coordinates.total
    ):
        return with_rule_labels(payload)

    bounded = {**payload, "files": kept}
    if workflow is not payload.get("workflow"):
        bounded["workflow"] = workflow
    _set_or_drop_cut_list(bounded, "cross_file", cross_file)
    _set_or_drop_cut_list(bounded, "cross_file_coordinates", coordinates)
    bounded["truncated"] = _truncated_block(
        findings=(findings_shown, findings_total),
        files=(len(kept), len(files)),
        cross_file=(cross_file.shown, cross_file.total),
        cross_file_coordinates=(coordinates.shown, coordinates.total),
        workflow_present=workflow_present,
    )
    return with_rule_labels(bounded)


# ---------------------------------------------------------------------------
# remedy_brief — assemble the reply from its already-shaped parts
# ---------------------------------------------------------------------------


def remedy_brief_payload(
    *,
    location: dict[str, Any],
    files: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    relations: list[dict[str, Any]],
    ideal_instruction: list[dict[str, Any]],
    artifact_rules: dict[str, Any] | None,
    preservation_contract: str,
    procedure: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the `remedy_brief` reply from its already-shaped plain-dict parts.

    `artifact_rules` is omitted entirely when no rule names the location's kind — every other
    input rides as given, this function only shapes the envelope. `procedure` is this kind's
    heal procedure: the deterministic line fixes to apply first, then the kind's rules in
    the order to work them.
    """
    out: dict[str, Any] = {
        "location": location,
        "files": files,
        "findings": findings,
        "relations": relations,
        "ideal_instruction": ideal_instruction,
        "preservation_contract": preservation_contract,
        "next": (
            "Apply `procedure.mechanical_fixes` first (every part carries some of them when the "
            "brief pages; each replaces one line's `before` with its "
            "`after`), then rewrite every file of this location whole, working this kind's rules in "
            "`procedure.rules` order, then call validate with path set to each "
            "file's absolute `path` (never its relative `file` name — the healed project may not "
            "be the caller's own working directory); its preservation block says whether the "
            "rewrite kept everything."
        ),
    }
    if procedure is not None:
        out["procedure"] = procedure
    if artifact_rules is not None:
        out["artifact_rules"] = artifact_rules
    return out


# ---------------------------------------------------------------------------
# Rule explanation — readable text for `explain`
# ---------------------------------------------------------------------------


def _join_match_value(val: Any) -> str:
    """A match property's display text: a list joins into one comma-separated string (its
    Python repr otherwise leaked straight into the explain text), a scalar renders as-is."""
    return ", ".join(val) if isinstance(val, list) else str(val)


def _rule_meta_line(rule_data: dict[str, Any]) -> str:
    """The `severity: ... | category: ... | type: ... | scope: ... | <match property>: ...`
    line: severity always renders; `category` and the rule's own `type` render only when the
    caller's `rule_data` sets them (`explain_tool` always does); `match.type` renders as
    `scope:` and every other set match property follows, each list-valued one joined into
    readable text rather than left as a Python list repr."""
    meta = [f"severity: {rule_data.get('severity', 'medium')}"]
    category = rule_data.get("category")
    if category:
        meta.append(f"category: {category}")
    rule_type = rule_data.get("type")
    if rule_type:
        meta.append(f"type: {rule_type}")
    match = rule_data.get("match", {})
    if match and match.get("type"):
        meta.append(f"scope: {_join_match_value(match['type'])}")
    for key, val in (match or {}).items():
        # `type` already rendered above as `scope:`; every other set MATCH_PROPERTIES entry
        # (content_format, loading_verb, link_source_type, ...) is single-sourced from the same
        # `_serialize_match` dict `rules list` emits, so it must not go missing here.
        if key == "type":
            continue
        meta.append(f"{key}: {_join_match_value(val)}")
    return " | ".join(meta)


def _without_title_heading(text: str, title: str) -> str:
    """`text` without its level-1 heading that names `title` (already shown as the title line)."""
    tokens, offset = parse_blocks(text)
    shown = title.lower()
    dropped = {
        line
        for i, tok in enumerate(tokens)
        if tok.type == "heading_open" and tok.tag == "h1" and not tok.level and shown in tokens[i + 1].content.lower()
        for line in range(tok.map[0] + offset, tok.map[1] + offset)
    }
    return "\n".join(line for n, line in enumerate(file_lines(text)) if n not in dropped).strip()


def format_rule(rule_id: str, rule_data: dict[str, Any]) -> str:
    """Format rule explanation as readable text for MCP.

    Unlike validate (which returns structured JSON for agent parsing), explain
    returns human-readable text since its purpose is explanation.
    """
    title = rule_data.get("title", "")

    parts = [f"{rule_id} — {title}", _rule_meta_line(rule_data), ""]

    desc = rule_data.get("description", "")
    if desc:
        body = _without_title_heading(desc.strip(), title)
        if body:
            parts.append(body)
            parts.append("")

    if "examples" in rule_data:
        examples = rule_data["examples"] or {}
        pass_ex, fail_ex = examples.get("pass"), examples.get("fail")
        if not pass_ex and not fail_ex:
            parts.append("Examples: none — this rule has no Pass / Fail examples.")
            parts.append("")
        else:
            parts.append("Examples:")
            if pass_ex:
                parts.append("Pass:")
                parts.append(pass_ex)
            if fail_ex:
                parts.append("Fail:")
                parts.append(fail_ex)
            parts.append("")

    checks = rule_data.get("checks", [])
    if checks:
        parts.append("Checks:")
        parts.extend(f"  {c.get('id', '?')} ({c.get('type', '?')})" for c in checks)

    see_also = rule_data.get("see_also", [])
    if see_also:
        parts.append("")
        parts.append("See also: " + ", ".join(see_also))

    return "\n".join(parts)
