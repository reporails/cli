"""The text view of a `validate` reply: the short, line-per-field summary a Pro account's
`validate` returns in place of the JSON.

`render_text_view(payload)` is pure and deterministic: the same payload gives the same text.
Every line that renders a payload field starts with that field's key path, so instructions
written against the JSON shape find the same names. A section whose field is absent or empty
is left out. A rule id is shown as `Title ([ID](url))` from the reply's `rules` map, or bare
when the map has no entry.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

# The `workflow.locations` block (header plus rows) stays under this many characters.
LOCATIONS_BUDGET = 4000
# A location row names at most this many files, then `+N more`.
_ROW_FILES_SHOWN = 3
# A location's findings and relations sit under its row, indented past the table.
_DETAIL_INDENT = "      "
_REMAINDER_NOTE = "listed in full once earlier rounds re-validate"
_LOCATIONS_HEADER = "workflow.locations: order | kind | element | importance | finding_count | files"
# Preservation keys that are not verdict lists: the summary line and the kept counts own them.
_PRESERVATION_SUMMARY_KEYS = frozenset({"ok", "score_before", "score_after", "introduced", "kept"})


def has_text_view(payload: dict[str, Any], *, full: bool) -> bool:
    """True when the reply is returned as the text view: it carries a `workflow` or a
    `preservation` block and was not asked for in full."""
    return not full and ("workflow" in payload or "preservation" in payload)


def unseen_notices(payload: dict[str, Any], seen: set[str]) -> dict[str, Any]:
    """`payload` without the notices already in `seen`; the ids of the rest are added to `seen`.

    A notice shows once per run: a later view for the same project leaves it out."""
    notices = payload.get("notices")
    if not isinstance(notices, list) or not notices:
        return payload
    fresh = []
    for notice in notices:
        if not isinstance(notice, dict):
            continue
        key = str(notice.get("id") or notice.get("text") or "")
        if key in seen:
            continue
        seen.add(key)
        fresh.append(notice)
    return {**payload, "notices": fresh}


def render_text_view(payload: dict[str, Any]) -> str:
    """The reply as lines of text, one section after another; empty sections are left out."""
    rules = _as_dict(payload.get("rules"))
    sections = (
        _status_lines(payload),
        _compression_lines(payload),
        _offline_lines(payload),
        _notice_lines(payload),
        _surface_lines(payload),
        _workflow_lines(payload, rules),
        _hook_lines(payload),
        _preservation_lines(payload),
        _feedback_lines(payload, rules),
        _truncated_lines(payload),
    )
    return "\n".join(line for section in sections for line in section)


def rule_label(rule_id: str, rules: dict[str, Any]) -> str:
    """`Title ([ID](url))` for a rule the reply's `rules` map names; the bare id otherwise."""
    meta = rules.get(rule_id)
    title = meta.get("title") if isinstance(meta, dict) else ""
    url = meta.get("url") if isinstance(meta, dict) else ""
    if title and url:
        return f"{title} ([{rule_id}]({url}))"
    return f"{title} ({rule_id})" if title else str(rule_id)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dot(*parts: Any) -> str:
    return " · ".join(str(p) for p in parts if p not in (None, ""))


def _status_lines(payload: dict[str, Any]) -> list[str]:
    stats = _as_dict(payload.get("stats"))
    quality = payload.get("quality")
    findings = stats.get("total_findings")
    surfaces = payload.get("surface_health")
    file_count = (
        sum(s.get("file_count", 0) for s in surfaces if isinstance(s, dict)) if isinstance(surfaces, list) else 0
    )
    parts = (
        f"tier {payload['tier']}" if payload.get("tier") else "",
        f"score {quality:.1f}/10" if isinstance(quality, (int, float)) else "",
        f"{findings} findings" if findings is not None else "",
        f"level {payload['level']}" if payload.get("level") else "",
        f"{file_count} files" if file_count else "",
    )
    line = _dot(*parts)
    return [f"validate: {line}"] if line else []


def _compression_lines(payload: dict[str, Any]) -> list[str]:
    comp = payload.get("compression")
    if not isinstance(comp, dict):
        return []
    return [
        f"compression: {comp.get('findings', 0)} findings → {comp.get('locations', 0)} rewrites"
        f" · {comp.get('moves_score', 0)} move your score · {comp.get('cosmetic', 0)} cosmetic"
    ]


def _offline_lines(payload: dict[str, Any]) -> list[str]:
    server_error = payload.get("server_error") if isinstance(payload.get("server_error"), dict) else None
    funnel = payload.get("funnel") if isinstance(payload.get("funnel"), dict) else None
    lines = []
    if payload.get("offline"):
        note = server_error.get("message") if server_error and not funnel else ""
        lines.append(f"offline: true — {note}" if note else "offline: true")
    if server_error:
        lines.append(f"server_error: {_dot(server_error.get('error'), 'status ' + str(server_error.get('status')))}")
        if not funnel and server_error.get("message"):
            lines[-1] += f" — {server_error['message']}"
    if funnel:
        retry = funnel.get("retry_after")
        lines.append(
            _dot(
                f"funnel.retryable: {_flag(funnel.get('retryable'))}",
                f"funnel.retry_after: {retry}" if retry is not None else "",
                funnel.get("message"),
                funnel.get("upgrade_url"),
            )
        )
    return lines


def _flag(value: Any) -> str:
    return "true" if value else "false"


def _notice_lines(payload: dict[str, Any]) -> list[str]:
    notices = [n for n in payload.get("notices") or () if isinstance(n, dict)]
    if not notices:
        return []
    lines = ["notices:"]
    for n in notices:
        url = f" ({n['url']})" if n.get("url") else ""
        lines.append(f"  - {n.get('level', 'info')}: {n.get('text', '')}{url}")
    return lines


def _surface_lines(payload: dict[str, Any]) -> list[str]:
    surfaces = [s for s in payload.get("surface_health") or () if isinstance(s, dict)]
    if not surfaces:
        return []
    return ["surface_health:"] + [
        "  - "
        + _dot(
            s.get("name"),
            f"score {s['score']}" if s.get("score") is not None else "",
            f"{s.get('finding_count', 0)} findings",
            f"{s.get('file_count', 0)} files",
        )
        for s in surfaces
    ]


def _workflow_lines(payload: dict[str, Any], rules: dict[str, Any]) -> list[str]:
    workflow = payload.get("workflow")
    if not isinstance(workflow, dict):
        return []
    lines = []
    if workflow.get("summary"):
        lines.append(f"workflow.summary: {workflow['summary']}")
    targets = workflow.get("targets")
    if isinstance(targets, dict):
        lines.append(
            "workflow.targets: "
            + _dot(
                ", ".join(map(str, targets.get("tokens") or ())),
                f"{targets.get('locations')} of {targets.get('of')} locations",
            )
        )
    locations = [loc for loc in workflow.get("locations") or () if isinstance(loc, dict)]
    lines.extend(locations_block(locations, detail=lambda loc: _detail_lines(loc, rules)))
    lines.extend(_listed_lines(workflow.get("listed"), rules))
    return lines


def _row(loc: dict[str, Any]) -> str:
    files = [str(f) for f in loc.get("files") or ()]
    shown = ", ".join(files[:_ROW_FILES_SHOWN])
    if len(files) > _ROW_FILES_SHOWN:
        shown += f", +{len(files) - _ROW_FILES_SHOWN} more"
    cells = (
        loc.get("order"),
        loc.get("kind"),
        loc.get("element"),
        loc.get("importance"),
        loc.get("finding_count"),
        shown,
    )
    return "  " + " | ".join("" if c is None else str(c) for c in cells)


def _remainder_lines(rest: list[dict[str, Any]]) -> list[str]:
    """One line per kind among the locations left out of the table: how many and which orders."""
    by_kind: dict[str, list[Any]] = {}
    for loc in rest:
        by_kind.setdefault(str(loc.get("kind", "")), []).append(loc.get("order"))
    lines = []
    for kind, orders in by_kind.items():
        numeric = [o for o in orders if isinstance(o, int)]
        span = f" (orders {min(numeric)}\u2013{max(numeric)})" if numeric else ""
        lines.append(f"  {kind}: {len(orders)} locations{span} — {_REMAINDER_NOTE}")
    return lines


def _shown_rows(locations: list[dict[str, Any]], rows: list[str], budget: int) -> int:
    """How many leading rows the table shows: all of them when header and rows fit `budget`,
    otherwise as many as still leave room for a summary line per remaining kind."""

    def size(lines: list[str]) -> int:
        return sum(len(line) + 1 for line in lines)

    if size([_LOCATIONS_HEADER, *rows]) <= budget:
        return len(rows)
    shown = 0
    while shown < len(rows):
        candidate = [_LOCATIONS_HEADER, *rows[: shown + 1], *_remainder_lines(locations[shown + 1 :])]
        if size(candidate) > budget:
            break
        shown += 1
    return shown


def locations_block(
    locations: list[dict[str, Any]],
    budget: int = LOCATIONS_BUDGET,
    detail: Callable[[dict[str, Any]], list[str]] | None = None,
) -> list[str]:
    """The `workflow.locations` header and rows, under `budget` characters.

    Rows go in index order while the table, the next row and a summary line per remaining kind
    still fit; every location left out is summarised per kind. `detail` returns the lines that
    follow a shown row; they sit outside the budget, which governs the index rows only."""
    if not locations:
        return []
    rows = [_row(loc) for loc in locations]
    shown = _shown_rows(locations, rows, budget)
    lines = [_LOCATIONS_HEADER]
    for row, loc in zip(rows[:shown], locations[:shown], strict=True):
        lines.append(row)
        if detail is not None:
            lines.extend(detail(loc))
    return [*lines, *_remainder_lines(locations[shown:])]


def _detail_lines(loc: dict[str, Any], rules: dict[str, Any]) -> list[str]:
    lines = _finding_lines(loc.get("findings"), rules, depth=0)
    for rel in loc.get("relations") or ():
        if not isinstance(rel, dict):
            continue
        head = f"relation {rule_label(str(rel.get('rule', '')), rules)}"
        here = f"{rel.get('file', '')}:{rel.get('line', '')}"
        there = f"{rel.get('partner_file', '')}:{rel.get('partner_line', '')}"
        remedy = f"remedy: {rel['remedy']}" if rel.get("remedy") else ""
        lines.append(_DETAIL_INDENT + "- " + " — ".join(p for p in (f"{head} {here} \u2194 {there}", remedy) if p))
    return lines


def _finding_lines(findings: Any, rules: dict[str, Any], depth: int) -> list[str]:
    lines = []
    for f in findings or ():
        if not isinstance(f, dict):
            continue
        head = " ".join(p for p in (str(f.get("impact_tier") or ""), rule_label(str(f.get("rule", "")), rules)) if p)
        remedy = f"remedy: {f['remedy']}" if f.get("remedy") else ""
        where = f"{head} {f.get('file', '')}:{f.get('line', '')}"
        lines.append(
            _DETAIL_INDENT + "  " * depth + "- " + " — ".join(p for p in (where, f.get("message"), remedy) if p)
        )
        lines.extend(_finding_lines(f.get("members"), rules, depth + 1))
    return lines


def _listed_lines(listed: Any, rules: dict[str, Any]) -> list[str]:
    groups = [g for g in listed or () if isinstance(g, dict)]
    if not groups:
        return []
    lines = ["workflow.listed:"]
    for group in groups:
        entries = "; ".join(
            f"{rule_label(str(r.get('rule', '')), rules)} \u00d7{r.get('count', 0)}"
            for r in group.get("rules") or ()
            if isinstance(r, dict)
        )
        lines.append(f"  - why: {group.get('why', '')}")
        lines.append(f"    rules: {entries}")
    return lines


def _hook_lines(payload: dict[str, Any]) -> list[str]:
    hooks = [h for h in payload.get("host_hooks") or () if isinstance(h, dict)]
    if not hooks:
        return []
    lines = ["host_hooks:"]
    for h in hooks:
        tools = ", ".join(map(str, h.get("tools") or ())) or "none"
        identity = ", ".join(map(str, h.get("identity_fields") or ())) or "none"
        lines.append(
            "  - "
            + _dot(
                h.get("agent"),
                h.get("event"),
                f"matcher {h.get('matcher') or 'any'}",
                h.get("scope"),
                h.get("file"),
                f"tools {tools}",
                f"identity {identity}",
            )
        )
    return lines


def _verdict_present(value: Any) -> bool:
    if isinstance(value, dict):
        return any(value.values())
    return bool(value)


def _preservation_lines(payload: dict[str, Any]) -> list[str]:
    pres = payload.get("preservation")
    if not isinstance(pres, dict):
        return []
    introduced = pres.get("introduced")
    count = introduced if isinstance(introduced, int) and not isinstance(introduced, bool) else 0
    head = (
        f"preservation.ok: {_flag(pres.get('ok'))}",
        f"score_before {pres['score_before']}" if pres.get("score_before") is not None else "",
        f"score_after {pres['score_after']}" if pres.get("score_after") is not None else "",
        f"introduced {count}",
    )
    lines = [_dot(*head)]
    for key, value in pres.items():
        if key not in _PRESERVATION_SUMMARY_KEYS and _verdict_present(value):
            lines.append(f"preservation.{key}: {json.dumps(value, separators=(',', ':'), ensure_ascii=False)}")
    kept = pres.get("kept")
    if isinstance(kept, dict) and kept:
        lines.append("preservation.kept: " + _dot(*(f"{k} {v}" for k, v in kept.items())))
    return lines


def _feedback_lines(payload: dict[str, Any], rules: dict[str, Any]) -> list[str]:
    items = [f for f in payload.get("feedback") or () if isinstance(f, dict)]
    if not items:
        return []
    lines = ["feedback:"]
    for f in items:
        head = " ".join(p for p in (str(f.get("impact_tier") or ""), rule_label(str(f.get("rule", "")), rules)) if p)
        where = f"line {f['line']}" if f.get("line") is not None else ""
        remedy = f"remedy: {f['remedy']}" if f.get("remedy") else ""
        lines.append("  - " + " — ".join(p for p in (f"{head} {where}".strip(), f.get("message"), remedy) if p))
    return lines


def _truncated_lines(payload: dict[str, Any]) -> list[str]:
    truncated = payload.get("truncated")
    hint = truncated.get("hint") if isinstance(truncated, dict) else ""
    return [f"truncated.hint: {hint}"] if hint else []
