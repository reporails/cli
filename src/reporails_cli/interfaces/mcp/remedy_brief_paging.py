"""Bound a `remedy_brief` reply under the client's per-tool-result output cap, splitting an
oversized brief into numbered parts a caller requests in turn.

An unbounded brief on a large file can exceed the client's cap, with no way for a
shell-less remedy agent to read the rest. The full `ideal_instruction` guide is
static across every location's brief and is never cut to fit — the remedy agent is
pre-allowed only `validate` and `remedy_brief`, so a reference it could not otherwise resolve
(e.g. pointing at `explain`) would make the guide unreachable. Instead the guide (already
close to a whole part's budget on its own, at ~17,000 chars) rides its own dedicated part(s)
after every file part, split by rule entry when it does not fit one part; every part names
which part number(s) carry it (`ideal_instruction_parts`), so the remedy agent can fetch it
directly with `remedy_brief(path, location, part=N)` alone. The location's own fixed fields,
line fixes and `files[]` / `findings` / `relations` come first: a file's own `instructions`,
and the `findings` / `relations` that name it, are split together (never a file's text split
from the findings that address it, and never all dumped onto whichever part first mentions
the file) — a file with many findings is bounded too, not only a `files[]`-many-files
location.
"""

from __future__ import annotations

import json
from typing import Any

# A reply comfortably under the client's per-tool-result output cap. One part's own JSON
# length, `separators=(",", ":")` to match `_result`'s own compact encoding.
_REMEDY_BRIEF_PART_LIMIT = 16_000


def _json_len(obj: Any) -> int:
    return len(json.dumps(obj, separators=(",", ":")))


# One `files_out` entry's piece, plus the slice of the location's `findings` / `relations`
# that ride alongside it — a huge finding count on one huge file is exactly the shape a
# files-only bound misses, so a file's own findings/relations are split the same way its
# `instructions` are, not attached whole to whichever piece happens to introduce the file.
_Piece = tuple[dict[str, Any], list[Any], list[Any]]


def _file_pieces(entry: dict[str, Any], budget: int, findings: list[Any], relations: list[Any]) -> list[_Piece]:
    """One file's brief entry as one or more pieces, each at most `budget` chars of its own
    JSON: whole (with all of `findings` / `relations`) when the entry already fits; otherwise
    its `headings`, `instructions`, `findings` and `relations` are packed in that order, item
    by item, each piece paying for the file's own small fixed fields (`file`, `path`, ...)
    plus the items it holds. A single item too large to fit `budget` on its own still ships
    alone in its own piece — the split bounds parts, never an item's own text."""
    if _json_len(entry) + _json_len(findings) + _json_len(relations) <= budget:
        return [(entry, findings, relations)]
    base = {k: v for k, v in entry.items() if k not in ("instructions", "headings")}
    # Each piece repeats `base` plus its empty `instructions` / `headings` keys.
    room = max(budget - _json_len({**base, "instructions": [], "headings": []}), 1)
    atoms: list[tuple[str, Any]] = [("headings", h) for h in entry.get("headings") or []]
    atoms += [("instructions", i) for i in entry.get("instructions") or []]
    atoms += [("findings", f) for f in findings]
    atoms += [("relations", r) for r in relations]
    groups: list[list[tuple[str, Any]]] = []
    current: list[tuple[str, Any]] = []
    used = 0
    for atom in atoms:
        size = _json_len(atom[1]) + 1  # +1: the comma that joins it to the item before it
        if current and used + size > room:
            groups.append(current)
            current, used = [], 0
        current.append(atom)
        used += size
    if current:
        groups.append(current)
    pieces: list[_Piece] = []
    for group in groups:
        by_kind = {
            kind: [item for k, item in group if k == kind]
            for kind in ("headings", "instructions", "findings", "relations")
        }
        pieces.append(
            (
                {**base, "instructions": by_kind["instructions"], "headings": by_kind["headings"]},
                by_kind["findings"],
                by_kind["relations"],
            )
        )
    return pieces


def _piece_size(piece: _Piece) -> int:
    entry, findings, relations = piece
    # +3: the comma that joins this piece's entry, findings and relations to the ones before it.
    return _json_len(entry) + _json_len(findings) + _json_len(relations) + 3


def _file_pieces_for(
    files_out: list[dict[str, Any]],
    findings_by_file: dict[str, list[Any]],
    relations_by_file: dict[str, list[Any]],
    budget: int,
) -> list[_Piece]:
    """Every file's own pieces (`_file_pieces`), flattened in file order."""
    return [
        piece
        for entry in files_out
        for piece in _file_pieces(
            entry, budget, findings_by_file.get(entry["file"], []), relations_by_file.get(entry["file"], [])
        )
    ]


# One indivisible unit of a part's content: a fixed field of the reply (`("field", (key,
# value))`), one deterministic line fix (`("fix", item)`) or one file piece (`("piece", piece)`),
# with the characters it adds to a part.
_Atom = tuple[str, Any, int]

# Reply keys that are not fixed fields: the location rides every part, the rest are content.
_CONTENT_KEYS = ("location", "files", "findings", "relations", "ideal_instruction", "procedure")


def _content_atoms(
    full: dict[str, Any],
    files_out: list[dict[str, Any]],
    findings_by_file: dict[str, list[Any]],
    relations_by_file: dict[str, list[Any]],
    budget: int,
) -> list[_Atom]:
    """The reply's content as indivisible atoms in packing order: the fixed fields, then each
    `procedure.mechanical_fixes` line fix, then every file piece. The procedure's `rules` ride
    as one fixed field; its line fixes are atoms of their own, so a location with thousands of
    them pages like the files do."""
    atoms: list[_Atom] = []
    procedure = full.get("procedure")
    if not isinstance(procedure, dict):
        procedure = None
    if procedure is not None:
        head = {**procedure, "mechanical_fixes": []}
        atoms.append(("field", ("procedure", head), _json_len({"procedure": head}) + 1))
    atoms.extend(
        ("field", (key, full[key]), _json_len({key: full[key]}) + 1)
        for key in full
        if key not in _CONTENT_KEYS or (key == "procedure" and procedure is None)
    )
    atoms.extend(("fix", fix, _json_len(fix) + 1) for fix in (procedure or {}).get("mechanical_fixes") or [])
    atoms.extend(
        ("piece", piece, _piece_size(piece))
        for piece in _file_pieces_for(files_out, findings_by_file, relations_by_file, budget)
    )
    return atoms


def _paginate_content(atoms: list[_Atom], budget: int) -> list[list[_Atom]]:
    """`atoms` packed in order into parts of at most `budget` chars. An atom larger than
    `budget` on its own opens a part and closes it: it ships alone, uncut."""
    parts: list[list[_Atom]] = []
    current: list[_Atom] = []
    used = 0
    for atom in atoms:
        if current and used + atom[2] > budget:
            parts.append(current)
            current, used = [], 0
        current.append(atom)
        used += atom[2]
    if current or not parts:
        parts.append(current)
    return parts


def _by_file(items: list[Any], known_files: set[str], fallback_file: str | None) -> dict[str, list[Any]]:
    """`items` (findings or relations) grouped by their own `file` key, order preserved within
    each group — `_paginate_files` slices each file's own group across its pieces. An item
    whose `file` is not in `known_files` (a location whose `files` lists a directory carries a
    finding for that directory alongside the directory's real, briefable files) is
    grouped under `fallback_file` instead, so it still rides somewhere rather than being
    silently dropped for having no matching `files[]` entry to page alongside."""
    out: dict[str, list[Any]] = {}
    for item in items:
        key = item.get("file")
        if key not in known_files:
            key = fallback_file
        out.setdefault(key, []).append(item)
    return out


def _unpack_part(group: list[_Atom]) -> dict[str, Any]:
    """One part's reply fields, flattened out of its atoms: the fixed fields it holds, the
    line fixes under `procedure.mechanical_fixes`, and its `files` / `findings` / `relations`."""
    out: dict[str, Any] = {}
    fixes = [item for kind, item, _size in group if kind == "fix"]
    for kind, item, _size in group:
        if kind == "field":
            out[item[0]] = item[1]
    if fixes:
        out["procedure"] = {**out.get("procedure", {}), "mechanical_fixes": fixes}
    pieces = [item for kind, item, _size in group if kind == "piece"]
    out["files"] = [entry for entry, _findings, _relations in pieces]
    out["findings"] = [f for _entry, findings, _relations in pieces for f in findings]
    out["relations"] = [r for _entry, _findings, relations in pieces for r in relations]
    return out


def _guide_groups(guide: list[dict[str, Any]], budget: int) -> list[list[dict[str, Any]]]:
    """The full ideal-instruction guide split into groups under `budget` chars of their own
    JSON, packed by rule entry — the guide is never dropped or referenced elsewhere, only
    split, so it always fully reconstructs across whichever parts carry it."""
    groups: list[list[dict[str, Any]]] = []
    current: list[dict[str, Any]] = []
    used = 0
    for item in guide:
        size = _json_len(item) + 1  # +1: the comma that joins it to the item before it
        if current and used + size > budget:
            groups.append(current)
            current, used = [], 0
        current.append(item)
        used += size
    if current:
        groups.append(current)
    return groups


_EMPTY_CONTENT: dict[str, list[Any]] = {"files": [], "findings": [], "relations": []}


def _part_fields_len(location_out: dict[str, Any]) -> int:
    """The characters every part spends on its own envelope, beyond the file or guide content
    it carries: the location, the empty content keys, and the `part` / `total_parts` /
    `ideal_instruction_parts` / `next_part` fields, sized for three-digit part numbers and up to
    ten guide parts. A part's content is packed into the limit minus this, so the whole part
    stays under the limit."""
    numbers = list(range(990, 1000))
    envelope = {
        "location": location_out,
        **_EMPTY_CONTENT,
        "procedure": {"mechanical_fixes": []},
        "ideal_instruction": [],
        "part": 999,
        "total_parts": 999,
        "ideal_instruction_parts": numbers,
        "next_part": _next_part_note(999, numbers, 999),
    }
    return _json_len(envelope)


def _next_part_note(total_parts: int, guide_part_numbers: list[int], next_part: int) -> str:
    return (
        f"This brief has {total_parts} parts; the ideal-instruction guide is on part(s) "
        f"{guide_part_numbers}; call remedy_brief again with the same path, location and "
        f"targets, and part={next_part}, for the rest — every part's `ideal_instruction`, "
        "`files[]`, `findings`, `relations` and `procedure.mechanical_fixes` together carry the whole brief."
    )


def page_reply(
    full: dict[str, Any], files_out: list[dict[str, Any]], location_out: dict[str, Any], part: int
) -> dict[str, Any]:
    """Slice `full` (the whole, unbounded reply) into numbered parts when it would exceed
    `_REMEDY_BRIEF_PART_LIMIT`, else return it unchanged.

    The content parts come first, packed in order by size: the reply's fixed fields
    (`procedure` with its `rules`, `preservation_contract`, `next`, `artifact_rules`), then the
    deterministic line fixes (`procedure.mechanical_fixes`, one item at a time, so a location
    with thousands of them pages like its files), then the files' pieces. Part 1 therefore
    opens with the fixed fields; a fixed field too large to sit beside the content that
    follows closes its part. `findings` and `relations` are split per file the same way each
    file's own `instructions` and `headings` are (`_file_pieces`), so a file with many
    findings is bounded too, not only a `files[]`-many-files location. No part is empty.

    The full `ideal_instruction` guide (`full["ideal_instruction"]`, `~17,000 chars` on its
    own) trails as its own dedicated part(s) after every file part (`_guide_groups`) — never
    mixed with a file's own content and never cut. Every part names which part number(s)
    carry the guide (`ideal_instruction_parts`), so the remedy agent (pre-allowed only
    `validate` and `remedy_brief`) can fetch it directly with `remedy_brief(path, location,
    part=N)` alone, without needing to page through every file part first. A `part` outside
    `[1, total_parts]` is an `error` reply naming the valid range. Every part, envelope included,
    stays under the limit except one whose single item (an instruction, a heading, a finding, a
    line fix, a guide entry or one fixed field) is larger than the limit on its own: that item ships alone, uncut."""
    guide = full.get("ideal_instruction") or []
    known_files = {entry["file"] for entry in files_out}
    fallback_file = files_out[0]["file"] if files_out else None
    findings_by_file = _by_file(full.get("findings") or [], known_files, fallback_file)
    relations_by_file = _by_file(full.get("relations") or [], known_files, fallback_file)
    budget = max(_REMEDY_BRIEF_PART_LIMIT - _part_fields_len(location_out), 1)

    atoms = _content_atoms(full, files_out, findings_by_file, relations_by_file, budget)
    content_parts = _paginate_content(atoms, budget)
    guide_groups = _guide_groups(guide, budget)
    total_parts = len(content_parts) + len(guide_groups)
    if not 1 <= part <= max(total_parts, 1):
        return {
            "error": "part_out_of_range",
            "message": f"This brief has {total_parts} part(s); ask for a part from 1 to {total_parts}.",
        }
    if total_parts <= 1:
        return full

    guide_part_numbers = list(range(len(content_parts) + 1, total_parts + 1))
    index = part - 1
    if index < len(content_parts):
        reply = {"location": location_out, **_unpack_part(content_parts[index]), "ideal_instruction": []}
    else:
        guide_index = index - len(content_parts)
        reply = {"location": location_out, "ideal_instruction": guide_groups[guide_index], **_EMPTY_CONTENT}

    reply["part"] = index + 1
    reply["total_parts"] = total_parts
    reply["ideal_instruction_parts"] = guide_part_numbers
    if index + 1 < total_parts:
        reply["next_part"] = _next_part_note(total_parts, guide_part_numbers, index + 2)
    return reply
