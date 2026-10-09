"""Structure in the preservation check: table rows, list items, headings, fenced blocks and
links a rewrite removed, list items it moved to another list, a constraint it detached from the
directive it limited, a bare negative heading it relabelled, and lines it padded with copies of
lines the file already has. Blocks come from the mapper's reading of the markdown
(`DocumentStructure`), never from the text itself.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections import Counter
from collections.abc import Sequence
from typing import Any

from reporails_cli.core.heal.preservation.conditions import by_line
from reporails_cli.core.heal.preservation.match import pair_score
from reporails_cli.core.heal.preservation.snapshot import SnapshotAtom
from reporails_cli.core.heal.preservation.words import content_words
from reporails_cli.core.platform.dto.structure import DocumentStructure


def _live(pairs: tuple[tuple[int, Any], ...], relation_lines: frozenset[int]) -> list[Any]:
    """The values of `pairs` whose line is not one a relation names as a true duplicate."""
    return [value for line, value in pairs if line not in relation_lines]


def _row_keys(rows: tuple[tuple[int, str], ...], relation_lines: frozenset[int]) -> list[str]:
    """The key of each table row not on a relation-allowed line: its first cell's words, case and
    spacing folded. A row whose first cell is empty has no key and is left out."""
    return [key for line, cell in rows if line not in relation_lines and (key := "".join(cell.split()).lower())]


def _fence_key(body: str) -> str:
    """A fenced block's body with its whitespace normalized."""
    return " ".join(body.split())


def _sections(structure: DocumentStructure, line: int) -> int:
    """The section `line` sits in: the count of headings at or before it."""
    return bisect_right(structure.headings, line)


def _removed_multiset(before: list[str], after: list[str]) -> int:
    """How many occurrences from the `before` multiset are missing from `after`."""
    return sum((Counter(before) - Counter(after)).values())


def _label(text: str) -> str:
    """A heading's label: case and punctuation folded."""
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", "", text.lower())).strip()


def relabelled_negative_headings(
    before_text: str, before_headings: list[Any], after_heading_texts: list[str]
) -> list[dict[str, Any]]:
    """Each bare negative heading (`## Don'ts`) of the snapshot with no heading of the same label
    left in the rewrite — at any level, in any case, in any markdown style the mapper reads
    (`#`, underlined, inside a quote). Its items are prohibitions because of that label, so a
    renamed heading weakens every one of them. `before_headings` are the snapshot's heading atoms
    (relation-allowed lines already dropped); an entry's `text` is the heading's line as written."""
    kept = Counter(_label(text) for text in after_heading_texts)
    lines = before_text.split("\n")
    out: list[dict[str, Any]] = []
    for atom in before_headings:
        label = _label(atom.text)
        if kept[label] > 0:
            kept[label] -= 1
        else:
            out.append(
                {"line": atom.line, "text": lines[atom.line - 1].strip() if atom.line <= len(lines) else atom.text}
            )
    return out


def removed_structure(
    before: DocumentStructure,
    after: DocumentStructure,
    relation_lines: frozenset[int],
    imports: tuple[Sequence[str], Sequence[str]],
) -> dict[str, int]:
    """The `removed_structure` block: table rows / list items / headings / fences / links the
    snapshot had that the current text no longer does. Relation-allowed lines are dropped from
    the "before" side first, so an allowed deletion never counts as a loss. `imports` holds the `@import`
    references written in the snapshot's text and in the current text: one dropped is a lost import."""
    return {
        "table_rows": _removed_multiset(
            _row_keys(before.table_rows, relation_lines), _row_keys(after.table_rows, frozenset())
        ),
        "list_items": max(0, len(_live(before.list_items, relation_lines)) - len(after.list_items)),
        "headings": max(0, len([n for n in before.headings if n not in relation_lines]) - len(after.headings)),
        "fences": _removed_multiset(
            [_fence_key(b) for b in _live(before.fences, relation_lines)], [_fence_key(b) for _n, b in after.fences]
        ),
        "links": _removed_multiset(_live(before.links, relation_lines), [t for _n, t in after.links]),
        "imports": _removed_multiset(list(imports[0]), list(imports[1])),
    }


def structure_totals(
    before: DocumentStructure, relation_lines: frozenset[int], imports: Sequence[str]
) -> dict[str, int]:
    """The snapshot's OWN structure counts - table rows / list items / headings / fences /
    links - with relation-allowed lines excluded first, the same filtering `removed_structure`
    applies to its "before" side. Exposed separately so `kept` (total minus removed) never
    re-derives what the snapshot originally had from the removal count alone."""
    return {
        "table_rows": len(_row_keys(before.table_rows, relation_lines)),
        "list_items": len(_live(before.list_items, relation_lines)),
        "headings": len([n for n in before.headings if n not in relation_lines]),
        "fences": len(_live(before.fences, relation_lines)),
        "links": len(_live(before.links, relation_lines)),
        "imports": len(imports),
    }


def _is_detached(p_match: Any, d_match: Any, blocks: dict[int, int]) -> bool:
    """Whether the matched prohibition lands neither in the matched directive's block nor in
    the block right after it — detached means apart, not merely a different (adjacent) block."""
    d_block, p_block = blocks.get(d_match.line), blocks.get(p_match.line)
    return d_block is not None and p_block is not None and p_block not in (d_block, d_block + 1)


def detached_constraints(
    snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Any], new_structure: DocumentStructure
) -> list[dict[str, Any]]:
    """A snapshot prohibition that shared its line with a directive, now detached from it."""
    blocks = new_structure.block_of
    out: list[dict[str, Any]] = []
    for atoms_here in by_line(snap_atoms).values():
        prohibitions = [a for a in atoms_here if a.charge_value == -1]
        directives = [a for a in atoms_here if a.charge_value == 1]
        for p in prohibitions:
            p_match = matched_new_for.get(id(p))
            if p_match is None:
                continue
            for d in directives:
                d_match = matched_new_for.get(id(d))
                if d_match is not None and _is_detached(p_match, d_match, blocks):
                    out.append({"line": p.line, "text": p.text})
                    break
    return out


def _list_landing(atom: SnapshotAtom, matched_new_for: dict[int, Any], new_groups: dict[int, int]) -> int | None:
    """The new list-group id `atom`'s match lands in, or `None` when it has no match."""
    match = matched_new_for.get(id(atom))
    return new_groups.get(match.line) if match is not None else None


def _home_group(
    members: list[SnapshotAtom], landings: dict[int, int | None], section: int | None, group_section: dict[int, int]
) -> int | None:
    """The new list a split snapshot list still lives in — `None` when its matched members all
    land in one list (nothing moved) or fewer than two carry a match. The home is the landing
    list in the snapshot list's own section, the one holding most members when several are;
    with none there, the landing list holding most members, ties to the earliest member's."""
    dests = [dest for m in members if (dest := landings[id(m)]) is not None]
    if len(dests) < 2 or len(set(dests)) < 2:
        return None
    counts = Counter(dests)
    in_section = [d for d in counts if group_section.get(d) == section]
    pool = in_section or list(counts)
    return max(pool, key=lambda d: (counts[d], -dests.index(d)))


def _moved_off_home(
    members: list[SnapshotAtom], landings: dict[int, int | None], home: int, new_by_group: dict[int, list[Any]]
) -> list[dict[str, Any]]:
    """The members whose match landed outside `home` while `home` holds no qualifying candidate
    for them — a near-duplicate the one-to-one assignment paired with its twin in another list
    still has its counterpart at home, so it did not move."""
    return [
        {"line": sa.line, "text": sa.text}
        for sa in members
        if landings[id(sa)] not in (None, home)
        and not any(pair_score(sa, na) is not None for na in new_by_group.get(home, ()))
    ]


def moved_list_items(
    snap_atoms: list[SnapshotAtom],
    matched_new_for: dict[int, Any],
    snapshot_structure: DocumentStructure,
    new_structure: DocumentStructure,
    new_atoms: list[Any],
) -> list[dict[str, Any]]:
    """A snapshot list item whose matched new atom lands outside the list its own list still
    lives in — a rewrite that moved a bullet out of its list into another one, even though a
    straight instruction/count compare reads it as kept. List membership is the contiguous list
    block a line sits in (`DocumentStructure.list_items`), never its marker glyph, so a list moved whole (or two
    sections swapping) is not split and not flagged, and a marker corrected to match the block it
    already sits in is not either. A split list's home is anchored to its own section, so the
    item that stayed is never the one reported."""
    new_groups = dict(new_structure.list_items)
    group_section = {group: _sections(new_structure, line) for line, group in new_groups.items()}
    new_by_group = _by_list(new_atoms, new_groups)
    out: list[dict[str, Any]] = []
    for members in _by_list(snap_atoms, dict(snapshot_structure.list_items)).values():
        landings = {id(m): _list_landing(m, matched_new_for, new_groups) for m in members}
        home = _home_group(members, landings, _sections(snapshot_structure, members[0].line), group_section)
        if home is not None:
            out.extend(_moved_off_home(members, landings, home, new_by_group))
    return out


def _by_list(atoms: list[Any], groups: dict[int, int]) -> dict[int, list[Any]]:
    """`atoms` bucketed by the list group their line sits in; an atom outside any list is left out."""
    out: dict[int, list[Any]] = {}
    for atom in atoms:
        group = groups.get(atom.line)
        if group is not None:
            out.setdefault(group, []).append(atom)
    return out


_DUPLICATE_MIN_WORDS = 2  # an atom with fewer content words is never a duplicate
_DUPLICATE_DIFFERENCE = 0.2  # share of two atoms' joint words they may differ in and still be copies
_BODY_FORMATS = frozenset({"prose", "list", "numbered"})


def _near_copy(a: set[str], b: set[str]) -> bool:
    return len(a ^ b) <= max(1, int(_DUPLICATE_DIFFERENCE * len(a | b)))


def _duplicates(atoms: list[Any]) -> list[Any]:
    """Each prose / list atom that copies (word for word, or all but a word in five) an atom before it."""
    bodies = [
        (a, w)
        for a in atoms
        if a.format in _BODY_FORMATS and len(w := content_words(a.plain_text)) >= _DUPLICATE_MIN_WORDS
    ]
    return [a for i, (a, words) in enumerate(bodies) if any(_near_copy(words, earlier) for _a, earlier in bodies[:i])]


def padded_lines(old_atoms: list[Any], new_atoms: list[Any]) -> list[dict[str, Any]]:
    """The atoms a rewrite added that copy an atom the file already has — the rewrite carries more
    copies than the original did; the last ones are listed."""
    extra = len(_duplicates(new_atoms)) - len(_duplicates(old_atoms))
    return [{"line": a.line, "text": a.text} for a in _duplicates(new_atoms)[-extra:]] if extra > 0 else []
