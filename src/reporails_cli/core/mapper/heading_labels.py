"""Category-label headings: a heading that sorts a section beside a sibling label gives no instruction.

`## Keep — maintainer-ordered notes` beside `## Partial — docs cover most` groups a file's entries.
Read alone, a label's leading word can sound like an imperative; set beside a sibling label
of the same shape it organizes content. A leading word that is itself an order (`Always`,
`Never`, `Must`, `Avoid`) or text after the dash that gives an instruction (`Never — force-push to main`)
keeps the heading an instruction.
"""

from __future__ import annotations

import re
from collections import defaultdict

from reporails_cli.core.mapper.classify import DIRECTIVE_CUES, classify_charge
from reporails_cli.core.platform.dto.ruleset import Atom

# One leading word, then an em dash, an en dash, a spaced hyphen or a colon; then what follows.
_LABEL_RE = re.compile(r"^([^\W\d_]+)(?:\s*[\u2014\u2013]|\s+-\s|:)(.*)$", re.DOTALL)

# Rule trace of a label heading read neutral because a sibling carries the same shape.
PAIRED_LABEL_RULE = "paired_label_heading"


def is_label_heading(atom: Atom) -> bool:
    """Whether a heading is one leading word set off by a dash or a colon (`Keep — …`) that is
    no order: the word is neither a directive cue nor a prohibition (`Avoid`, `Forbid`) and the
    text after it carries no charge."""
    if atom.kind != "heading":
        return False
    match = _LABEL_RE.match(atom.plain_text or atom.text)
    if match is None or match.group(1).lower() in DIRECTIVE_CUES or atom.charge_value < 0:
        return False
    rest = match.group(2).strip()
    return not rest or classify_charge(rest)[1] == 0


def neutralize_paired_label_headings(atoms: list[Atom]) -> None:
    """Read every label heading with a same-shaped sibling as neutral, in place.

    Siblings share a file, a depth and a parent heading (the nearest earlier heading of a
    shallower depth). Run once every heading charge is final, so no later decode charges
    one back.
    """
    siblings: dict[tuple[str, int, int], list[Atom]] = defaultdict(list)
    stack: list[tuple[int, int]] = []  # (depth, index of the heading) of the open ancestors
    path = ""
    for index, atom in enumerate(atoms):
        if atom.kind != "heading" or atom.depth is None:
            continue
        if atom.file_path != path:
            path, stack = atom.file_path, []
        while stack and stack[-1][0] >= atom.depth:
            stack.pop()
        if is_label_heading(atom):
            siblings[(path, atom.depth, stack[-1][1] if stack else -1)].append(atom)
        stack.append((atom.depth, index))
    for group in siblings.values():
        if len(group) < 2:
            continue
        for atom in group:
            atom.charge, atom.charge_value, atom.modality = "NEUTRAL", 0, "none"
            atom.rule = PAIRED_LABEL_RULE
