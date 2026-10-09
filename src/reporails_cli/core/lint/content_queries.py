"""Content-quality queries on RulesetMap atoms.

Replaces deterministic regex checks for content presence/absence rules.
Each query inspects the mapper's AST-derived atoms — no regex on raw text.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace
from typing import Any

from reporails_cli.core.mapper.md_parser import wrapping_runs
from reporails_cli.core.platform.dto.ruleset import LIST_OBJECT_ROLE, Atom, RulesetMap
from reporails_cli.core.platform.policy.negative_headings import is_negative_heading


@dataclass(frozen=True)
class QueryResult:
    """Result of a content query against RulesetMap atoms."""

    found: bool
    file: str = ""
    line: int = 0
    evidence: str = ""
    # Every match in the file, in line order, for a query that reports each one; the result
    # itself then stands for the first. Empty for a query that reports one match.
    matches: tuple[QueryResult, ...] = ()


def _every_match(file_path: str, found: list[QueryResult]) -> QueryResult:
    """One result carrying every match: found at the first, with the whole list in `matches`."""
    if not found:
        return QueryResult(False, file_path)
    return replace(found[0], matches=tuple(found))


def _norm_key(path: str) -> str:
    """Normalize a file path to the exact key used to group atoms/records by file.

    Both `Atom.file_path` and `FileRecord.path` originate from the same
    RulesetMap, so an exact key (leading `./` stripped) matches a file's atoms
    without the substring bleed that let one file's key match another's path.
    """
    return path[2:] if path.startswith("./") else path


def atoms_for_file(rm: RulesetMap, file_path: str) -> list[Atom]:
    """Get atoms belonging to a specific file (exact normalized path match)."""
    key = _norm_key(file_path)
    return [a for a in rm.atoms if _norm_key(a.file_path) == key]


def own_atoms(atoms: Iterable[Atom]) -> list[Atom]:
    """The atoms written in the file itself: an atom an `@import` brings in sits on the `@` line and is not in
    the file's text."""
    return [a for a in atoms if not a.imported_from]


def own_atoms_for_file(rm: RulesetMap, file_path: str) -> list[Atom]:
    """`atoms_for_file` without the atoms an `@import` brings in."""
    return own_atoms(atoms_for_file(rm, file_path))


def instruction_atoms_for_file(rm: RulesetMap, file_path: str, *, own: bool = False) -> list[Atom]:
    """`file_path`'s atoms without the list items read as an instruction's object
    (`LIST_OBJECT_ROLE`), which take no place of their own among the file's instructions; `own` also leaves
    out the atoms an `@import` brings in."""
    atoms = own_atoms_for_file(rm, file_path) if own else atoms_for_file(rm, file_path)
    return [a for a in atoms if a.role != LIST_OBJECT_ROLE]


def _all_file_paths(rm: RulesetMap) -> set[str]:
    """Get unique file paths from RulesetMap."""
    return {fr.path for fr in rm.files}


# ──────────────────────────────────────────────────────────────────
# QUERY FUNCTIONS
# Each takes (rm, file_path, **args) and returns QueryResult.
# file_path scopes the query to a single file's atoms.
# ──────────────────────────────────────────────────────────────────


def has_headings(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has any markdown headings."""
    atoms = atoms_for_file(rm, file_path)
    for a in atoms:
        if a.kind == "heading":
            return QueryResult(True, file_path, a.line, f"Heading: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_heading_matching(rm: RulesetMap, file_path: str, **args: Any) -> QueryResult:
    """Check if file has a heading matching any of the given terms."""
    terms = args.get("terms", [])
    if not terms:
        return QueryResult(False, file_path)
    pattern = re.compile("|".join(re.escape(t) for t in terms), re.IGNORECASE)
    atoms = atoms_for_file(rm, file_path)
    for a in atoms:
        if a.kind == "heading" and pattern.search(a.text):
            return QueryResult(True, file_path, a.line, f"Matched heading: {a.text[:60]}")
    return QueryResult(False, file_path)


# A lead block is description-shaped when it is uncharged prose, a blockquote, or a list
# of at least this many words — long enough to say what the project is.
_LEAD_FORMATS = frozenset({"prose", "blockquote", "list"})
_LEAD_MIN_TOKENS = 5


def has_project_description(rm: RulesetMap, file_path: str, **args: Any) -> QueryResult:
    """Check if file describes the project: a matching heading, or a lead block under the title.

    The lead block is the content under the title, up to the first second-level (or deeper)
    heading or the first instruction. It counts when a descriptive prose, blockquote, or list
    atom there carries at least `_LEAD_MIN_TOKENS` words — the sentence under `# Project` that
    says what it is. An instruction-shaped (ambiguous) sentence is not a description.
    """
    by_heading = has_heading_matching(rm, file_path, **args)
    if by_heading.found:
        return by_heading
    for a in sorted(atoms_for_file(rm, file_path), key=lambda a: a.line):
        if a.kind == "heading":
            if a.depth is not None and a.depth >= 2:
                break
            continue
        if a.charge_value != 0:
            break
        if a.charge == "AMBIGUOUS":
            continue
        if a.format in _LEAD_FORMATS and a.token_count >= _LEAD_MIN_TOKENS:
            return QueryResult(True, file_path, a.line, f"Lead description: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_code_blocks(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has code block content."""
    atoms = atoms_for_file(rm, file_path)
    for a in atoms:
        if a.format == "code_block":
            return QueryResult(True, file_path, a.line, "Code block found")
    return QueryResult(False, file_path)


def has_layered_structure(rm: RulesetMap, file_path: str, **args: Any) -> QueryResult:
    """Check if file has top-level heading structure (content layering)."""
    min_headings = args.get("min_headings", 2)
    atoms = atoms_for_file(rm, file_path)
    top_headings = [a for a in atoms if a.kind == "heading" and a.depth is not None and a.depth <= 2]
    if len(top_headings) >= min_headings:
        return QueryResult(True, file_path, top_headings[0].line, f"{len(top_headings)} top-level headings")
    return QueryResult(False, file_path)


def has_named_tokens_matching(rm: RulesetMap, file_path: str, **args: Any) -> QueryResult:
    """Check if file atoms contain any of the specified named tokens."""
    tokens = set(args.get("tokens", []))
    if not tokens:
        return QueryResult(False, file_path)
    atoms = atoms_for_file(rm, file_path)
    for a in atoms:
        overlap = tokens & {t.lower() for t in a.named_tokens}
        if overlap:
            return QueryResult(True, file_path, a.line, f"Named tokens: {', '.join(list(overlap)[:3])}")
    return QueryResult(False, file_path)


def has_constraint_atoms(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has constraint atoms (charge_value == -1)."""
    atoms = atoms_for_file(rm, file_path)
    for a in atoms:
        if a.charge_value == -1:
            return QueryResult(True, file_path, a.line, f"Constraint: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_directive_atoms(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has directive atoms (charge_value == +1)."""
    atoms = atoms_for_file(rm, file_path)
    for a in atoms:
        if a.charge_value == +1:
            return QueryResult(True, file_path, a.line, f"Directive: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_role_definition(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file defines an agent role ('you are', 'your role', role: anchor)."""
    atoms = atoms_for_file(rm, file_path)
    for a in atoms:
        lower = (a.plain_text or a.text).lower()
        if "you are" in lower or "your role" in lower or a.role == "anchor":
            return QueryResult(True, file_path, a.line, f"Role definition: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_valid_markdown(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has any parsed atoms (valid markdown that produced content)."""
    atoms = atoms_for_file(rm, file_path)
    if atoms:
        return QueryResult(True, file_path, atoms[0].line, f"{len(atoms)} atoms parsed")
    return QueryResult(False, file_path)


def has_frontmatter_field(rm: RulesetMap, file_path: str, **args: Any) -> QueryResult:
    """Check if the file record has specific frontmatter-derived fields."""
    field_name = args.get("field", "")
    key = _norm_key(file_path)
    for fr in rm.files:
        if _norm_key(fr.path) != key:
            continue
        if field_name == "scope" and fr.scope != "global":
            return QueryResult(True, file_path, 1, f"scope={fr.scope}")
        if field_name == "globs" and fr.globs:
            return QueryResult(True, file_path, 1, f"globs={fr.globs}")
    return QueryResult(False, file_path)


def has_non_italic_constraints(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has constraint atoms not fully wrapped in *italic*.

    Returns found=True when a constraint (-1) exists without full-sentence italic,
    meaning the rule is violated (expect: absent to flag as violation). Every such
    constraint is a match.
    """
    atoms = atoms_for_file(rm, file_path)
    found: list[QueryResult] = []
    for a in atoms:
        # A `code_block` atom (a fence-cascade directive) carries LITERAL markdown:
        # its `*`/`**` are text inside a fence, not rendered italic/bold, so an
        # italic-wrapping appearance check must not fire on it. The charge count
        # (`has_constraint_atoms`) still sees it — only this appearance read skips.
        if a.charge_value != -1 or a.kind == "heading" or a.format == "code_block":
            continue
        # Full-sentence italic: an italic run covers the whole text
        if any(not run.strong for run in wrapping_runs(a.text)):
            continue
        found.append(QueryResult(True, file_path, a.line, f"Constraint not italic: {a.text[:60]}"))
    return _every_match(file_path, found)


def has_mermaid_blocks(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has mermaid code blocks (```mermaid)."""
    atoms = atoms_for_file(rm, file_path)
    for a in atoms:
        if a.format == "code_block" and "mermaid" in a.named_tokens:
            return QueryResult(True, file_path, a.line, "Mermaid block found")
    return QueryResult(False, file_path)


def has_branching_steps(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has numbered list items with conditional/branching language."""
    atoms = atoms_for_file(rm, file_path)
    numbered_count = 0
    branching = False
    for a in atoms:
        if a.format == "numbered":
            numbered_count += 1
            if a.scope_conditional:
                branching = True
    if numbered_count >= 3 and branching:
        return QueryResult(True, file_path, 0, f"{numbered_count} numbered steps with branching")
    return QueryResult(False, file_path)


def has_charged_headings(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has heading atoms with charge (instructions in headings). Every one is a match;
    its evidence is the heading text. A bare negative heading (`## Don'ts`) labels a list of
    prohibitions and is not a match."""
    return _every_match(
        file_path,
        [
            QueryResult(True, file_path, a.line, a.text[:50])
            for a in atoms_for_file(rm, file_path)
            if a.kind == "heading" and a.charge_value != 0 and not is_negative_heading(a.text)
        ],
    )


# ──────────────────────────────────────────────────────────────────
# REGISTRY — maps query names to functions
# ──────────────────────────────────────────────────────────────────

QUERY_REGISTRY: dict[str, Any] = {
    "has_headings": has_headings,
    "has_heading_matching": has_heading_matching,
    "has_project_description": has_project_description,
    "has_code_blocks": has_code_blocks,
    "has_layered_structure": has_layered_structure,
    "has_named_tokens_matching": has_named_tokens_matching,
    "has_constraint_atoms": has_constraint_atoms,
    "has_directive_atoms": has_directive_atoms,
    "has_role_definition": has_role_definition,
    "has_valid_markdown": has_valid_markdown,
    "has_frontmatter_field": has_frontmatter_field,
    "has_charged_headings": has_charged_headings,
    "has_non_italic_constraints": has_non_italic_constraints,
    "has_mermaid_blocks": has_mermaid_blocks,
    "has_branching_steps": has_branching_steps,
}
