"""Content-quality queries on RulesetMap atoms.

Replaces deterministic regex checks for content presence/absence rules.
Each query inspects the mapper's AST-derived atoms — no regex on raw text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from reporails_cli.core.mapper.mapper import Atom, RulesetMap


@dataclass(frozen=True)
class QueryResult:
    """Result of a content query against RulesetMap atoms."""

    found: bool
    file: str = ""
    line: int = 0
    evidence: str = ""


def _atoms_for_file(rm: RulesetMap, file_path: str) -> list[Atom]:
    """Get atoms belonging to a specific file."""
    return [a for a in rm.atoms if a.file_path.endswith(file_path) or file_path in a.file_path]


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
    atoms = _atoms_for_file(rm, file_path)
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
    atoms = _atoms_for_file(rm, file_path)
    for a in atoms:
        if a.kind == "heading" and pattern.search(a.text):
            return QueryResult(True, file_path, a.line, f"Matched heading: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_code_blocks(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has code block content."""
    atoms = _atoms_for_file(rm, file_path)
    for a in atoms:
        if a.format == "code_block":
            return QueryResult(True, file_path, a.line, "Code block found")
    return QueryResult(False, file_path)


def has_layered_structure(rm: RulesetMap, file_path: str, **args: Any) -> QueryResult:
    """Check if file has top-level heading structure (content layering)."""
    min_headings = args.get("min_headings", 2)
    atoms = _atoms_for_file(rm, file_path)
    top_headings = [a for a in atoms if a.kind == "heading" and a.depth is not None and a.depth <= 2]
    if len(top_headings) >= min_headings:
        return QueryResult(True, file_path, top_headings[0].line, f"{len(top_headings)} top-level headings")
    return QueryResult(False, file_path)


def has_named_tokens_matching(rm: RulesetMap, file_path: str, **args: Any) -> QueryResult:
    """Check if file atoms contain any of the specified named tokens."""
    tokens = set(args.get("tokens", []))
    if not tokens:
        return QueryResult(False, file_path)
    atoms = _atoms_for_file(rm, file_path)
    for a in atoms:
        overlap = tokens & {t.lower() for t in a.named_tokens}
        if overlap:
            return QueryResult(True, file_path, a.line, f"Named tokens: {', '.join(list(overlap)[:3])}")
    return QueryResult(False, file_path)


def has_constraint_atoms(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has constraint atoms (charge_value == -1)."""
    atoms = _atoms_for_file(rm, file_path)
    for a in atoms:
        if a.charge_value == -1:
            return QueryResult(True, file_path, a.line, f"Constraint: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_directive_atoms(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has directive atoms (charge_value == +1)."""
    atoms = _atoms_for_file(rm, file_path)
    for a in atoms:
        if a.charge_value == +1:
            return QueryResult(True, file_path, a.line, f"Directive: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_role_definition(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file defines an agent role ('you are', 'your role', role: anchor)."""
    atoms = _atoms_for_file(rm, file_path)
    for a in atoms:
        lower = (a.plain_text or a.text).lower()
        if "you are" in lower or "your role" in lower or a.role == "anchor":
            return QueryResult(True, file_path, a.line, f"Role definition: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_valid_markdown(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has any parsed atoms (valid markdown that produced content)."""
    atoms = _atoms_for_file(rm, file_path)
    if atoms:
        return QueryResult(True, file_path, atoms[0].line, f"{len(atoms)} atoms parsed")
    return QueryResult(False, file_path)


def has_frontmatter_field(rm: RulesetMap, file_path: str, **args: Any) -> QueryResult:
    """Check if the file record has specific frontmatter-derived fields."""
    field_name = args.get("field", "")
    for fr in rm.files:
        if fr.path.endswith(file_path) or file_path in fr.path:
            if field_name == "scope" and fr.scope != "global":
                return QueryResult(True, file_path, 1, f"scope={fr.scope}")
            if field_name == "globs" and fr.globs:
                return QueryResult(True, file_path, 1, f"globs={fr.globs}")
    return QueryResult(False, file_path)


def has_non_italic_constraints(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has constraint atoms not fully wrapped in *italic*.

    Returns found=True when a constraint (-1) exists without full-sentence italic,
    meaning the rule is violated (expect: absent to flag as violation).
    """
    atoms = _atoms_for_file(rm, file_path)
    for a in atoms:
        if a.charge_value != -1 or a.kind == "heading":
            continue
        content = a.text.strip()
        # Strip leading list markers
        for prefix in ("- ", "* "):
            if content.startswith(prefix):
                content = content[len(prefix) :].strip()
                break
        if re.match(r"^\d+\.\s", content):
            content = re.sub(r"^\d+\.\s+", "", content).strip()
        # Full-sentence italic: starts and ends with single * (not **)
        if content.startswith("*") and content.endswith("*") and not content.startswith("**"):
            continue
        return QueryResult(True, file_path, a.line, f"Constraint not italic: {a.text[:60]}")
    return QueryResult(False, file_path)


def has_mermaid_blocks(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has mermaid code blocks (```mermaid)."""
    atoms = _atoms_for_file(rm, file_path)
    for a in atoms:
        if a.format == "code_block" and "mermaid" in a.named_tokens:
            return QueryResult(True, file_path, a.line, "Mermaid block found")
    return QueryResult(False, file_path)


def has_branching_steps(rm: RulesetMap, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has numbered list items with conditional/branching language."""
    atoms = _atoms_for_file(rm, file_path)
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


def has_charged_headings(rm: Any, file_path: str, **_args: Any) -> QueryResult:
    """Check if file has heading atoms with charge (instructions in headings)."""
    for a in rm.atoms:
        if a.file_path != file_path:
            continue
        if a.kind == "heading" and a.charge_value != 0:
            return QueryResult(True, file_path, a.line, f"Charged heading: {a.text[:60]}")
    return QueryResult(False, file_path)


# ──────────────────────────────────────────────────────────────────
# REGISTRY — maps query names to functions
# ──────────────────────────────────────────────────────────────────

QUERY_REGISTRY: dict[str, Any] = {
    "has_headings": has_headings,
    "has_heading_matching": has_heading_matching,
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
