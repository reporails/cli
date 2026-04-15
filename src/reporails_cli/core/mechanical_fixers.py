"""Mechanical fixers for atom-level instruction quality issues.

Each fixer reads raw file content, locates atoms by line number, and
performs surgical text transformations. All fixers are idempotent —
running twice produces no changes on the second run.

Application order per file: format → bold → italic_constraint → ordering.
Within each fixer, edits are applied bottom-to-top by line number to
preserve line number stability for subsequent edits.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from reporails_cli.core.mapper.mapper import Atom, RulesetMap


@dataclass(frozen=True)
class MechanicalFix:
    """Outcome of a mechanical fix applied to raw file content."""

    fix_type: str  # format | bold | italic_constraint | ordering
    file_path: str
    line: int
    description: str
    before: str
    after: str


# ──────────────────────────────────────────────────────────────────
# Fix 1: Unformatted code → backticks
# ──────────────────────────────────────────────────────────────────

_BACKTICK_RE = re.compile(r"`[^`]+`")


def _is_inside_backticks(text: str, token: str) -> bool:
    """Check if every occurrence of token in text is inside backtick spans."""
    stripped = _BACKTICK_RE.sub("", text)
    return token not in stripped


def fix_unformatted_code(atoms: list[Atom], lines: list[str]) -> list[MechanicalFix]:
    """Wrap unformatted code tokens in backticks."""
    fixes: list[MechanicalFix] = []
    for atom in atoms:
        if not atom.unformatted_code:
            continue
        idx = atom.line - 1
        if idx < 0 or idx >= len(lines):
            continue
        original = lines[idx]
        modified = original
        for token in atom.unformatted_code:
            if _is_inside_backticks(modified, token):
                continue
            # Replace the first non-backticked occurrence
            # Use word boundary to avoid partial matches
            pattern = re.compile(r"(?<!`)(?<![`\w])" + re.escape(token) + r"(?![`\w])(?!`)")
            replacement = f"`{token}`"
            modified, count = pattern.subn(replacement, modified, count=1)
            if count == 0:
                # Fallback: simple replacement for tokens at word boundaries
                modified = modified.replace(token, f"`{token}`", 1)
        if modified != original:
            lines[idx] = modified
            fixes.append(
                MechanicalFix(
                    fix_type="format",
                    file_path=atom.file_path,
                    line=atom.line,
                    description="Wrapped code tokens in backticks",
                    before=original.rstrip(),
                    after=modified.rstrip(),
                )
            )
    return fixes


# ──────────────────────────────────────────────────────────────────
# Fix 2: Bold on constraints → italic
# ──────────────────────────────────────────────────────────────────

_BOLD_TERM_RE = re.compile(r"\*\*([^*]+)\*\*")
_BOLD_LABEL_RE = re.compile(r"\*\*[^*]+\*\*\s*:")
_BOLD_NEGATION_RE = re.compile(
    r"^(?:NEVER|ALWAYS|MUST|CRITICAL|IMPORTANT|DO NOT|NOT|WARNING|NOTE|NO)\b",
    re.IGNORECASE,
)


def fix_bold_on_constraints(atoms: list[Atom], lines: list[str]) -> list[MechanicalFix]:
    """Replace **term** with *term* on constraint atoms (charge_value == -1)."""
    fixes: list[MechanicalFix] = []
    for atom in atoms:
        if atom.charge_value != -1:
            continue
        idx = atom.line - 1
        if idx < 0 or idx >= len(lines):
            continue
        original = lines[idx]
        # Skip structural labels (**Label**:)
        if _BOLD_LABEL_RE.search(original):
            continue

        modified = original
        for match in _BOLD_TERM_RE.finditer(original):
            term = match.group(1)
            # Skip negation keywords (they're emphasis, not competition)
            if _BOLD_NEGATION_RE.match(term):
                continue
            # Replace **term** with *term*
            modified = modified.replace(f"**{term}**", f"*{term}*", 1)

        if modified != original:
            lines[idx] = modified
            fixes.append(
                MechanicalFix(
                    fix_type="bold",
                    file_path=atom.file_path,
                    line=atom.line,
                    description="Replaced bold with italic on constraint",
                    before=original.rstrip(),
                    after=modified.rstrip(),
                )
            )
    return fixes


# ──────────────────────────────────────────────────────────────────
# Fix 3: Non-italic constraints → wrap in *...*
# ──────────────────────────────────────────────────────────────────

_LIST_MARKER_RE = re.compile(r"^(\s*(?:[-*+]|\d+[.)]) )")
_ITALIC_WRAP_RE = re.compile(r"^\*[^*].*[^*]\*$")


def fix_italic_constraints(atoms: list[Atom], lines: list[str]) -> list[MechanicalFix]:
    """Wrap constraint atoms (charge_value == -1) in full-sentence italic."""
    fixes: list[MechanicalFix] = []
    for atom in atoms:
        if atom.charge_value != -1:
            continue
        if atom.kind == "heading":
            continue
        idx = atom.line - 1
        if idx < 0 or idx >= len(lines):
            continue
        original = lines[idx]
        content = original.rstrip()

        # Extract list marker prefix if present
        marker_match = _LIST_MARKER_RE.match(content)
        prefix = marker_match.group(1) if marker_match else ""
        body = content[len(prefix) :]

        # Already fully wrapped in italic?
        stripped = body.strip()
        if _ITALIC_WRAP_RE.match(stripped):
            continue
        # Already starts with * and ends with * (might be partial)
        if stripped.startswith("*") and stripped.endswith("*") and not stripped.startswith("**"):
            continue
        # Contains an italic-wrapped constraint portion (e.g., "text. *Do NOT X.*")
        # Wrapping the whole line would nest italic markers and break markdown.
        if re.search(r"(?<!\*)\*[^*]+\*(?!\*)", stripped):
            continue

        # Wrap the body in italic
        wrapped = prefix + "*" + body.strip() + "*"
        lines[idx] = wrapped + "\n" if original.endswith("\n") else wrapped

        fixes.append(
            MechanicalFix(
                fix_type="italic_constraint",
                file_path=atom.file_path,
                line=atom.line,
                description="Wrapped constraint in full-sentence italic",
                before=original.rstrip(),
                after=wrapped,
            )
        )
    return fixes


# ──────────────────────────────────────────────────────────────────
# Fix 4: Charge ordering — constraint before directive → swap
# ──────────────────────────────────────────────────────────────────


def fix_ordering(atoms: list[Atom], lines: list[str]) -> list[MechanicalFix]:
    """Within each cluster, swap constraint-before-directive to directive-first."""
    fixes: list[MechanicalFix] = []

    # Group charged atoms by cluster_id
    clusters: dict[int, list[Atom]] = {}
    for a in atoms:
        if a.charge_value != 0 and a.cluster_id >= 0:
            clusters.setdefault(a.cluster_id, []).append(a)

    for cluster_atoms in clusters.values():
        directives = [a for a in cluster_atoms if a.charge_value == +1]
        constraints = [a for a in cluster_atoms if a.charge_value == -1]
        if not directives or not constraints:
            continue

        first_dir = min(directives, key=lambda a: a.position_index)
        first_con = min(constraints, key=lambda a: a.position_index)
        if first_con.position_index >= first_dir.position_index:
            continue

        # Only swap single-line atoms
        con_idx = first_con.line - 1
        dir_idx = first_dir.line - 1
        if con_idx < 0 or dir_idx < 0 or con_idx >= len(lines) or dir_idx >= len(lines):
            continue
        # Don't swap across large distances (> 10 lines)
        if abs(dir_idx - con_idx) > 10:
            continue

        # Swap the lines
        lines[con_idx], lines[dir_idx] = lines[dir_idx], lines[con_idx]
        fixes.append(
            MechanicalFix(
                fix_type="ordering",
                file_path=first_con.file_path,
                line=first_con.line,
                description=f"Swapped constraint (L{first_con.line}) with directive (L{first_dir.line})",
                before=f"L{first_con.line}: constraint, L{first_dir.line}: directive",
                after=f"L{first_con.line}: directive, L{first_dir.line}: constraint",
            )
        )
    return fixes


# ──────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────


def apply_mechanical_fixes(
    ruleset_map: RulesetMap,
    scan_root: Path,  # noqa: ARG001
    *,
    dry_run: bool = False,
    fix_types: set[str] | None = None,
) -> list[MechanicalFix]:
    """Apply all mechanical fixes to files in the ruleset map.

    Returns the list of fixes applied. When dry_run is True, computes
    fixes but does not write files.
    """
    all_fixes: list[MechanicalFix] = []

    # Group atoms by file
    atoms_by_file: dict[str, list[Atom]] = {}
    for atom in ruleset_map.atoms:
        atoms_by_file.setdefault(atom.file_path, []).append(atom)

    allowed = fix_types or {"format", "bold", "italic_constraint", "ordering"}

    for file_path, atoms in atoms_by_file.items():
        path = Path(file_path)
        if not path.is_file():
            continue

        content = path.read_text(encoding="utf-8")
        lines = content.splitlines(keepends=True)
        file_fixes: list[MechanicalFix] = []

        # Apply in order: format → bold → italic_constraint → ordering
        if "format" in allowed:
            file_fixes.extend(fix_unformatted_code(atoms, lines))
        if "bold" in allowed:
            file_fixes.extend(fix_bold_on_constraints(atoms, lines))
        if "italic_constraint" in allowed:
            file_fixes.extend(fix_italic_constraints(atoms, lines))
        if "ordering" in allowed:
            file_fixes.extend(fix_ordering(atoms, lines))

        if file_fixes and not dry_run:
            path.write_text("".join(lines), encoding="utf-8")

        all_fixes.extend(file_fixes)

    return all_fixes
