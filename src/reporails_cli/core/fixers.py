"""Auto-fixers for deterministic violations.

Each fixer appends a missing section to an instruction file.
All fixers are idempotent — they check for the section before adding it.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from reporails_cli.core.models import Violation


@dataclass(frozen=True)
class FixResult:
    """Outcome of a successful auto-fix."""

    rule_id: str
    file_path: str
    description: str


# Type alias for fixer functions
FixerFn = Callable[[Violation, Path], FixResult | None]


def _resolve_file(violation: Violation, scan_root: Path) -> Path | None:
    """Extract and resolve the file path from a violation location."""
    loc = violation.location
    file_part = loc.rsplit(":", 1)[0] if ":" in loc else loc
    path = Path(file_part)
    if path.is_absolute():
        return path if path.is_file() else None
    resolved = scan_root / path
    return resolved if resolved.is_file() else None


def _ensure_trailing_newline(content: str) -> str:
    """Ensure content ends with exactly one newline before appending."""
    return content.rstrip("\n") + "\n\n"


# ---------------------------------------------------------------------------
# Fixer: CORE:C:0010 — Has Constraints and Pitfalls
# ---------------------------------------------------------------------------


def fix_add_constraints(violation: Violation, scan_root: Path) -> FixResult | None:
    """Add a ## Constraints section if missing."""
    fpath = _resolve_file(violation, scan_root)
    if fpath is None:
        return None

    content = fpath.read_text(encoding="utf-8")
    if re.search(r"(?i)^## (constraint|pitfall|caveat|gotcha)", content, re.MULTILINE):
        return None

    fpath.write_text(
        _ensure_trailing_newline(content) + "## Constraints\n\n- TODO: Add project constraints\n",
        encoding="utf-8",
    )
    rel = _rel_path(fpath, scan_root)
    return FixResult(
        rule_id=violation.rule_id,
        file_path=rel,
        description=f"Added ## Constraints section to {rel}",
    )


# ---------------------------------------------------------------------------
# Fixer: CORE:C:0003 — Has Commands
# ---------------------------------------------------------------------------


def fix_add_commands(violation: Violation, scan_root: Path) -> FixResult | None:
    """Add a ## Commands section with placeholder if missing."""
    fpath = _resolve_file(violation, scan_root)
    if fpath is None:
        return None

    content = fpath.read_text(encoding="utf-8")
    # Rule passes if inline code command or shell prompt exists
    if re.search(r"`[a-z]+ .+`", content) or re.search(r"\$ [a-z]+", content):
        return None

    section = "## Commands\n\n```bash\n# TODO: Add project commands\n```\n"
    fpath.write_text(
        _ensure_trailing_newline(content) + section,
        encoding="utf-8",
    )
    rel = _rel_path(fpath, scan_root)
    return FixResult(
        rule_id=violation.rule_id,
        file_path=rel,
        description=f"Added ## Commands section to {rel}",
    )


# ---------------------------------------------------------------------------
# Fixer: CORE:C:0004 — Has Testing Conventions
# ---------------------------------------------------------------------------


def fix_add_testing(violation: Violation, scan_root: Path) -> FixResult | None:
    """Add a ## Testing section if missing."""
    fpath = _resolve_file(violation, scan_root)
    if fpath is None:
        return None

    content = fpath.read_text(encoding="utf-8")
    if re.search(r"(?i)^## test", content, re.MULTILINE):
        return None
    if re.search(r"(?i)(pytest|jest|vitest|mocha|unittest|rspec)", content):
        return None

    fpath.write_text(
        _ensure_trailing_newline(content) + "## Testing\n\n- TODO: Add test commands and conventions\n",
        encoding="utf-8",
    )
    rel = _rel_path(fpath, scan_root)
    return FixResult(
        rule_id=violation.rule_id,
        file_path=rel,
        description=f"Added ## Testing section to {rel}",
    )


# ---------------------------------------------------------------------------
# Fixer: CORE:C:0015 — Structured Sections
# ---------------------------------------------------------------------------


def fix_add_sections(violation: Violation, scan_root: Path) -> FixResult | None:
    """Add basic ## headings if the file has zero level-2 headings."""
    fpath = _resolve_file(violation, scan_root)
    if fpath is None:
        return None

    content = fpath.read_text(encoding="utf-8")
    if re.search(r"^## ", content, re.MULTILINE):
        return None

    fpath.write_text(
        _ensure_trailing_newline(content) + "## Overview\n\n## Getting Started\n",
        encoding="utf-8",
    )
    rel = _rel_path(fpath, scan_root)
    return FixResult(
        rule_id=violation.rule_id,
        file_path=rel,
        description=f"Added ## Overview and ## Getting Started sections to {rel}",
    )


# ---------------------------------------------------------------------------
# Fixer: CORE:C:0002 — Has Project Structure
# ---------------------------------------------------------------------------


def fix_add_structure(violation: Violation, scan_root: Path) -> FixResult | None:
    """Add a ## Project Structure section if missing."""
    fpath = _resolve_file(violation, scan_root)
    if fpath is None:
        return None

    content = fpath.read_text(encoding="utf-8")
    if re.search(r"(?i)^## (project )?structure", content, re.MULTILINE):
        return None
    if re.search(r"(?i)^## director", content, re.MULTILINE):
        return None
    if re.search(r"src/|tests/|docs/", content):
        return None

    section = "## Project Structure\n\n```\n# TODO: Add project directory layout\n```\n"
    fpath.write_text(
        _ensure_trailing_newline(content) + section,
        encoding="utf-8",
    )
    rel = _rel_path(fpath, scan_root)
    return FixResult(
        rule_id=violation.rule_id,
        file_path=rel,
        description=f"Added ## Project Structure section to {rel}",
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

FIXERS: dict[str, FixerFn] = {
    "CORE:C:0010": fix_add_constraints,
    "CORE:C:0003": fix_add_commands,
    "CORE:C:0004": fix_add_testing,
    "CORE:C:0015": fix_add_sections,
    "CORE:C:0002": fix_add_structure,
}


def apply_auto_fixes(violations: list[Violation], scan_root: Path) -> list[FixResult]:
    """Apply all available auto-fixes. Returns list of successful fixes."""
    results: list[FixResult] = []
    for v in violations:
        fix = apply_single_fix(v, scan_root)
        if fix is not None:
            results.append(fix)
    return results


def apply_single_fix(violation: Violation, scan_root: Path) -> FixResult | None:
    """Apply a single fixer for one violation. Returns None if no fixer or fix failed."""
    fixer = FIXERS.get(violation.rule_id)
    if fixer is None:
        return None
    return fixer(violation, scan_root)


def describe_fix(violation: Violation) -> str | None:
    """Return a human-readable description of what the fixer would do, or None if not fixable."""
    descriptions: dict[str, str] = {
        "CORE:C:0010": "Append a ## Constraints section with placeholder",
        "CORE:C:0003": "Append a ## Commands section with placeholder",
        "CORE:C:0004": "Append a ## Testing section with placeholder",
        "CORE:C:0015": "Append ## Overview and ## Getting Started sections",
        "CORE:C:0002": "Append a ## Project Structure section with placeholder",
    }
    return descriptions.get(violation.rule_id)


def partition_violations(violations: list[Violation]) -> tuple[list[Violation], list[Violation]]:
    """Split violations into (fixable, non_fixable) based on FIXERS registry."""
    fixable: list[Violation] = []
    non_fixable: list[Violation] = []
    for v in violations:
        if v.rule_id in FIXERS:
            fixable.append(v)
        else:
            non_fixable.append(v)
    return fixable, non_fixable


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rel_path(fpath: Path, scan_root: Path) -> str:
    """Return relative path string, falling back to name if outside scan_root."""
    try:
        return str(fpath.relative_to(scan_root))
    except ValueError:
        return fpath.name
