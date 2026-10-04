"""Section suggesters for missing-section findings.

Each suggester turns an already-fired finding (constraints, commands, testing,
headings, directory layout) into a `Suggestion` describing where the missing
section belongs and what the rule asks it to hold. The finding that reaches a
suggester already established the section is missing — via the deterministic
pattern check or the content-query atom check that produced it — so a suggester
does not re-derive that from the file text; it only names the fix. Nothing is
written to disk — suggest, don't write.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from reporails_cli.core.discovery.walk import is_under
from reporails_cli.core.platform.dto.models import ClassifiedFile, Rule, Violation


@dataclass(frozen=True)
class Suggestion:
    """A missing section a file's finding points at — not written."""

    rule_id: str
    file_path: str
    section: str
    description: str


# Type alias for suggester functions
SuggesterFn = Callable[
    [Violation, Path, "list[ClassifiedFile] | None", "dict[str, Rule] | None"],
    "Suggestion | None",
]


def _target_file_for_rule(
    rule_id: str,
    scan_root: Path,
    classified_files: list[ClassifiedFile] | None,
    rules: dict[str, Rule] | None,
) -> Path | None:
    """Resolve the file the rule's own `match.type` is about.

    A missing-section suggestion names the file a human would actually add the
    section to — the project's file of the rule's declared type. A rule with no
    type restriction (a project-wide content rule) is a section rule too, so it
    defaults to the project's main instruction file, same as an explicit
    `match: {type: main}` rule. Returns None when the project has no file of
    that type — the caller reports the absence instead of naming an unrelated
    file the finding happened to be pinned to.
    """
    if not classified_files or not rules:
        return None
    rule = rules.get(rule_id)
    match_type = rule.match.type if rule and rule.match else None
    type_names = match_type if isinstance(match_type, list) else [match_type or "main"]
    for type_name in type_names:
        for cf in classified_files:
            if cf.file_type != type_name:
                continue
            try:
                if is_under(cf.path, scan_root):
                    return cf.path
            except (OSError, ValueError):
                continue
    return None


def _absent_target_label(rule_id: str, rules: dict[str, Rule] | None) -> str:
    """Describe the missing target file instead of naming an unrelated one."""
    match_type = None
    if rules is not None:
        rule = rules.get(rule_id)
        match_type = rule.match.type if rule and rule.match else None
    if isinstance(match_type, list):
        match_type = match_type[0] if match_type else None
    label = "main instruction file" if not match_type or match_type == "main" else f"{match_type} file"
    return f"(no {label} in this project)"


# ---------------------------------------------------------------------------
# Suggester: CORE:C:0019 — Explicit Prohibitions
# ---------------------------------------------------------------------------


def suggest_constraints(
    violation: Violation,
    scan_root: Path,
    classified_files: list[ClassifiedFile] | None = None,
    rules: dict[str, Rule] | None = None,
) -> Suggestion | None:
    """Suggest a ## Constraints section for a fired Explicit Prohibitions finding."""
    fpath = _target_file_for_rule(violation.rule_id, scan_root, classified_files, rules)
    file_path = _rel_path(fpath, scan_root) if fpath else _absent_target_label(violation.rule_id, rules)

    return Suggestion(
        rule_id=violation.rule_id,
        file_path=file_path,
        section="## Constraints",
        description="State at least one explicit prohibition — a sentence telling the agent what not to do.",
    )


# ---------------------------------------------------------------------------
# Suggester: CORE:C:0010 — Build And Test Commands
# ---------------------------------------------------------------------------


def suggest_commands(
    violation: Violation,
    scan_root: Path,
    classified_files: list[ClassifiedFile] | None = None,
    rules: dict[str, Rule] | None = None,
) -> Suggestion | None:
    """Suggest a ## Commands section for a fired Build And Test Commands finding."""
    fpath = _target_file_for_rule(violation.rule_id, scan_root, classified_files, rules)
    file_path = _rel_path(fpath, scan_root) if fpath else _absent_target_label(violation.rule_id, rules)

    return Suggestion(
        rule_id=violation.rule_id,
        file_path=file_path,
        section="## Commands",
        description="List the build and test commands the agent can run to verify its own changes.",
    )


# ---------------------------------------------------------------------------
# Suggester: CORE:C:0005 — Testing Framework Documented
# ---------------------------------------------------------------------------


def suggest_testing(
    violation: Violation,
    scan_root: Path,
    classified_files: list[ClassifiedFile] | None = None,
    rules: dict[str, Rule] | None = None,
) -> Suggestion | None:
    """Suggest a ## Testing section for a fired Testing Framework Documented finding."""
    fpath = _target_file_for_rule(violation.rule_id, scan_root, classified_files, rules)
    file_path = _rel_path(fpath, scan_root) if fpath else _absent_target_label(violation.rule_id, rules)

    return Suggestion(
        rule_id=violation.rule_id,
        file_path=file_path,
        section="## Testing",
        description="Document the testing framework — which tool to use, where tests live, and how to run them.",
    )


# ---------------------------------------------------------------------------
# Suggester: CORE:S:0016 — Layered Content Structure
# ---------------------------------------------------------------------------


def suggest_sections(
    violation: Violation,
    scan_root: Path,
    classified_files: list[ClassifiedFile] | None = None,
    rules: dict[str, Rule] | None = None,
) -> Suggestion | None:
    """Suggest top-level headings for a fired Layered Content Structure finding."""
    fpath = _target_file_for_rule(violation.rule_id, scan_root, classified_files, rules)
    file_path = _rel_path(fpath, scan_root) if fpath else _absent_target_label(violation.rule_id, rules)

    return Suggestion(
        rule_id=violation.rule_id,
        file_path=file_path,
        section="Top-level headings (e.g. ## Overview, ## Getting Started)",
        description=(
            "Split the content under at least two top-level headings for its major topics, "
            "so the agent can find a section instead of scanning a flat wall of text."
        ),
    )


# ---------------------------------------------------------------------------
# Suggester: CORE:C:0035 — Directory Layout Documented
# ---------------------------------------------------------------------------


def suggest_structure(
    violation: Violation,
    scan_root: Path,
    classified_files: list[ClassifiedFile] | None = None,
    rules: dict[str, Rule] | None = None,
) -> Suggestion | None:
    """Suggest a ## Project Structure section for a fired Directory Layout Documented finding."""
    fpath = _target_file_for_rule(violation.rule_id, scan_root, classified_files, rules)
    file_path = _rel_path(fpath, scan_root) if fpath else _absent_target_label(violation.rule_id, rules)

    return Suggestion(
        rule_id=violation.rule_id,
        file_path=file_path,
        section="## Project Structure",
        description="Show a directory tree or path references (e.g. src/, tests/) so the agent can place files.",
    )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

SECTION_SUGGESTERS: dict[str, SuggesterFn] = {
    "CORE:C:0019": suggest_constraints,  # Explicit Prohibitions
    "CORE:C:0010": suggest_commands,  # Build And Test Commands
    "CORE:C:0005": suggest_testing,  # Testing Framework Documented
    "CORE:S:0016": suggest_sections,  # Layered Content Structure
    "CORE:C:0035": suggest_structure,  # Directory Layout Documented
}


def suggest_missing_sections(
    violations: list[Violation],
    scan_root: Path,
    classified_files: list[ClassifiedFile] | None = None,
    rules: dict[str, Rule] | None = None,
) -> list[Suggestion]:
    """Collect all available section suggestions. Returns list of suggestions found."""
    results: list[Suggestion] = []
    for v in violations:
        suggestion = suggest_single_section(v, scan_root, classified_files, rules)
        if suggestion is not None:
            results.append(suggestion)
    return results


def suggest_single_section(
    violation: Violation,
    scan_root: Path,
    classified_files: list[ClassifiedFile] | None = None,
    rules: dict[str, Rule] | None = None,
) -> Suggestion | None:
    """Run a single suggester for one violation. Returns None if no suggester is keyed on the rule."""
    suggester = SECTION_SUGGESTERS.get(violation.rule_id)
    if suggester is None:
        return None
    return suggester(violation, scan_root, classified_files, rules)


def partition_violations(violations: list[Violation]) -> tuple[list[Violation], list[Violation]]:
    """Split violations into (suggestible, non_suggestible) based on SECTION_SUGGESTERS registry."""
    suggestible: list[Violation] = []
    non_suggestible: list[Violation] = []
    for v in violations:
        if v.rule_id in SECTION_SUGGESTERS:
            suggestible.append(v)
        else:
            non_suggestible.append(v)
    return suggestible, non_suggestible


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _rel_path(fpath: Path, scan_root: Path) -> str:
    """Return relative path string, falling back to name if outside scan_root."""
    try:
        return fpath.relative_to(scan_root).as_posix()
    except ValueError:
        return fpath.name
