"""Client-side checks — run locally on RulesetMap atoms.

Five checks: unformatted code tokens, bold on directives,
broad scope terms, charge ordering, orphan atoms.
"""

from __future__ import annotations

import re

from reporails_cli.core.mapper.mapper import Atom, RulesetMap
from reporails_cli.core.models import LocalFinding

_BOLD_TERM_RE = re.compile(r"\*\*([^*]+)\*\*")
_BOLD_NEGATION_RE = re.compile(
    r"^(?:NEVER|ALWAYS|MUST|CRITICAL|IMPORTANT|DO NOT|NOT|WARNING|NOTE|NO)\b",
    re.IGNORECASE,
)
# Bold spans followed by ":" are structural labels, not emphasis
_BOLD_LABEL_RE = re.compile(r"\*\*[^*]+\*\*\s*:")

_SCOPE_RE = re.compile(
    r"^(?:when|if|unless|before|after)\s+(.+?),\s+",
    re.IGNORECASE,
)
_BROAD_SCOPE_WORDS = {
    "external",
    "third-party",
    "services",
    "dependencies",
    "integrations",
    "components",
    "any",
    "all",
}

_SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}


def run_client_checks(ruleset_map: RulesetMap) -> list[LocalFinding]:
    """Run D-level client checks on a RulesetMap.

    Returns findings sorted by severity then line number. File paths
    are normalized to project-relative display paths.
    """
    findings: list[LocalFinding] = []

    # Group atoms by file for filepath context
    atoms_by_file: dict[str, list[Atom]] = {}
    for atom in ruleset_map.atoms:
        atoms_by_file.setdefault(atom.file_path, []).append(atom)

    for filepath, atoms in atoms_by_file.items():
        display = _relative_display_path(filepath)
        findings.extend(_check_file(atoms, display))

    findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.line))
    return findings


def _relative_display_path(file_path: str) -> str:
    """Normalize file path for display. Uses merger's normalize_finding_path."""
    from reporails_cli.core.merger import normalize_finding_path

    return normalize_finding_path(file_path)


def _check_file(atoms: list[Atom], filepath: str) -> list[LocalFinding]:
    """Run all D-level checks on atoms from a single file."""
    findings: list[LocalFinding] = []
    charged = [a for a in atoms if a.charge_value != 0]

    findings.extend(_check_unformatted_code(atoms, filepath))
    findings.extend(_check_heading_instructions(atoms, filepath))
    findings.extend(_check_bold_patterns(charged, filepath))
    findings.extend(_check_broad_scope(charged, filepath))
    findings.extend(_check_ordering_and_orphans(charged, filepath))

    return findings


def _check_unformatted_code(atoms: list[Atom], filepath: str) -> list[LocalFinding]:
    """Check for code tokens missing backtick formatting."""
    return [
        LocalFinding(
            file=filepath,
            line=a.line,
            severity="warning",
            rule="format",
            message=f"'{code_tok}' should be in backticks — use `{code_tok}`",
            fix=f"Wrap in backticks: `{code_tok}`",
            source="client_check",
        )
        for a in atoms
        for code_tok in a.unformatted_code
    ]


def _check_heading_instructions(atoms: list[Atom], filepath: str) -> list[LocalFinding]:
    """Check for instructions placed in headings instead of body text."""
    return [
        LocalFinding(
            file=filepath,
            line=a.line,
            severity="info",
            rule="heading_instruction",
            message=(
                f'Instruction in heading: "{a.text[:50]}" — '
                f"headings should organize content, not carry instructions. "
                f"Move the instruction to the section body."
            ),
            fix="Use the heading as a section label and put the instruction in the first line of the section.",
            source="client_check",
        )
        for a in atoms
        if a.kind == "heading" and a.charge_value != 0
    ]


def _check_bold_patterns(charged: list[Atom], filepath: str) -> list[LocalFinding]:
    """Check for harmful bold emphasis on directive atoms."""
    findings: list[LocalFinding] = []
    for a in charged:
        bold_spans = _BOLD_TERM_RE.findall(a.text)
        if not bold_spans:
            continue
        # Skip structural labels: **Term**: (bold followed by colon)
        if _BOLD_LABEL_RE.search(a.text):
            continue
        harmful_terms: list[str] = []
        for span in bold_spans:
            if _BOLD_NEGATION_RE.match(span):
                continue
            if span.strip().rstrip(".!") == a.text.strip().lstrip("*").rstrip("*").strip().rstrip(".!"):
                continue
            harmful_terms.append(span)
        if not harmful_terms:
            continue
        terms_str = ", ".join(f"**{t}**" for t in harmful_terms[:3])
        if a.charge_value == +1:
            findings.append(
                LocalFinding(
                    file=filepath,
                    line=a.line,
                    severity="info",
                    rule="bold",
                    message=(
                        f"Bold on terms: {terms_str}. "
                        f"Bold competes for attention between instructions — "
                        f"use `backtick` or *italic* instead."
                    ),
                    fix="Use `backtick` for code tokens or *italic* for emphasis.",
                    source="client_check",
                )
            )
    return findings


def _check_broad_scope(charged: list[Atom], filepath: str) -> list[LocalFinding]:
    """Check for overly broad conditional scope terms."""
    findings: list[LocalFinding] = []
    for a in charged:
        if not a.scope_conditional:
            continue
        m = _SCOPE_RE.match(a.text)
        if not m:
            continue
        scope_text = m.group(1).lower()
        broad_matches = [w for w in _BROAD_SCOPE_WORDS if w in scope_text]
        if broad_matches:
            findings.append(
                LocalFinding(
                    file=filepath,
                    line=a.line,
                    severity="warning",
                    rule="scope",
                    message=(
                        f'Broad conditional scope: "{m.group(1)}". '
                        f"Broad terms ({', '.join(broad_matches)}) may trigger unintended behavior."
                    ),
                    fix="Name the specific situation instead of using broad terms, or remove the condition.",
                    source="client_check",
                )
            )
    return findings


def _check_ordering_and_orphans(charged: list[Atom], filepath: str) -> list[LocalFinding]:
    """Check charge ordering within clusters and detect orphan constraints."""
    findings: list[LocalFinding] = []

    clusters: dict[int, list[Atom]] = {}
    for a in charged:
        if a.cluster_id >= 0:
            clusters.setdefault(a.cluster_id, []).append(a)

    for cluster_atoms in clusters.values():
        directives = [a for a in cluster_atoms if a.charge_value == +1]
        constraints = [a for a in cluster_atoms if a.charge_value == -1]

        if directives and constraints:
            first_dir = min(directives, key=lambda a: a.position_index)
            first_con = min(constraints, key=lambda a: a.position_index)
            if first_con.position_index < first_dir.position_index:
                findings.append(
                    LocalFinding(
                        file=filepath,
                        line=first_con.line,
                        severity="warning",
                        rule="ordering",
                        message=(
                            f"Prohibition at L{first_con.line} comes before "
                            f"directive at L{first_dir.line} — the model follows "
                            f"instructions better when you state what TO do first, "
                            f"then what NOT to do."
                        ),
                        fix="Reorder: directive first, reasoning in between, prohibition last.",
                        source="client_check",
                    )
                )
        # Directives-only is valid — the golden pattern (+1, 0, -1) only
        # requires a prohibition when there's a behavior to suppress.
        # "Use ruff" stands alone. Only flag constraints-only (missing directive).
        elif constraints:
            rep = min(constraints, key=lambda a: a.position_index)
            findings.append(
                LocalFinding(
                    file=filepath,
                    line=rep.line,
                    severity="info",
                    rule="orphan",
                    message=(
                        f"{len(constraints)} prohibition(s) with no matching directive on this topic. "
                        f"Adding a 'do this instead' counterpart strengthens compliance."
                    ),
                    fix="Add a related directive before the prohibition(s).",
                    source="client_check",
                )
            )

    return findings
