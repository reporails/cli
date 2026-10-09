"""The plain sentence for each reason a finding is listed instead of rewritten.

A reply names a reason by code; the words come from here. Each sentence says what leaving
the finding means and what the maintainer can do about it.
"""

from __future__ import annotations

_LISTED_REASONS = {
    "convention": (
        "A documentation convention: leaving it changes nothing the agent loads. Fix it by hand if you want it tidy."
    ),
    "unbacked": (
        "No measured effect backs this rule yet, so it is listed rather than ordered. Fix it by hand if you "
        "agree with it."
    ),
    "size": (
        "The loaded size already counts in full, so trimming further is your call. Cut by hand if you want it shorter."
    ),
    "project": (
        "A fact about the project outside the instruction files. Change it in the project if you want it gone."
    ),
    "no-remedy": ("No rewrite exists for this rule yet. Fix it by hand, or leave it as it stands."),
    "no-gain": (
        "Fixing it is not expected to raise the score. Fix it by hand when you next edit the line, or leave it."
    ),
    "lowers-score": (
        "Applying the rewrite is expected to lower the score of the file it edits. Keep it as it stands, or "
        "rework it by hand."
    ),
    "heading-instruction": (
        "A heading written as an instruction is often a section label. Reword it by hand if it is not one, "
        "moving the instruction into the section body word for word first."
    ),
    "default-competition": ("The rewrites of the instructions it concerns fix it, so it is listed for context only."),
    "no-lever": (
        "Nothing on the weaker side of this topic can be strengthened further. Leave it, or restructure the "
        "topic by hand."
    ),
    "balance-fragment": (
        "Every instruction on the weaker side shares its line with another instruction, so no single-line "
        "rewrite is offered. Give each its own line by hand if you want it rewritten."
    ),
    "line-fragment": (
        "This instruction shares its line with another instruction, so no single-line rewrite is offered. "
        "Give it its own line by hand if you want it rewritten."
    ),
    "balance-no-clear": (
        "A rewrite would still leave the weaker side far weaker than the other, so none is offered. Rework "
        "the topic by hand, or leave it."
    ),
    "dilution-model-dependent": (
        "Trimming the surrounding prose is your call. Cut what only restates the instruction, or leave it as it stands."
    ),
    "leave-it": (
        "The only fix would change what the line says, so none is ordered. Edit the line by hand if you want "
        "it changed."
    ),
    "at-ceiling": (
        "Every file here already scores the maximum, so a rewrite cannot raise it. Leave it, or tidy it by hand."
    ),
    "dilution-no-lever": (
        "Nothing around this instruction is safe to trim. Leave it, or restructure the file by hand."
    ),
    "dilution-uncuttable": (
        "What surrounds this instruction is list items, table rows or code, or the file's opening paragraph, "
        "so nothing is safe to trim. Leave it, or restructure by hand."
    ),
    "config-file": (
        "Settings, hook and MCP config files are not rewritten for you. Review the finding and edit the file by hand."
    ),
    "no-co-load": (
        "These two files never load together, so neither copy crowds the other; keep both or move the line "
        "to a file both folders load."
    ),
    "excluded": (
        "The file is in `heal_exclude` in your `.ails/config.yml`: it is still checked and scored, "
        "and heal does not rewrite it. Remove it from the list to have it rewritten."
    ),
}

_FALLBACK = "This finding is listed rather than rewritten for you. Fix it by hand, or leave it as it stands."


def listed_reason_text(code: str) -> str:
    """The sentence for a listed reason code; a neutral one for a code the cli does not know."""
    return _LISTED_REASONS.get(code, _FALLBACK)
