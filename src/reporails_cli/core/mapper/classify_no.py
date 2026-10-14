"""Reading of the `No <noun phrase>` opener for the rule-based charge classifier.

Tells a prohibition (`No console.log`) from a status report (`No open issues`) and from
a description (`No X is Y`).
"""

from __future__ import annotations

# "No X is/are/was/were Y" — descriptive, not a prohibition. Shared by the
# Phase 1 prohibition guard and the map-validation must_constraint check.
DESCRIPTIVE_NO_COPULAS = frozenset({"is", "are", "was", "were", "has", "have", "does", "did"})


def starts_descriptive_no(lowers: list[str]) -> bool:
    """True for a descriptive `No X is/are Y` opener (not a prohibition)."""
    return bool(lowers) and lowers[0] == "no" and any(v in DESCRIPTIVE_NO_COPULAS for v in lowers[1:8])


# A `No …` opener is a determiner only in front of a noun phrase. These followers
# turn it into an adverbial or a pronoun (`no longer used`, `no matter what`), so
# the line is neither a status report nor a prohibition of the `No <NP>` kind.
_NO_ADVERBIAL_FOLLOWERS = frozenset({"longer", "matter", "more", "less", "doubt", "one", "other", "such"})

# A prohibition scopes itself with a LOCATIONAL preposition — it names the place
# the rule binds (`in code`, `between sections`, `on the main branch`, `at the
# boundary`). Every other preposition / subordinator describes an absence instead
# (`No support for Windows`, `No plans for v2`, `No context unless configured`),
# so this is the set that disqualifies the prohibition reading.
NO_DESCRIPTIVE_PREPS = frozenset(
    {
        "for",
        "of",
        "about",
        "with",
        "without",
        "by",
        "to",
        "from",
        "unless",
        "when",
        "while",
        "except",
        "after",
        "before",
        "during",
        "beyond",
        "near",
        "around",
        "since",
        "per",
    }
)


# The noun phrases a `No <NP>` STATUS report names. A status line reports a count
# or a verdict; anything else a two-word `No <NP>` names is the forbidden thing
# itself (`No console.log`, `No blank lines`), so the status reading is a closed
# vocabulary rather than a shape rule.
_NO_STATUS_PHRASES = frozenset(
    {
        "open issues",
        "known issues",
        "open questions",
        "issues found",
        "issues remain",
        "priority action items",
        "action items",
        "action required",
        "action needed",
        "further action",
        "change needed",
        "changes needed",
        "change required",
        "changes required",
        "setup required",
        "setup needed",
        "drift detected",
        "cloud dependencies",
    }
)
_NO_STATUS_PHRASE_MAX_WORDS = max(len(p.split()) for p in _NO_STATUS_PHRASES)

# Adverbs that date a statement — a line reporting what is absent *so far* reports,
# it does not forbid (`No data in this table yet`).
_NO_STATUS_ADVERBS = ("yet", "currently", "so far", "right now", "at the moment", "for now", "at present", "to date")

# Nouns that merely end in `-ed`; the inflection read below would take them for a
# participle and mistake the clause for a report.
_ED_NOUNS = frozenset({"speed", "breed", "creed", "tweed", "steed", "embed"})

# A terse prohibition is a short verbless clause; past that length the line is prose.
_NO_PROHIBITION_MAX_WORDS = 10


def starts_bare_no_status(lowers: list[str]) -> bool:
    """True for a `No <noun phrase>` STATUS line — not a prohibition.

    A status line reports a count or a verdict and stops (`No regressions.`,
    `No changes.`, `None.`, `No open issues`, `No drift detected on the tracked
    dimensions`). A prohibition written with the same opener names the thing it
    forbids (`No console.log`, `No hardcoded secrets`, `No blank lines`), and that
    naming takes at least two words — so the one-word form is the status shape
    itself, and past one word the line only reports when it names one of the
    status phrases in `_NO_STATUS_PHRASES`.
    """
    if not lowers or lowers[0] not in ("no", "none"):
        return False
    rest = lowers[1:]
    if not rest:
        return True  # a bare "None." / "No."
    if rest[0] in _NO_ADVERBIAL_FOLLOWERS:
        return False
    if len(rest) == 1:
        return True  # `No regressions.` / `No changes.` — the bare count
    return any(" ".join(rest[:n]) in _NO_STATUS_PHRASES for n in range(2, _NO_STATUS_PHRASE_MAX_WORDS + 1))


def _carries_status_adverb(lowers: list[str]) -> bool:
    """True when the clause dates its own statement (`… yet`, `… so far`)."""
    joined = f" {' '.join(lowers)} "
    return any(f" {adverb} " in joined for adverb in _NO_STATUS_ADVERBS)


def is_terse_no_prohibition(lowers: list[str]) -> bool:
    """True for a verbless `No <noun phrase>` prohibition.

    The positive side of :func:`starts_bare_no_status`: a short clause that names a
    forbidden thing, with or without the place it is forbidden in
    (`No console.log`, `No hardcoded secrets in code`, `No blank lines between
    sections`).

    Three shapes are excluded because they describe an absence instead of forbidding
    a thing: a non-locational preposition, which names what is missing rather than
    where a rule binds (`No support for Windows`, `No plans for v2`); a dating adverb
    (`No data in this table yet`); and a predicate — a copula
    (:func:`starts_descriptive_no`) or a past participle past the attributive slot,
    which turns the line into a report (`No new CSS classes introduced`, `No rule
    existed to verify file scope`). The one word directly after `No` is the head
    noun's own modifier (`No hardcoded secrets`), so it is never read as the verb.
    """
    if len(lowers) < 3 or lowers[0] != "no" or len(lowers) > _NO_PROHIBITION_MAX_WORDS:
        return False
    if lowers[1] in _NO_ADVERBIAL_FOLLOWERS:
        return False
    if (
        starts_descriptive_no(lowers)
        or starts_bare_no_status(lowers)
        or _carries_status_adverb(lowers)
        or any(w in NO_DESCRIPTIVE_PREPS for w in lowers[1:])
    ):
        return False
    return not any(_is_past_participle(w) for w in lowers[2:])


def _is_past_participle(word: str) -> bool:
    """True for an `-ed` form that reads as a clause's verb, not as a noun."""
    return word.endswith("ed") and len(word) > 4 and word not in _ED_NOUNS
