"""The author's sections and the kinds they name, read from the mapper's atoms of a file in order.

A section runs from a heading atom to the next heading atom, so two sections that share a heading
text stay apart. A kind is the words a rewrite puts into an instruction as the thing it covers.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from reporails_cli.core.heal.preservation.words import AtomView
from reporails_cli.core.mapper.classify_lexicon import CONDITION_CONJUNCTIONS, words_of
from reporails_cli.core.mapper.instructions import opens_command
from reporails_cli.core.mapper.lexical import word_forms

# Atoms of a section in file order, its heading atom first when it has one.
Section = list[AtomView]

_SHARED_LEAD = 2  # instructions that open with the same word and name different things


def sections_by_line(by_line: Mapping[int, Sequence[AtomView]]) -> dict[int, Section]:
    """The section each line of the file sits in: a heading atom opens one, and every line up to the
    next heading atom (the heading's own line included) shares it."""
    out: dict[int, Section] = {}
    current: Section = []
    for line in sorted(by_line):
        if any(a.format == "heading" for a in by_line[line]):
            current = []
        current.extend(by_line[line])
        out[line] = current
    return out


def heading_words(section: Section) -> list[str]:
    """The lowered words of the section's heading atom; empty for a section with none."""
    return next((words_of(a.plain_text) for a in section if a.format == "heading"), [])


def lists_kinds(heading: Sequence[str]) -> bool:
    """Whether a heading's words join with `and` / `or` (`Hooks and scripts`): it names several
    kinds, none of them the referent of a line under it."""
    return any(w in CONDITION_CONJUNCTIONS for w in heading)


def _holds(words: list[str], phrase: Sequence[str]) -> bool:
    """Whether `phrase` runs unbroken in `words`, each word in a singular or plural spelling."""
    size = len(phrase)
    return any(all(words[i + k] in word_forms(phrase[k]) for k in range(size)) for i in range(len(words) - size + 1))


def _lists_beside(atom: AtomView, phrase: Sequence[str]) -> bool:
    """Whether `atom` holds `phrase` in a list: it has an `and` / `or` that joins two things (one
    that opens a command of its own, `and push`, joins two actions instead)."""
    tokens = atom.plain_text.split()
    if not _holds([w for t in tokens for w in words_of(t)], phrase):
        return False
    return any(
        words_of(t)[:1]
        and words_of(t)[0] in CONDITION_CONJUNCTIONS
        and not opens_command(" ".join(tokens[k + 1 :]), sequenced=True)
        for k, t in enumerate(tokens)
    )


def named_beside_others(section: Section, own: AtomView, phrase: Sequence[str]) -> bool:
    """Whether another line of the section names `phrase` as one kind among several: in a list, or on
    one of two or more lines that open with the same word and name different things (`Run X against
    Python`, `Run Y against shell scripts`)."""
    siblings = [a for a in section if a.format != "heading" and a.line != own.line]
    if any(_lists_beside(a, phrase) for a in siblings):
        return True
    leads: dict[str, set[str]] = {}
    for a in siblings:
        words = words_of(a.plain_text)
        if len(words) > 1:
            leads.setdefault(words[0], set()).add(words[1])
    return any(
        len(leads.get(words[0], ())) >= _SHARED_LEAD and _holds(words, phrase)
        for words in (words_of(a.plain_text) for a in siblings)
        if words
    )
