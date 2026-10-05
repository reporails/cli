"""Named constructs in the preservation check: which backticked construct a rewrite lost, which
it invented (named by nothing in the file, no path on disk, no program the machine or the
project's manifests know), which it repeats beyond what its instructions account for, and which
a prohibition now bans or no longer bans.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from typing import Any

from reporails_cli.core.heal.preservation.snapshot import SnapshotAtom
from reporails_cli.core.heal.preservation.words import content_words, named_key
from reporails_cli.core.platform.contract.environment import ProjectEnvironment


def token_present(inner: str, text: str) -> bool:
    """Whether `inner` (a named token's inner text) occurs in `text` as a whole word — never
    as a bare substring of a longer word (`main` inside `maintain`). A backtick is not a word
    character, so `` `main` `` and `` `main -q` `` both match on the word boundary alone."""
    return re.search(rf"(?<!\w){re.escape(inner)}(?!\w)", text) is not None


def _token_inners(atoms: Sequence[Any]) -> set[str]:
    """The inner text (backticks stripped) of every named token of `atoms`."""
    return {tok.strip("`") for a in atoms for tok in getattr(a, "named_tokens", None) or ()}


def lost_named_tokens(snap_atoms: list[SnapshotAtom], new_text: str, new_atoms: Sequence[Any] = ()) -> list[str]:
    """Every named token (backtick span) of any snapshot atom whose inner text is present in
    neither the new file text (as a whole token) nor the named tokens of any new atom, once
    each, in first-seen order."""
    new_inners = _token_inners(new_atoms)
    lost: list[str] = []
    for sa in snap_atoms:
        for tok in sa.named_tokens:
            inner = tok.strip("`")
            if inner and inner not in new_inners and not token_present(inner, new_text) and tok not in lost:
                lost.append(tok)
    return lost


def mentions(inner: str, text: str) -> int:
    """How often `inner` occurs in `text` as a mention of its own — not joined to a longer
    name. Not preceded by a word character or `/ . : -` (so `category` does not count inside
    `/check-category`, `foo-category`, `a/category`, or `x.category.py`), and not followed by
    a word character, `/`, `-`, or a `.`/`:` that is itself followed by a word character
    (`skills:foo` and `x.md` still exclude `category`; a sentence-ending colon or period still
    ends a mention). A construct ending in `/` (a directory, e.g. `docs/`) is a different,
    longer path when a path continuation follows its trailing slash — a word character, `<`,
    `{`, `[`, `*`, `~`, `-`, or a `.`/`:` followed by a word character (`docs/guides/x.md`,
    `` docs/<area>/ ``) — so such a construct counts everywhere else instead (`docs/,`,
    `(docs/)`, a sentence-ending `docs/.`, a backtick, whitespace, or the text's end)."""
    after = r"(?![\w<{\[*~-]|[.:]\w)" if inner.endswith("/") else r"(?![\w/-]|[.:]\w)"
    return len(re.findall(rf"(?<![\w/.:-]){re.escape(inner)}{after}", text))


def _unnamed_counterparts(
    snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Any], split_covering_for: dict[int, list[Any]]
) -> set[int]:
    """`id()`s of every new atom that stands in for an originally-unnamed snapshot instruction
    — its direct match, or every atom in the split window that covers it — `repeated_named`'s
    credit-eligible set for the vague-instruction-concretized allowance."""
    was_unnamed = {id(match) for sa in snap_atoms if not sa.named_tokens if (match := matched_new_for.get(id(sa)))}
    for sa in snap_atoms:
        if not sa.named_tokens:
            was_unnamed.update(id(na) for na in split_covering_for.get(id(sa), ()))
    return was_unnamed


def _flag_overruns(
    order: list[str], allowance: Counter[str], original_text: str, new_text: str
) -> list[dict[str, Any]]:
    """`order`'s tokens (first-seen), each flagged when its new-text mention count exceeds
    `allowance` plus its original mention count. Each entry is `{token, before, after, allowed}`."""
    out: list[dict[str, Any]] = []
    for inner in dict.fromkeys(order):
        before, after = mentions(inner, original_text), mentions(inner, new_text)
        allowed = before + allowance[inner]
        if after > allowed:
            out.append({"token": f"`{inner}`", "before": before, "after": after, "allowed": allowed})
    return out


def repeated_named(
    snap_atoms: list[SnapshotAtom],
    new_atoms: list[Any],
    matched_new_for: dict[int, Any],
    split_covering_for: dict[int, list[Any]],
    original_text: str,
    new_text: str,
) -> list[dict[str, Any]]:
    """Every construct the file already names that the rewrite mentions more often than the
    original did, beyond one extra mention per instruction that names it — an instruction the
    original names it in, or one that named nothing before the rewrite and now names it (a
    vague instruction naming what it means, including one split across several new
    instructions — every new atom in its `split_covering_for` window counts as its counterpart,
    same as a single direct match would). Anything past that repeats a construct the file
    already names. Each entry is `{token, before, after, allowed}`, in first-seen order."""
    allowance: Counter[str] = Counter()
    order: list[str] = []
    for sa in snap_atoms:
        for inner in dict.fromkeys(t.strip("`") for t in sa.named_tokens):
            if inner:
                allowance[inner] += sa.charge_value != 0
                order.append(inner)
    was_unnamed = _unnamed_counterparts(snap_atoms, matched_new_for, split_covering_for)
    for na in new_atoms:
        for inner in dict.fromkeys(t.strip("`") for t in getattr(na, "named_tokens", None) or ()):
            if inner and token_present(inner, original_text):
                order.append(inner)
                allowance[inner] += id(na) in was_unnamed and na.charge_value != 0
    return _flag_overruns(order, allowance, original_text, new_text)


_GLOB_CHARS = frozenset("*?[]")


def token_present_ci(inner: str, text: str) -> bool:
    """Whole-word, case-insensitive occurrence of `inner` in `text` — an invented-token check
    compares the rewrite's own casing against the snapshot's, never demanding an exact match."""
    return re.search(rf"(?<!\w){re.escape(inner)}(?!\w)", text, re.IGNORECASE) is not None


def _is_existing_path(inner: str, environment: ProjectEnvironment) -> bool:
    """Whether `inner` reads as a real path. A trailing slash is stripped first (a directory
    reference), and a path carrying a glob character never counts (a glob pattern is not itself a
    path that "exists")."""
    candidate = inner.rstrip("/")
    if not candidate or any(c in _GLOB_CHARS for c in candidate):
        return False
    return environment.path_exists(candidate)


def _is_known_command(inner: str, environment: ProjectEnvironment) -> bool:
    """Whether `inner`'s program - its first word - is on this machine's `PATH` or declared in
    the project's manifests: naming a command the project runs is what a remedy asks for."""
    words = inner.split()
    program = words[0] if words else ""
    if not program or "/" in program:
        return False
    return environment.on_path(program) or token_present_ci(program, environment.manifest_text())


def invented_named(
    snapshot_text: str,
    new_atoms: list[Any],
    environment: ProjectEnvironment | None,
    sibling_texts: tuple[str, ...] = (),
    snap_atoms: Sequence[SnapshotAtom] = (),
) -> list[dict[str, Any]]:
    """Every named token (backtick span) of a NEW-file prose atom that names something neither
    the snapshot (its text or the named tokens of its atoms) nor a sibling file of the location
    ever named, that is not an existing path
    (from the project root, the file's own directory, or `~`), and whose program the machine
    and the project's manifests do not know (both asked of `environment`; `None` confirms
    nothing) - a rewrite inventing a construct (a tool name that does not exist, e.g.). A code
    block's fence language is its label, never a name, so code blocks are skipped. Checked
    case-insensitively, backticks stripped, once per token text in first-seen (new-file) order."""
    grounding = (snapshot_text, *sibling_texts)
    snap_inners = {i.lower() for i in _token_inners(snap_atoms)}
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for na in new_atoms:
        if getattr(na, "format", "") == "code_block":
            continue
        for tok in getattr(na, "named_tokens", None) or ():
            inner = tok.strip("`")
            key = inner.lower()
            if not inner or key in seen or key in snap_inners:
                continue
            if any(token_present_ci(inner, text) for text in grounding) or (
                environment is not None
                and (_is_existing_path(inner, environment) or _is_known_command(inner, environment))
            ):
                continue
            seen.add(key)
            out.append({"line": na.line, "token": tok})
    return out


_SUBWORD_RE = re.compile(r"[a-zA-Z0-9]+")


def _subwords(text: str) -> set[str]:
    """`text` split into its own alphanumeric sub-words, three-plus letters, lowered —
    underscores, slashes, dots and backticks are all boundaries here (unlike `content_words`,
    which keeps `snake_case` and `dotted.paths` joined), the finer split a path segment or an
    identifier needs to expose the plain word it carries."""
    return {w.lower() for w in _SUBWORD_RE.findall(text) if len(w) > 2}


def _names_an_existing_referent(token_key: str, old_text: str) -> bool:
    """Whether `token_key` only spells out a referent the OLD instruction's own words already
    point to — "per the template" naming itself as `docs/audits/template.md`, "an active
    grant" naming itself as `config: grants_active` — rather than naming a genuinely new
    forbidden object. Deliberately EXACT sub-word match only (no plural/prefix fuzzing): an
    earlier prefix-relaxed version also cleared "test" (an adjective inside "test fixtures")
    against "tests" (a directory name, `tests/pass/`) as though they were the same referent, and
    that reading was wrong — it silenced a real narrowing this check exists to catch. Naming a
    fuzzy-plural referent this exact check still misses (e.g. "the workflow" -> a path containing
    `workflows`) stays flagged rather than risk that collision again."""
    token_words = _subwords(token_key)
    if not token_words:
        return False
    old_words = content_words(old_text)
    return bool(token_words & old_words)


# An example marker — `e.g.`, `for example`, `such as`, `like`, `for instance`, bare or opening a
# parenthetical — or a reason-clause marker — `because`, `since`, `so that`, `to avoid`,
# `otherwise`, or a `,`/`—` before a clause-opening `so`. Once one of these opens, the rest of
# the instruction's own text is an illustration or a justification, not more of what the
# instruction itself forbids or permits.
_EXAMPLE_OR_REASON_RE = re.compile(
    r"\((?:e\.g\.|for example|such as|like|for instance)(?!\w)"
    r"|\b(?:e\.g\.|for example|such as|like|for instance)(?!\w)"
    r"|\b(?:because|since|so that|to avoid|otherwise)\b"
    r"|[,—-]\s*so\b",
    re.IGNORECASE,
)


def _governing_clause_end(text: str) -> int | None:
    """The position in `text` where an example or reason-clause marker opens, or `None` when
    none does — a named token at or past this position sits outside the instruction's own
    governing clause."""
    starts = [m.start() for m in _EXAMPLE_OR_REASON_RE.finditer(text)]
    return min(starts) if starts else None


def _in_trailing_illustration(token: str, text: str, clause_end: int | None) -> bool:
    """Whether `token` (its own backtick-quoted span) first occurs in `text` at or after
    `clause_end` — an example or a reason the rewrite tacked on, not part of what the
    instruction's governing clause itself forbids or permits."""
    if clause_end is None:
        return False
    pos = text.find(token)
    return pos != -1 and pos >= clause_end


def prohibition_scope_changes(snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Any]) -> list[dict[str, Any]]:
    """Every matched prohibition (`charge_value < 0`) whose own forbidden-object set changed —
    a named construct the rewrite now bans that the original instruction never named (widened),
    or one the original named that the rewrite dropped (narrowed) — even when that construct
    already exists elsewhere in the file, the blind spot the vague-instruction-concretized
    allowance in `repeated_named` leaves open for a PROHIBITION specifically (naming what a
    vague directive means is fine; naming a new thing a prohibition now forbids is a scope
    change). A token counts as genuinely added or dropped only when its own bare word is absent,
    case-insensitively, from the other side's instruction text outright — recasing, backticking,
    or unbackticking a word this same instruction already said in plain text is formatting, not
    a scope change — AND (on the added side only) the token neither merely spells out a referent
    the old instruction's own words already carried (`_names_an_existing_referent`: "per the
    template" naming itself as a file path is concretizing a referent already in the sentence,
    not banning something new) NOR sits inside a trailing example or reason clause the rewrite
    tacked onto the instruction's own governing clause (`_in_trailing_illustration`: "such as
    `X`" or "— because `X`" illustrates or justifies the SAME prohibition, it does not widen
    what the instruction itself forbids). The dropped side reads the original the same way: a
    construct the original only gave as an example or a reason is not something the rewrite
    dropped from what is forbidden. Each entry is `{line, text, new_line, new_text, added,
    dropped}` (`added`/`dropped` are lowercased construct keys); `line` names the original
    prohibition so a caller can quote it."""
    out: list[dict[str, Any]] = []
    for sa in snap_atoms:
        if sa.charge_value >= 0:
            continue
        match = matched_new_for.get(id(sa))
        if match is None:
            continue
        old_clause_end = _governing_clause_end(sa.text)
        old_named = {named_key(t) for t in sa.named_tokens if not _in_trailing_illustration(t, sa.text, old_clause_end)}
        new_tokens = getattr(match, "named_tokens", None) or ()
        new_named = {named_key(t) for t in new_tokens}
        clause_end = _governing_clause_end(match.text)
        illustrated = {named_key(t) for t in new_tokens if _in_trailing_illustration(t, match.text, clause_end)}
        added = sorted(
            t
            for t in new_named
            if not token_present_ci(t, sa.text) and not _names_an_existing_referent(t, sa.text) and t not in illustrated
        )
        dropped = sorted(t for t in old_named if not token_present_ci(t, match.text))
        if added or dropped:
            out.append(
                {
                    "line": sa.line,
                    "text": sa.text,
                    "new_line": match.line,
                    "new_text": match.text,
                    "added": added,
                    "dropped": dropped,
                }
            )
    return out
