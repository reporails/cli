"""Named constructs in the preservation check: which backticked construct a rewrite lost, which
it invented (named by nothing in the file, no path on disk, no program the machine or the
project's manifests know), which it repeats beyond what its instructions account for, and which
a prohibition now bans or no longer bans.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence

from reporails_cli.core.heal.preservation.words import AtomView, named_key, slot_words
from reporails_cli.core.mapper.classify import condition_text
from reporails_cli.core.mapper.classify_lexicon import words_of
from reporails_cli.core.platform.contract.environment import ProjectEnvironment
from reporails_cli.core.platform.contract.glob_pattern import GLOB_CHARS
from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.heal import SnapshotAtom
from reporails_cli.core.platform.dto.ruleset import Atom


def token_present(inner: str, text: str) -> bool:
    """Whether `inner` (a named token's inner text) occurs in `text` as a whole word — never
    as a bare substring of a longer word (`main` inside `maintain`). A backtick is not a word
    character, so `` `main` `` and `` `main -q` `` both match on the word boundary alone."""
    return re.search(rf"(?<!\w){re.escape(inner)}(?!\w)", text) is not None


def wordless(inner: str) -> bool:
    """Whether a named construct holds no letter or digit (`.`, `::`, `--`): such a mark occurs
    all through ordinary prose, so only its own backticked span counts as a mention of it."""
    return not any(c.isalnum() for c in inner)


def _span_present(inner: str, text: str, *, fold: bool = False) -> bool:
    """Whether the named construct `inner` is present in `text`: a wordless one as its own
    backticked span, any other as a whole word (`fold` ignores case)."""
    if wordless(inner):
        return f"`{inner}`" in text
    return token_present_ci(inner, text) if fold else token_present(inner, text)


def _token_inners(atoms: Sequence[AtomView]) -> set[str]:
    """The inner text of every named token of `atoms`."""
    return {tok for a in atoms for tok in a.named_tokens}


def lost_named_tokens(snap_atoms: list[SnapshotAtom], new_text: str, new_atoms: Sequence[Atom] = ()) -> list[str]:
    """Every named token (backtick span) of any snapshot atom whose inner text is present in
    neither the new file text (as a whole token) nor the named tokens of any new atom, once
    each, in first-seen order."""
    new_inners = _token_inners(new_atoms)
    lost: list[str] = []
    for sa in snap_atoms:
        for tok in sa.named_tokens:
            if tok and tok not in new_inners and not _span_present(tok, new_text) and tok not in lost:
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
    snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Atom], split_covering_for: dict[int, list[Atom]]
) -> set[int]:
    """`id()`s of every new atom that stands in for an originally-unnamed snapshot instruction
    — its direct match, or every atom in the split window that covers it — `repeated_named`'s
    credit-eligible set for the vague-instruction-concretized allowance."""
    was_unnamed = {id(match) for sa in snap_atoms if not sa.named_tokens if (match := matched_new_for.get(id(sa)))}
    for sa in snap_atoms:
        if not sa.named_tokens:
            was_unnamed.update(id(na) for na in split_covering_for.get(id(sa), ()))
    return was_unnamed


def _flag_overruns(order: list[str], allowance: Counter[str], original_text: str, new_text: str) -> list[JsonObject]:
    """`order`'s tokens (first-seen), each flagged when its new-text mention count exceeds
    `allowance` plus its original mention count. Each entry is `{token, before, after, allowed}`."""
    out: list[JsonObject] = []
    for inner in dict.fromkeys(order):
        before, after = mentions(inner, original_text), mentions(inner, new_text)
        allowed = before + allowance[inner]
        if after > allowed:
            out.append({"token": f"`{inner}`", "before": before, "after": after, "allowed": allowed})
    return out


def repeated_named(
    snap_atoms: list[SnapshotAtom],
    new_atoms: list[Atom],
    *,
    matched_new_for: dict[int, Atom],
    split_covering_for: dict[int, list[Atom]],
    original_text: str,
    new_text: str,
) -> list[JsonObject]:
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
        for inner in dict.fromkeys(sa.named_tokens):
            if inner and not wordless(inner):
                allowance[inner] += sa.charge_value != 0
                order.append(inner)
    was_unnamed = _unnamed_counterparts(snap_atoms, matched_new_for, split_covering_for)
    for na in new_atoms:
        for inner in dict.fromkeys(na.named_tokens):
            if inner and not wordless(inner) and token_present(inner, original_text):
                order.append(inner)
                allowance[inner] += id(na) in was_unnamed and na.charge_value != 0
    return _flag_overruns(order, allowance, original_text, new_text)


def token_present_ci(inner: str, text: str) -> bool:
    """Whole-word, case-insensitive occurrence of `inner` in `text` — an invented-token check
    compares the rewrite's own casing against the snapshot's, never demanding an exact match."""
    return re.search(rf"(?<!\w){re.escape(inner)}(?!\w)", text, re.IGNORECASE) is not None


def _is_existing_path(inner: str, environment: ProjectEnvironment) -> bool:
    """Whether `inner` reads as a real path. A trailing slash is stripped first (a directory
    reference), and a path carrying a glob character never counts (a glob pattern is not itself a
    path that "exists")."""
    candidate = inner.rstrip("/")
    if not candidate or any(c in GLOB_CHARS for c in candidate):
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
    new_atoms: list[Atom],
    environment: ProjectEnvironment | None,
    sibling_texts: tuple[str, ...] = (),
    snap_atoms: Sequence[SnapshotAtom] = (),
) -> list[JsonObject]:
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
    out: list[JsonObject] = []
    for na in new_atoms:
        if na.format == "code_block":
            continue
        for inner in na.named_tokens:
            key = inner.lower()
            if not inner or key in seen or key in snap_inners:
                continue
            if any(_span_present(inner, text, fold=True) for text in grounding) or (
                environment is not None
                and (_is_existing_path(inner, environment) or _is_known_command(inner, environment))
            ):
                continue
            seen.add(key)
            out.append({"line": na.line, "token": inner})
    return out


def _subwords(text: str) -> set[str]:
    """The three-plus letter words of `text`, lowered — underscores, slashes, dots and backticks
    are all boundaries here, the split a path segment or an identifier needs to expose the plain
    word it carries."""
    return {w for w in words_of(text) if len(w) > 2}


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
    return bool(token_words & _subwords(old_text))


def _governed(atom: AtomView) -> set[str]:
    """The lowered named constructs of `atom` that sit in the object, the scope or the condition the
    mapper read: a construct outside all three (an example or a reason tacked on) illustrates or justifies the
    instruction and is no part of what it forbids. An atom with no slots read governs all of them."""
    if atom.slots is None:
        return {named_key(t) for t in atom.named_tokens}
    words = set(slot_words(atom, "object", "scope")) | set(words_of(condition_text(atom) or ""))
    return {named_key(t) for t in atom.named_tokens if not (own := words_of(t)) or set(own) <= words}


def prohibition_scope_changes(snap_atoms: list[SnapshotAtom], matched_new_for: dict[int, Atom]) -> list[JsonObject]:
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
    not banning something new). Only the constructs in the object or scope the mapper read count
    (`_governed`): one outside both illustrates or justifies the SAME prohibition and does not
    change what it forbids. Each entry is `{line, text, new_line, new_text, added,
    dropped}` (`added`/`dropped` are lowercased construct keys); `line` names the original
    prohibition so a caller can quote it."""
    out: list[JsonObject] = []
    for sa in snap_atoms:
        if sa.charge_value >= 0:
            continue
        match = matched_new_for.get(id(sa))
        if match is None:
            continue
        added = sorted(
            t
            for t in _governed(match)
            if not token_present_ci(t, sa.text) and not _names_an_existing_referent(t, sa.text)
        )
        dropped = sorted(t for t in _governed(sa) if not token_present_ci(t, match.text))
        if added or dropped:
            out.append(
                {
                    "line": sa.line,
                    "text": sa.text,
                    "new_line": match.line,
                    "new_text": match.text,
                    "added": [*added],
                    "dropped": [*dropped],
                }
            )
    return out
