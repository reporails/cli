"""Pure data shapes of the mapper: text spans, reading and lookup records, cache entries, findings."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import NamedTuple, TypedDict

from reporails_cli.core.platform.contract.json_value import JsonObject
from reporails_cli.core.platform.dto.diagnostics import FindingSeverity
from reporails_cli.core.platform.dto.ruleset import Atom, FileRecord, Modality, Specificity


def _moved(pos: int, at: int, removed: int, inserted: int, *, opens: bool) -> int:
    """Where column `pos` lands when `removed` characters at `at` become `inserted` ones. A column that
    opens something (a range start) at the edit point moves with the inserted text; one that closes
    something (a range end) stays before it. A column inside the removed characters falls to `at`."""
    if pos >= at + removed and (opens or pos > at):
        return pos + inserted - removed
    return min(pos, at)


def _moved_ranges(
    ranges: tuple[tuple[int, int], ...], at: int, removed: int, inserted: int
) -> tuple[tuple[int, int], ...]:
    return tuple(
        (_moved(lo, at, removed, inserted, opens=True), _moved(hi, at, removed, inserted, opens=False))
        for lo, hi in ranges
    )


class AppearanceFields(TypedDict):
    """The specificity and token-list fields of an Atom, passed on as keyword arguments."""

    specificity: Specificity
    named_tokens: list[str]
    unformatted_code: list[str]
    italic_tokens: list[str]
    bold_tokens: list[str]


class SpecificityFields(AppearanceFields):
    """The appearance fields with the token count of the line."""

    token_count: int


@dataclass(frozen=True, slots=True)
class PassEntry:
    """An atom carried through unchanged."""

    atom: Atom


@dataclass(frozen=True, slots=True)
class HeadEntry:
    """A heading atom decoded from the text at `start`."""

    atom: Atom
    start: int


@dataclass(frozen=True, slots=True)
class SentEntry:
    """An instruction atom split into `units`, decoded from the texts from `start`."""

    atom: Atom
    plain: bool
    start: int
    units: list[str]


type PlanEntry = PassEntry | HeadEntry | SentEntry


@dataclass
class Span:
    """One decoded O/B/I span: its joined text, confidence, and token offset.

    ``conf`` is the mean max-softmax probability over the span's words, ``0.0``
    when the axis decodes no span (``text`` empty). ``offset`` is the
    ``[start_tok, end_tok)`` half-open word-index bounding box covering every
    B/I run folded into ``text`` (start inclusive, end exclusive — mirrors the
    half-open char offsets ``word_spans`` already uses); ``None`` when the axis
    decodes no span.
    """

    text: str
    conf: float
    offset: tuple[int, int] | None = None


@dataclass
class AtomTuple:
    """A per-sentence 5-tuple: polarity + subject/predicate/object/scope spans.

    The four spans are separated: ``subject`` is the actor (who performs / is
    governed; empty for imperatives), ``predicate`` the action, ``object`` the
    value only (subject is no longer fused into it), ``scope`` the condition.
    Each is a :class:`Span` carrying its own text and confidence.
    """

    polarity: int  # +1 directive, -1 restrictive, 0 neutral
    modality: Modality
    subject: Span
    predicate: Span
    object: Span
    scope: Span
    text: str


class CoverageRestrictor(NamedTuple):
    """When a word cuts a rule's coverage down: it must be followed by one of `next_words` (any word
    when empty), and the author's line must hold none of `already` (the senses it already carries)."""

    next_words: frozenset[str]
    already: frozenset[str]


class FileTypeSpec(NamedTuple):
    """A registry file type read for matching."""

    patterns: list[str]
    declared: dict[str, str | list[str]]  # the file type's own properties
    props: JsonObject  # `declared` with the activation keys folded in


RegistryMatch = tuple[int, str, str, JsonObject]  # (specificity, agent, file type, properties)


@dataclass
class RegistryQuery:
    """What one registry lookup is for: the file's lowered relative path, its absolute path and
    scan root when known, and the registry it is matched against."""

    rel_lower: str
    registry: dict[str, JsonObject]
    path: Path | None
    root: Path | None
    plugin_roots: Sequence[Path] = ()

    @property
    def below_root(self) -> bool:
        """Whether the file sits in a subdirectory rather than at the root."""
        return "/" in self.rel_lower and not self.rel_lower.startswith("/")


@dataclass
class RegistryPicks:
    """The best match so far, and the best match for a subdirectory copy of an eager global file."""

    best: RegistryMatch | None = None
    below_root_copy: RegistryMatch | None = None


class FileRead(NamedTuple):
    """How an agent reads a file: its file type, when it loads and from which precedence scope."""

    file_type: str
    loading: str
    precedence: str


@dataclass
class CachedFileEntry:
    """Cached tokenization + embedding result for a single file."""

    atoms: list[JsonObject] = field(default_factory=list)
    last_used: str = ""  # ISO timestamp for LRU eviction
    description_embedding: list[int] | None = None  # int8 embedding of the frontmatter description


class CodeSpan(NamedTuple):
    """One code span of a text: where it sits (delimiters included) and what it holds."""

    start: int
    end: int
    content: str


class EmphasisRun(NamedTuple):
    """One bold or italic run of a text: where it sits (delimiters included), what it wraps, and the
    delimiter it was written with (`*`, `**`, `_` or `__`)."""

    start: int
    end: int
    content_start: int
    content_end: int
    marker: str

    @property
    def strong(self) -> bool:
        """Whether the run is bold (a double delimiter) rather than italic."""
        return len(self.marker) == 2

    def shifted(self, by: int) -> EmphasisRun:
        """The same run `by` characters further on (or back, when negative)."""
        return EmphasisRun(self.start + by, self.end + by, self.content_start + by, self.content_end + by, self.marker)


class InlineSpans(NamedTuple):
    """What the inline rules recorded on one inline token: its code spans, its written links and
    images and its inline HTML tags (character ranges), and its emphasis runs, each in order of start."""

    code: tuple[CodeSpan, ...]
    links: tuple[tuple[int, int], ...]
    emphasis: tuple[EmphasisRun, ...]
    html: tuple[tuple[int, int], ...] = ()


class Tokens(NamedTuple):
    """One text with its token ids and per-token character offsets (no padding)."""

    text: str
    ids: list[int]
    offsets: list[tuple[int, int]]


@dataclass
class MapFinding:
    """A validation finding from map inspection."""

    severity: FindingSeverity
    rule: str
    message: str
    line: int = 0
    text: str = ""


@dataclass
class SkillFolders:
    """Which folders are skill folders for one run, each answer computed once."""

    root: Path
    registry: dict[str, JsonObject]
    base: set[str]
    by_path: set[str]
    entries: dict[Path, FileRecord]  # folder -> the map's own entry record
    patterns: dict[str, list[str]] = field(default_factory=dict)
    on_disk: dict[tuple[Path, str], bool] = field(default_factory=dict)


@dataclass
class BlockReading:
    """What the walk over the parse tokens has found so far."""

    offset: int
    headings: list[int] = field(default_factory=list)
    items: list[tuple[int, int]] = field(default_factory=list)
    rows: list[tuple[int, str]] = field(default_factory=list)
    fences: list[tuple[int, str]] = field(default_factory=list)
    links: list[tuple[int, str]] = field(default_factory=list)
    block_of: dict[int, int] = field(default_factory=dict)
    lists: list[int] = field(default_factory=list)
    group: int = 0
    block: int = 0
    item_just_opened: bool = False


@dataclass(frozen=True)
class LineSpans:
    """The `[start, end)` columns of a line that a code span (or code block), a link, image or
    link reference definition and an inline HTML tag occupy, the column where the line's inline text
    starts after a blockquote's `>` markers or a list item's marker (None for a line with no inline
    text: a fenced or markup block, a blank line, a rule), and the emphasis runs that sit wholly on the
    line (their positions are columns; a run that runs over a line break is not listed)."""

    code: tuple[tuple[int, int], ...] = ()
    links: tuple[tuple[int, int], ...] = ()
    text: int | None = None
    emphasis: tuple[EmphasisRun, ...] = ()
    html: tuple[tuple[int, int], ...] = ()

    def spliced(self, at: int, removed: int, inserted: int) -> LineSpans:
        """These columns after `removed` characters of the line at column `at` are replaced by
        `inserted` new ones: every column after the edit moves with it, so the line need not be read
        again."""

        def move(pos: int, *, opens: bool) -> int:
            return _moved(pos, at, removed, inserted, opens=opens)

        return LineSpans(
            _moved_ranges(self.code, at, removed, inserted),
            _moved_ranges(self.links, at, removed, inserted),
            None if self.text is None else move(self.text, opens=False),
            tuple(
                EmphasisRun(
                    move(run.start, opens=True),
                    move(run.end, opens=False),
                    move(run.content_start, opens=False),
                    move(run.content_end, opens=True),
                    run.marker,
                )
                for run in self.emphasis
            ),
            _moved_ranges(self.html, at, removed, inserted),
        )

    def with_code(self, span: tuple[int, int]) -> LineSpans:
        """These columns with one more code span."""
        return replace(self, code=tuple(sorted((*self.code, span))))

    def softened(self, run: EmphasisRun) -> LineSpans:
        """These columns after the bold `run` becomes italic: one delimiter character is dropped on each
        side of its content."""
        italic = replace(self, emphasis=tuple(r._replace(marker="*") if r == run else r for r in self.emphasis))
        return italic.spliced(run.content_end, 1, 0).spliced(run.start, 1, 0)


class SourceRanges(NamedTuple):
    """What the parse places in the file: code, link and inline HTML char ranges, `(line, column)` where
    the inline text of each file line starts, and the emphasis runs (positions are file char offsets)."""

    code: tuple[tuple[int, int], ...]
    links: tuple[tuple[int, int], ...]
    text: tuple[tuple[int, int], ...]
    emphasis: tuple[EmphasisRun, ...]
    html: tuple[tuple[int, int], ...]
