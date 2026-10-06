"""The shared markdown parser, and the code, link, inline HTML and emphasis spans it finds in inline text.

`md_parser` is the one markdown-it instance the mapper builds: block structure comes from
`parse_blocks`, and a fragment that is not a file (an atom's text, a sentence) is read through
`parseInline`. Its inline rules leave the source span of each code span, link and inline HTML tag, and the source
position of each emphasis delimiter, on the token, so a caller that edits or masks the raw text
takes the positions from the parse instead of matching backticks, brackets or asterisks itself.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from functools import lru_cache
from typing import Any, NamedTuple

from markdown_it import MarkdownIt
from markdown_it.rules_inline import autolink as _autolink_rule
from markdown_it.rules_inline import backtick as _backtick_rule
from markdown_it.rules_inline import emphasis as _emphasis_rule
from markdown_it.rules_inline import html_inline as _html_inline_rule
from markdown_it.rules_inline import image as _image_rule
from markdown_it.rules_inline import link as _link_rule


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


def _record_span(rule: Callable[[Any, bool], bool], types: tuple[str, ...]) -> Callable[[Any, bool], bool]:
    """`rule`, with the source span it consumed left on `meta` of its first token of a type in `types`."""

    def wrapped(state: Any, silent: bool) -> bool:
        start, opened = state.pos, len(state.tokens)
        matched = rule(state, silent)
        if matched and not silent:
            for tok in state.tokens[opened:]:
                if tok.type in types:
                    tok.meta["span"] = (start, state.pos)
                    break
        return matched

    return wrapped


def _record_link_form(rule: Callable[[Any, bool], bool]) -> Callable[[Any, bool], bool]:
    """The inline rule `rule`, with `meta["reference"]` set on the link or image token it opens: true
    when the link was written as a reference (`[text][ref]`, `[ref]`) rather than with its target
    in parentheses."""

    def wrapped(state: Any, silent: bool) -> bool:
        opened = len(state.tokens)
        matched = rule(state, silent)
        if matched and not silent:
            by_reference = state.src[state.pos - 1] != ")"
            for tok in state.tokens[opened:]:
                if tok.type in ("link_open", "image"):
                    tok.meta["reference"] = by_reference
                    break
        return matched

    return wrapped


def _record_delimiters(rule: Callable[[Any, bool], bool]) -> Callable[[Any, bool], bool]:
    """The emphasis inline rule `rule`, with the source position of each delimiter character it pushes
    left on `meta["pos"]` of its token. The post-process turns the paired tokens into the open and close
    tokens of a run and keeps the token objects, so the position survives on them."""

    def wrapped(state: Any, silent: bool) -> bool:
        start = state.pos
        matched = rule(state, silent)
        if matched and not silent:
            # The rule pushes one token per delimiter character, after any text it flushed first.
            for offset, tok in enumerate(state.tokens[len(state.tokens) - (state.pos - start) :]):
                tok.meta["pos"] = start + offset
        return matched

    return wrapped


def _build_parser() -> MarkdownIt:
    parser = MarkdownIt().enable("table")
    parser.inline.ruler.at("backticks", _record_span(_backtick_rule, ("code_inline",)))
    parser.inline.ruler.at("emphasis", _record_delimiters(_emphasis_rule.tokenize))
    parser.inline.ruler.at("link", _record_span(_record_link_form(_link_rule), ("link_open",)))
    parser.inline.ruler.at("image", _record_span(_record_link_form(_image_rule), ("image",)))
    parser.inline.ruler.at("autolink", _record_span(_autolink_rule, ("link_open",)))
    parser.inline.ruler.at("html_inline", _record_span(_html_inline_rule, ("html_inline",)))
    return parser


md_parser = _build_parser()


def _emphasis_run(opener: Any, closer: Any) -> EmphasisRun:
    """The run an `em_open` / `strong_open` token and its closing token delimit. A bold opener is the
    second character of its pair and a bold closer the first, so the run's edges are counted from them."""
    width = len(opener.markup)
    return EmphasisRun(
        opener.meta["pos"] - (width - 1),
        closer.meta["pos"] + width,
        opener.meta["pos"] + 1,
        closer.meta["pos"],
        opener.markup,
    )


def recorded_spans(tok: Any) -> InlineSpans:
    """The code spans, written links and images, inline HTML tags and emphasis runs the inline token
    `tok` holds, as the inline rules recorded them: positions within the token's own text."""
    code: list[CodeSpan] = []
    links: list[tuple[int, int]] = []
    html: list[tuple[int, int]] = []
    emphasis: list[EmphasisRun] = []
    open_runs: list[Any] = []
    for child in tok.children or []:
        if child.type in ("em_open", "strong_open"):
            open_runs.append(child)
        elif child.type in ("em_close", "strong_close") and open_runs:
            emphasis.append(_emphasis_run(open_runs.pop(), child))
        elif (span := child.meta.get("span")) is None:
            continue
        elif child.type == "code_inline":
            code.append(CodeSpan(span[0], span[1], child.content))
        elif child.type in ("link_open", "image"):
            links.append((span[0], span[1]))
        elif child.type == "html_inline":
            html.append((span[0], span[1]))
    return InlineSpans(
        tuple(code), tuple(links), tuple(sorted(emphasis, key=lambda run: (run.start, -run.end))), tuple(html)
    )


@lru_cache(maxsize=4096)
def _inline_spans(text: str) -> InlineSpans:
    """The code spans, written links and images, and emphasis runs of `text`, read from its inline parse."""
    blocks = md_parser.parseInline(text)
    return recorded_spans(blocks[0]) if blocks else InlineSpans((), (), ())


def code_spans(text: str) -> tuple[CodeSpan, ...]:
    """Each code span of the inline `text`, in order: its character range (backticks included) and its content.

    A span is what the markdown parse reads: a run of backticks closes at a run of the same length
    (`` ``a`b`` `` is one span holding ``a`b``), an unmatched run and an escaped backtick are text.
    """
    return _inline_spans(text).code


def html_spans(text: str) -> tuple[tuple[int, int], ...]:
    """The character range of each inline HTML tag of `text` (`<img src="a.png">`, `</b>`, a comment), tag
    and attributes included."""
    return _inline_spans(text).html


def emphasis_runs(text: str) -> tuple[EmphasisRun, ...]:
    """Each bold or italic run of the inline `text`, in order of start: its character range (delimiters
    included), what it wraps and whether it is bold.

    A run is what the markdown parse reads: a delimiter pairs only when it is left- and right-flanking
    as markdown defines it (an intraword `snake_case_name`, an escaped `\\*`, a lone glob star and an
    unmatched delimiter are text), `***x***` is an italic run around a bold one, and a run inside a link
    label counts. Code spans hold no run.
    """
    return _inline_spans(text).emphasis


def leading_bold_run(text: str) -> EmphasisRun | None:
    """The bold run `text` opens with: the one that starts at its first non-space character.

    A text that opens with a bold word (`**Label** - what follows`, `**Rule:** ...`) is read here from
    the parse, so every reader of "the label a text opens with" takes the run's edges from one place and
    decides only what must follow it.
    """
    start = len(text) - len(text.lstrip())
    return next((run for run in emphasis_runs(text) if run.strong and run.start == start), None)


def wrapping_runs(text: str) -> tuple[EmphasisRun, ...]:
    """The emphasis runs that wrap all of `text`, outermost first, surrounding whitespace aside: a
    run that starts at its first non-space character and ends at its last, then the run that wraps
    that run's content the same way (`***x***` is an italic run around a bold one). Empty when the
    text is not emphasised from end to end."""
    runs = emphasis_runs(text)
    lo, hi = len(text) - len(text.lstrip()), len(text.rstrip())
    wrapping: list[EmphasisRun] = []
    while run := next((r for r in runs if r.start == lo and r.end == hi), None):
        wrapping.append(run)
        lo, hi = run.content_start, run.content_end
    return tuple(wrapping)


def has_bold_label(text: str, runs: Iterable[EmphasisRun]) -> bool:
    """Whether a bold run among `runs` of `text` is followed by a colon: it labels what comes after it
    (`**Note**: ...`), so the bold of the text is structure, not emphasis."""
    return any(run.strong and text[run.end :].lstrip().startswith(":") for run in runs)


def file_lines(text: str) -> list[str]:
    """The lines of `text` as the parser numbers them: split at `\\n` only, so a form feed, a vertical tab
    and the Unicode line and paragraph separators stay inside their line."""
    return text.split("\n")


def line_offsets(lines: list[str]) -> list[int]:
    """Char offset, in the text the `lines` were split from on newlines, where each line starts."""
    starts, pos = [], 0
    for line in lines:
        starts.append(pos)
        pos += len(line) + 1
    return starts


def definition_ranges(env: dict[str, Any], starts: list[int], offset: int) -> tuple[tuple[int, int], ...]:
    """The character range of each link reference definition a parse recorded in `env`: `starts` holds
    where each line begins (and the end of the text after the last), `offset` the lines stripped from
    the top before the parse."""
    return tuple(
        (starts[ref["map"][0] + offset], starts[ref["map"][1] + offset]) for ref in env.get("references", {}).values()
    )


@lru_cache(maxsize=4096)
def _definition_spans(text: str) -> tuple[tuple[int, int], ...]:
    """The character range of each link reference definition (`[ref]: path`) `text` holds as blocks.

    A line of an atom is read here as the document it came from: when the parse takes it as a
    definition it is link syntax, not words. A definition that only follows a paragraph line
    without a blank line between is not one in markdown, and is not listed.
    """
    env: dict[str, Any] = {}
    md_parser.parse(text, env)
    return definition_ranges(env, [*line_offsets(text.split("\n")), len(text)], 0)


def link_spans(text: str) -> tuple[tuple[int, int], ...]:
    """The character range of each link, image and link reference definition of `text`, label included.

    A link counts when written with its target in parentheses; a reference-style link
    (`[text][ref]`) needs a definition elsewhere and is not listed.
    """
    return (*_inline_spans(text).links, *_definition_spans(text))


def replace_spans[S: tuple[Any, ...]](text: str, spans: Iterable[S], replace: Callable[[S], str]) -> str:
    """`text` with each span (a tuple opening with its start and end) replaced by `replace(span)`.

    Spans are taken in order of start; one that begins inside the span before it is part of it
    and is left to it.
    """
    out: list[str] = []
    cursor = 0
    for span in sorted(spans, key=lambda s: (s[0], -s[1])):
        if span[0] < cursor:
            continue
        out += [text[cursor : span[0]], replace(span)]
        cursor = span[1]
    out.append(text[cursor:])
    return "".join(out)


def replace_code_spans(text: str, replacement: str | Callable[[CodeSpan], str]) -> str:
    """`text` with each code span (backticks included) replaced by `replacement`.

    `replacement` is the string to put in its place, or a function of the span returning it
    (`lambda span: span.content` keeps a span's words and drops its backticks).
    """
    if isinstance(replacement, str):
        fixed = replacement
        return replace_spans(text, code_spans(text), lambda _span: fixed)
    return replace_spans(text, code_spans(text), replacement)
