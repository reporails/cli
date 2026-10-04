"""The block structure the mapper reads from a markdown file: what the rewrite check counts."""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.preservation import structure
from reporails_cli.core.mapper.classify import absolute_cues, leading_prohibition
from reporails_cli.core.mapper.structure import LineSpans, line_spans, paragraph_lines, read_structure
from reporails_cli.core.platform.adapters.project_environment import LocalProjectEnvironment

_DOC = """---
name: sample
---
# Title

Intro with [a link](./a.md) and a bare https://example.com/x. Code `[no](./code.md)` is no link.

| Key | Value |
|-----|-------|
| `One` | first |
| Two | second |
| | third |

- top
  - nested
- second

```sh
echo "[x](./fenced.md)"
```

- after fence

Setext
------

1. numbered
"""


@pytest.mark.unit
@pytest.mark.subsys_map
def test_blocks_are_read_from_the_parse_with_file_line_numbers() -> None:
    doc = read_structure(_DOC)
    assert doc.headings == (4, 24)
    assert [line for line, _group in doc.list_items] == [14, 15, 16, 22, 27]
    assert [cell for _line, cell in doc.table_rows] == ["One", "Two", ""]
    assert doc.fences == ((18, 'echo "[x](./fenced.md)"\n'),)
    assert sorted(target for _line, target in doc.links) == ["./a.md", "https://example.com/x"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_nested_items_share_their_list_and_a_fence_does_not_split_a_list() -> None:
    groups = [group for _line, group in read_structure(_DOC).list_items]
    assert groups == [1, 1, 1, 1, 2]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_pipe_lines_without_a_separator_row_are_not_a_table() -> None:
    assert read_structure("| a | b |\n| c | d |\n").table_rows == ()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_list_after_a_paragraph_is_a_new_list() -> None:
    doc = read_structure("- a item\n\nText between.\n\n- b item\n")
    assert [group for _line, group in doc.list_items] == [1, 2]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_removed_structure_counts_what_the_rewrite_dropped() -> None:
    before = read_structure(_DOC)
    after = read_structure("# Title\n\nIntro.\n\n- top\n")
    removed = structure.removed_structure(before, after, frozenset())
    assert removed == {"table_rows": 2, "list_items": 4, "headings": 1, "fences": 1, "links": 2}
    assert structure.structure_totals(before, frozenset())["table_rows"] == 2


@pytest.mark.unit
@pytest.mark.subsys_map
def test_relation_lines_are_not_counted_as_lost() -> None:
    before = read_structure("# T\n\n- keep it\n- drop it\n")
    after = read_structure("# T\n\n- keep it\n")
    assert structure.removed_structure(before, after, frozenset({4}))["list_items"] == 0


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_leading_prohibition_is_read_from_the_words_not_the_markup() -> None:
    assert leading_prohibition("**Never** push") is not None
    assert leading_prohibition("Do not push") is not None
    assert leading_prohibition("Always push") is None


@pytest.mark.unit
@pytest.mark.subsys_map
def test_must_and_shall_are_not_absolute_cues() -> None:
    assert absolute_cues("You must run it and shall never skip it") == {"never"}
    assert absolute_cues("Always run it") == {"always"}


class _FakeEnvironment:
    def __init__(self, paths: set[str], programs: set[str], manifests: str = "") -> None:
        self._paths, self._programs, self._manifests = paths, programs, manifests

    def path_exists(self, candidate: str) -> bool:
        return candidate in self._paths

    def on_path(self, program: str) -> bool:
        return program in self._programs

    def manifest_text(self) -> str:
        return self._manifests


@pytest.mark.unit
@pytest.mark.subsys_map
def test_invented_named_asks_the_environment_instead_of_reading_the_disk() -> None:
    from types import SimpleNamespace

    from reporails_cli.core.heal.preservation.named import invented_named

    atoms = [
        SimpleNamespace(line=3, format="prose", named_tokens=["`src/app.py`", "`mytool run`", "`ghost`", "`make all`"])
    ]
    env = _FakeEnvironment({"src/app.py"}, {"mytool"}, "all:\n\tmake all\n")
    assert invented_named("Original text.", atoms, env) == [{"line": 3, "token": "`ghost`"}]
    assert [e["token"] for e in invented_named("Original text.", atoms, None)] == [
        "`src/app.py`",
        "`mytool run`",
        "`ghost`",
        "`make all`",
    ]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_local_environment_reads_paths_programs_and_manifests(tmp_path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text("x", encoding="utf-8")
    (tmp_path / "Makefile").write_text("build:\n\tgo build\n", encoding="utf-8")
    env = LocalProjectEnvironment(tmp_path, tmp_path / "src")
    assert env.path_exists("src/a.py") and env.path_exists("a.py")
    assert not env.path_exists("src/missing.py")
    assert env.on_path("python3") or env.on_path("sh")
    assert not env.on_path("no-such-program-xyz")
    assert "go build" in env.manifest_text()
    assert LocalProjectEnvironment(None).manifest_text() == ""


_PLACES = (
    "---\na: b\n---\nText `a` [l](u.md) ![i](p.png)\n\n    indented\n\n- item\n  more\n\n"
    "> quote\n> next\n\n~~~~\nfenced\n~~~~\n"
)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_paragraph_lines_are_plain_prose_outside_list_items() -> None:
    assert paragraph_lines(_PLACES) == [(3, 3), (10, 11)]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_line_spans_cover_code_and_links_in_line_columns() -> None:
    spans = line_spans(_PLACES)
    assert (spans[3].code, spans[3].links) == (((5, 8),), ((9, 18), (19, 30)))
    assert spans[5].code == ((0, 12),)  # an indented code block is code on every line it covers
    assert spans[13].code == ((0, 4),) and spans[14].code == ((0, 6),)  # so is a fenced block
    assert spans[7].code == () and spans[7].links == ()


@pytest.mark.unit
@pytest.mark.subsys_map
def test_line_spans_and_a_fragment_agree_on_where_a_link_sits() -> None:
    text = "See [a `b` c](d.md) now"
    (spans,) = line_spans(text)
    assert spans.links == ((4, 19),) and text[4:19] == "[a `b` c](d.md)"
    assert LineSpans.of_fragment(text) == spans
    assert spans.code == ((7, 10),)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_link_reference_definition_is_a_link_in_a_file_and_in_a_fragment() -> None:
    text = "See [guide].\n\n[guide]: docs/build.sh\n"
    spans = line_spans(text)
    assert spans[0].links == ((4, 11),)
    assert spans[2].links == ((0, 22),)
    assert LineSpans.of_fragment("[guide]: docs/build.sh").links == ((0, 22),)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_the_column_where_a_lines_text_starts_comes_from_the_parse() -> None:
    text = (
        "> quoted\n"
        "> > nested\n"
        "lazy line\n"
        "\n"
        "1) paren\n"
        "\n"
        "-\ttab\n"
        "\n"
        "+ plus\n"
        "\n"
        "- > quote in item\n"
        "\n"
        "```\n"
        "> in a fence\n"
        "```\n"
        "\n"
        "<div>\n"
        "- in markup\n"
        "</div>\n"
    )
    starts = {n: spans.text for n, spans in enumerate(line_spans(text))}
    assert [starts[n] for n in (0, 1, 2, 4, 6, 8, 10)] == [2, 4, 0, 3, 2, 2, 4]
    assert [starts[n] for n in (3, 12, 13, 14, 16, 17, 18)] == [None] * 7


@pytest.mark.unit
@pytest.mark.subsys_map
def test_line_spans_place_emphasis_runs_in_line_columns_and_a_fragment_agrees() -> None:
    text = "> - Do **not** push, _ever_\n\n```\n**in a fence**\n```\n\n**over\nlines**\n"
    spans = line_spans(text)
    assert [(r.start, r.end, r.content_start, r.content_end, r.marker) for r in spans[0].emphasis] == [
        (7, 14, 9, 12, "**"),
        (21, 27, 22, 26, "_"),
    ]
    assert spans[3].emphasis == ()  # bold typed inside a fence is text
    assert spans[6].emphasis == spans[7].emphasis == ()  # a run over a line break sits on no one line
    line = "Do **not** push"
    assert LineSpans.of_fragment(line).emphasis == line_spans(line)[0].emphasis


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_link_after_a_multi_line_code_span_keeps_its_file_line() -> None:
    from reporails_cli.core.mapper.structure import link_targets

    text = "# Docs\n\nRun `make\nbuild` first, then read\n[the guide](a.md) and\n[setup](b.md).\n"
    assert link_targets(text) == [(5, "a.md"), (6, "b.md")]
    assert read_structure(text).links == ((5, "a.md"), (6, "b.md"))


@pytest.mark.unit
@pytest.mark.subsys_map
def test_a_bare_url_after_a_multi_line_code_span_keeps_its_file_line() -> None:
    text = "Run `make\nbuild` then see\nhttps://example.com/x for more.\n"
    assert read_structure(text).links == ((3, "https://example.com/x"),)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("See **https://x.com** now.\n", ((1, "https://x.com"),)),
        ("See _https://x.com/a_ now.\n", ((1, "https://x.com/a"),)),
        ("See https://x.com/a\\_b now.\n", ((1, "https://x.com/a_b"),)),
        ("See https://x.com&lt;br&gt;next now.\n", ((1, "https://x.com<br>next"),)),
        ("See https://x.com\\\nnext line.\n", ((1, "https://x.com"),)),
        ("Run `a\nb` and **https://y.com** z.\n", ((2, "https://y.com"),)),
    ],
)
def test_a_bare_url_target_is_the_url_text_the_parse_reads(text: str, expected: tuple[tuple[int, str], ...]) -> None:
    assert read_structure(text).links == expected


@pytest.mark.unit
@pytest.mark.subsys_map
def test_line_spans_place_inline_html() -> None:
    (spans,) = line_spans('See <img src="a.png"> now')
    assert spans.html == ((4, 21),)
    assert LineSpans.of_fragment('See <img src="a.png"> now').html == ((4, 21),)


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("before", "token"),
    [
        ("see [a](b.md) and `c` and *d* then x_y.", "x_y"),
        ("x_y first then [a](b.md) and `c`", "x_y"),
        ("[a](b.md)x_y and <b>x_y</b>", "x_y"),
        ("> - *em* x_y **strong** `code`", "x_y"),
    ],
)
def test_a_wrap_shifts_the_columns_like_a_fresh_read(before: str, token: str) -> None:
    (spans,) = line_spans(before)
    at = before.index(token)
    after = f"{before[:at]}`{token}`{before[at + len(token) :]}"
    edited = spans.spliced(at, 0, 1).spliced(at + len(token) + 1, 0, 1).with_code((at, at + len(token) + 2))
    assert edited == line_spans(after)[0]


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("a **b** c [d](e) **f**", "a *b* c [d](e) **f**"),
        ("**b** and **f** and `g`", "*b* and **f** and `g`"),
        ("- never **log** the *token* <i>x</i>", "- never *log* the *token* <i>x</i>"),
    ],
)
def test_softening_a_bold_run_shifts_the_columns_like_a_fresh_read(before: str, after: str) -> None:
    (spans,) = line_spans(before)
    run = next(r for r in spans.emphasis if r.strong)
    assert spans.softened(run) == line_spans(after)[0]
