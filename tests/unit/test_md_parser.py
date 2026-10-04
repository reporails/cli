"""The code spans and links of one inline text are read from the markdown parse, in one place."""

import pytest

from reporails_cli.core.classify.content_format import detect_content_format
from reporails_cli.core.mapper.annotate import bold_title_label, check_specificity
from reporails_cli.core.mapper.classify import _after_bold_label, _strip_md_for_classify
from reporails_cli.core.mapper.instructions import _cut_mask, without_lead
from reporails_cli.core.mapper.markers import project_markers, strip_markdown_inline
from reporails_cli.core.mapper.md_parser import (
    code_spans,
    emphasis_runs,
    has_bold_label,
    leading_bold_run,
    link_spans,
    replace_code_spans,
    replace_spans,
    wrapping_runs,
)
from reporails_cli.core.mapper.parse import (
    _is_structural,
    _scan_neutral_for_embedded_markers,
    _strip_backtick_delims,
)
from reporails_cli.core.platform.dto.ruleset import Atom


def _neutral(text: str) -> Atom:
    return Atom(
        line=1, text=text, kind="excitation", charge="NEUTRAL", charge_value=0, modality="none", specificity="abstract"
    )


class TestCodeSpans:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_single_backtick_span_has_range_and_content(self):
        text = "Run `uv sync` first"
        assert [(s.start, s.end, s.content) for s in code_spans(text)] == [(4, 13, "uv sync")]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_double_backtick_span_holds_a_backtick(self):
        text = "Run ``a`b`` and `c` now"
        assert [s.content for s in code_spans(text)] == ["a`b", "c"]
        assert text[code_spans(text)[0].start : code_spans(text)[0].end] == "``a`b``"

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_unmatched_backtick_is_text(self):
        assert code_spans("Run `a now") == ()

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_escaped_backticks_are_text(self):
        assert code_spans(r"Run \`a\` now") == ()

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_empty_backtick_pair_is_text(self):
        assert [s.content for s in code_spans("Run `` now `x`")] == ["x"]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_spaced_double_backticks_hold_the_text_between(self):
        assert [s.content for s in code_spans("x `` y `` z")] == ["y"]


class TestLinkSpans:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_inline_link_and_image_cover_label_and_target(self):
        text = "See [the guide](g.md) and ![logo](l.png) now"
        assert [text[a:b] for a, b in link_spans(text)] == ["[the guide](g.md)", "![logo](l.png)"]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_target_with_parentheses_is_one_link(self):
        text = "See [page](a_(b).md) here"
        assert [text[a:b] for a, b in link_spans(text)] == ["[page](a_(b).md)"]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_link_inside_a_code_span_is_code(self):
        assert link_spans("Use `[a](b)` literally") == ()

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_definition_line_is_a_link_span(self):
        text = "[avoid force-add]: rules/no-force.md"
        assert link_spans(text) == ((0, len(text)),)

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_definition_after_a_paragraph_line_is_text(self):
        assert link_spans("Some words\n[x]: y.md") == ()

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_reference_style_link_without_a_definition_is_text(self):
        assert link_spans("See [the guide][g] here") == ()


class TestReplaceCodeSpans:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    @pytest.mark.parametrize(
        ("replacement", "expected"),
        [
            ("", "Run  and  now"),
            ("x", "Run x and x now"),
            (" ", "Run   and   now"),
            (lambda span: span.content, "Run make build and ``a`b`` now".replace("``a`b``", "a`b")),
        ],
    )
    def test_each_code_span_is_replaced(self, replacement, expected):
        text = "Run `make build` and ``a`b`` now"
        assert replace_code_spans(text, replacement) == expected

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_text_without_a_code_span_is_unchanged(self):
        assert replace_code_spans("no span \\` here", "x") == "no span \\` here"


class TestReplaceSpans:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_nested_span_is_left_to_the_one_around_it(self):
        text = "a [`b`](c) d"
        assert replace_spans(text, (*code_spans(text), *link_spans(text)), lambda _s: "_") == "a _ d"


class TestSitesReadTheParse:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_named_tokens_read_a_double_backtick_span(self):
        spec, named, *_ = check_specificity("Run ``a`b`` and `c` now")
        assert (spec, named) == ("named", ["a`b", "c"])

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_escaped_backticks_name_nothing(self):
        assert check_specificity(r"Run \`pytest\` now")[1] == []

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_unmatched_backtick_names_nothing(self):
        assert check_specificity("Run `pytest now")[1] == []

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_strip_markdown_inline_keeps_double_backtick_content(self):
        assert strip_markdown_inline("Run ``a_b*c`` and `d_e`") == "Run a_b*c and d_e"

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_marker_projection_locates_a_double_backtick_span(self):
        md = "Run ``a`b`` now"
        plain = strip_markdown_inline(md)
        assert project_markers(md, plain) == [(4, 7, "`")]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_cut_mask_covers_a_double_backtick_span(self):
        sentence = "Run ``a, b`` and stop"
        mask = _cut_mask(sentence)
        assert all(mask[sentence.index("``") : sentence.index("`` and") + 2])
        assert not mask[sentence.index("and")]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_backtick_delimiters_drop_from_a_double_backtick_span(self):
        assert _strip_backtick_delims("Run ``a b`` now") == "Run a b now"

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_charge_word_in_a_double_backtick_span_is_referential(self):
        atom = _neutral("The flag ``never-fail`` controls retry handling.")
        _scan_neutral_for_embedded_markers([atom])
        assert atom.charge == "NEUTRAL"

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_charge_word_in_an_unmatched_backtick_run_is_text(self):
        atom = _neutral("You must never `bypass the check here.")
        _scan_neutral_for_embedded_markers([atom])
        assert atom.charge == "AMBIGUOUS"


def _runs(text: str) -> list[tuple[str, str, bool]]:
    """Each emphasis run of `text` as (its source, what it wraps, whether it is bold)."""
    return [(text[r.start : r.end], text[r.content_start : r.content_end], r.strong) for r in emphasis_runs(text)]


class TestEmphasisRuns:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    @pytest.mark.parametrize(
        ("text", "runs"),
        [
            ("A ***x*** run", [("***x***", "**x**", False), ("**x**", "x", True)]),
            ("**a *b* c**", [("**a *b* c**", "a *b* c", True), ("*b*", "b", False)]),
            ("Use _x_ and __y__", [("_x_", "x", False), ("__y__", "y", True)]),
            ("the snake_case_name var", []),
            (r"an \*x\* literal", []),
            ("an * star and 2 * 3 * 4", []),
            ("see [a *b* c](u) and [**d**][r]", [("*b*", "b", False), ("**d**", "d", True)]),
            ("`a_*b*_c` and *d*", [("*d*", "d", False)]),
        ],
    )
    def test_runs_are_the_ones_the_parse_pairs(self, text, runs):
        assert _runs(text) == runs

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_strength_is_the_delimiter_width_and_the_marker_is_kept(self):
        assert [(r.marker, r.strong) for r in emphasis_runs("*a* **b** _c_ __d__")] == [
            ("*", False),
            ("**", True),
            ("_", False),
            ("__", True),
        ]


class TestEmphasisSitesReadTheParse:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_italic_with_underscores_counts_and_a_star_in_code_does_not(self):
        assert check_specificity("Use _x_ here")[3] == ["x"]
        assert check_specificity("Keep `a_*b*_c` and _d_")[3] == ["d"]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_double_underscore_is_bold(self):
        assert check_specificity("Use __x__ here")[4] == ["x"]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_italic_inside_bold_is_bold_only(self):
        _spec, _named, _unformatted, italic, bold = check_specificity("A **a *b* c** end.")
        assert (italic, bold) == ([], ["a *b* c"])

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_bold_inside_italic_is_cut_out_of_the_italic_words(self):
        assert check_specificity("*a **b** c* end")[3:] == (["a  c"], ["b"])

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_escaped_and_unmatched_stars_are_not_italic(self):
        assert check_specificity(r"an \*x\* literal")[3] == []
        assert check_specificity("an * star and *.pem")[3] == []

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_markers_keep_the_delimiter_written(self):
        md = "Use __x__ and _y_ here"
        plain = strip_markdown_inline(md)
        assert plain == "Use x and y here"
        assert project_markers(md, plain) == [(4, 5, "__"), (10, 11, "_")]

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_stripping_leaves_a_glob_a_name_and_an_escaped_star(self):
        assert strip_markdown_inline("*.pem and snake_case and 2 * 3") == "*.pem and snake_case and 2 * 3"
        assert strip_markdown_inline("**a** `b_*c*_d` *e*") == "a b_*c*_d e"

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_file_has_bold_where_the_parse_finds_a_bold_run(self):
        assert "bold" in detect_content_format("Some **bold** words.\n")
        assert "bold" in detect_content_format("A list:\n\n- an __item__\n")
        assert "bold" not in detect_content_format("Snake `__init__` in code\n\n    **indented code**\n")
        assert "bold" not in detect_content_format("A glob **/*.py and 2 ** 3\n")


class TestLeadingBoldRun:
    """The bold run a text opens with is read from the parse, and each reader decides what follows it."""

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_only_a_bold_run_at_the_first_non_space_character_opens_the_text(self):
        run = leading_bold_run("  **Label** - rest")
        assert run is not None and (run.start, run.end, run.marker) == (2, 11, "**")
        assert leading_bold_run("__Label__ - rest") is not None
        assert leading_bold_run("Say **Label** - rest") is None
        assert leading_bold_run("*Label* - rest") is None
        assert leading_bold_run("***Label*** - rest") is None
        assert leading_bold_run("**a ** b") is None
        assert leading_bold_run("") is None

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_title_label_is_a_leading_bold_run_set_off_by_a_colon_or_a_dash(self):
        for text in (
            "**Groups** - Organize",
            "**Groups** \u2014 Organize",
            "**Groups**: Organize",
            "__Groups__: Organize",
        ):
            assert bold_title_label(text) is not None, text
        for text in ("**Pre**-commit hooks", "**Groups** Organize", "Use **Groups**: Organize", "**Groups"):
            assert bold_title_label(text) is None, text
        assert bold_title_label("**a *b* c** - rest") is not None

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_lead_label_is_dropped_with_its_list_marker(self):
        assert without_lead("- **Rule:** keep it short") == "keep it short"
        assert without_lead("1. **Rule**: keep it short") == "keep it short"
        assert without_lead("- [x] Note: keep it short") == "keep it short"
        assert without_lead("__Rule:__ keep it short") == "keep it short"
        assert without_lead("**Rule** keep it short") == "**Rule** keep it short"
        assert without_lead("**Rule**:keep it short") == "**Rule**:keep it short"

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_text_after_a_bold_label_is_read_past_its_separator(self):
        assert _after_bold_label("- **Rules**: run tests") == "run tests"
        assert _after_bold_label("**Rules** \u2014 run tests") == "run tests"
        assert _after_bold_label("**Rules** run tests") == "run tests"
        assert _after_bold_label("**Rules**run tests") is None
        assert _after_bold_label("Rules: run tests") is None

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_bold_definition_label_fronts_a_body_unless_it_is_a_command_verb(self):
        assert _is_structural("**notes.md** - the project notes") is True
        assert _is_structural("**Term**: the project notes") is True
        assert _is_structural("**Two words**: the project notes") is False
        assert _is_structural("**Run**: the project notes") is False
        assert _is_structural("**Term** \u2014 always run the tests") is False


class TestBoldNegation:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_bold_on_a_prohibition_marker_is_not_emphasis(self):
        assert check_specificity("Use **never** and **Refrain from mocking** and **cache** here")[4] == ["cache"]


class TestClassifyStrip:
    """The text the lexical classifier reads loses its emphasis delimiters and one list marker only."""

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_a_leading_number_or_heading_mark_is_part_of_the_text(self):
        assert _strip_md_for_classify("2026 roadmap") == "2026 roadmap"
        assert _strip_md_for_classify("- 2026 roadmap") == "2026 roadmap"
        assert _strip_md_for_classify("1. Run `x`") == "Run x"
        assert _strip_md_for_classify("2 * 3 * 4") == "2 * 3 * 4"
        assert _strip_md_for_classify("**Run** the _tests_") == "Run the tests"


class TestWrappingRuns:
    @pytest.mark.unit
    @pytest.mark.subsys_map
    @pytest.mark.parametrize(
        ("text", "wrapped_by"),
        [
            ("**Never push.**", ["**"]),
            ("  *Never push.*  ", ["*"]),
            ("_Never push._", ["_"]),
            ("***Never push.***", ["*", "**"]),
            ("*a* and *b*", []),
            ("**Never** push.", []),
            ("**Never push**.", []),
            ("a `**b**` c", []),
            ("**a** and **b**", []),
        ],
    )
    def test_runs_that_wrap_all_of_a_text(self, text, wrapped_by):
        assert [run.marker for run in wrapping_runs(text)] == wrapped_by

    @pytest.mark.unit
    @pytest.mark.subsys_map
    @pytest.mark.parametrize(
        ("text", "labelled"),
        [
            ("**Label**: do it", True),
            ("Do it. **Rule** : keep it", True),
            ("**Label:** do it", False),
            ("**Label** - do it", False),
            ("Do **it**: now", True),
            ("Do *it*: now", False),
            ("Do `**it**`: now", False),
        ],
    )
    def test_a_bold_run_followed_by_a_colon_labels_the_text(self, text, labelled):
        assert has_bold_label(text, emphasis_runs(text)) is labelled

    @pytest.mark.unit
    @pytest.mark.subsys_map
    def test_stripping_can_keep_code_spans_as_written(self):
        assert strip_markdown_inline("Run **`make`** and *x*", keep_code=True) == "Run `make` and x"
        assert strip_markdown_inline("Run **`make`** and *x*") == "Run make and x"
