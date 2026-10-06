"""Mutation-kill tests for core.mapper.parse internals.

Each test feeds an input whose correct output a specific injected operator bug
would change (a wrong structural verdict, a dropped scope flag, a miscounted
reindex, a broken quote/paren mask, a mis-merged charge sign), so the assertion
reddens when that bug returns.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from reporails_cli.core.mapper import parse as p
from reporails_cli.core.platform.dto.ruleset import Atom


def _atom(text: str, *, kind: str = "excitation", fmt: str = "prose", cv: int = 0, charge: str = "NEUTRAL") -> Atom:
    return Atom(
        line=1,
        text=text,
        kind=kind,
        charge=charge,
        charge_value=cv,
        modality="none",
        specificity="abstract",
        plain_text=text,
        format=fmt,
        rule="p0",
    )


# ── _is_structural (L139, L154) ──────────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_non_verb_bold_definition_is_structural() -> None:
    """A `**Term**: desc` whose term is NOT a verb stays a structural definition
    (kills L139 `m and group in verbs` -> `or`, which would un-defn every label)."""
    assert p._is_structural("**Widget**: a small reusable UI element") is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_only_a_whole_line_quotation_is_structural() -> None:
    # A line that IS a quotation stays neutral; a line that merely opens with a quoted
    # term and carries on is running text and keeps its charge.
    assert p._is_structural('"Never push to main."') is True
    assert p._is_structural("\u201cNever push to main.\u201d") is True
    assert p._is_structural('"Feature creep" is a known failure mode; flag it early.') is False


@pytest.mark.unit
@pytest.mark.subsys_map
def test_pipe_reference_line_is_structural() -> None:
    """A prose line shaped like a code|desc table row is structural
    (kills L154 `or pipe_ref` -> `and`)."""
    assert p._is_structural("`build` | the build command", "prose") is True


# ── _classify_content scope flag (L171, L175) ────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_structural_classification_is_not_scope_conditional() -> None:
    """A structural atom returns scope_conditional=False (kills L171 False->True)."""
    result = p._classify_content(
        "**Widget**: a small reusable UI element", "Widget: a small reusable UI element", "prose"
    )
    assert result == ("NEUTRAL", 0, "none", "structural", False)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_third_person_classification_is_not_scope_conditional() -> None:
    """A 3rd-person atom returns scope_conditional=False (kills L175 False->True)."""
    result = p._classify_content("Triggers the build workflow", "Triggers the build workflow", "prose")
    assert result == ("NEUTRAL", 0, "none", "third_person", False)


# ── _drop_contentless_atoms reindex (L213) ───────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_drop_contentless_reindexes_non_heading_atoms() -> None:
    """Surviving non-heading atoms are re-indexed 0..n (kills L213 `!=` -> `==`)."""
    a1 = _atom("foo bar")
    a2 = _atom("baz qux")
    a1.position_index = a2.position_index = 99
    kept = p._drop_contentless_atoms([a1, a2])
    assert [a.position_index for a in kept] == [0, 1]


# ── _ast_is_trivial / _fence_parses_as_code (L259, L265, L283) ───────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_empty_module_is_trivial() -> None:
    """An empty parsed module is trivial (kills L259 True->False)."""
    assert p._ast_is_trivial(ast.parse("")) is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_bare_name_module_is_trivial() -> None:
    """A bare-name expression module is trivial (kills L265 True->False)."""
    assert p._ast_is_trivial(ast.parse("config")) is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_json_body_parses_as_code() -> None:
    """A JSON object body is recognised as code (kills the json-branch True->False)."""
    assert p._fence_parses_as_code('{"a": 1}') is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_toml_body_parses_as_code() -> None:
    """A TOML-only body (not valid JSON) is recognised as code (kills L283 True->False)."""
    assert p._fence_parses_as_code('key = "value"') is True


# ── fence directive routing (L311, L331, L495) ───────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_neutral_text_fence_stays_one_block() -> None:
    """A text fence with no charged line stays a single neutral block, not one atom
    per line (kills L311 `not entries or not any(...)` -> `and`)."""
    content = (
        "```text\n"
        "this is just some descriptive text here and there\n"
        "another plain descriptive line of words present\n"
        "```\n"
    )
    atoms = p.tokenize(content)
    assert len(atoms) == 1
    assert atoms[0].format == "code_block"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_code_declared_fence_is_not_read_as_directive() -> None:
    """A python-declared fence stays a neutral code block even if its body reads
    like an instruction (kills L331 `and` -> `or`, which would read it line-by-line).

    A whole-fence block is literal text, so it is
    also exempt from the neutral-atom embedded-marker scan — never CONSTRAINT, never
    AMBIGUOUS, whatever words its body happens to contain.
    """
    content = "```python\nnever delete the production database right now today\n```\n"
    atoms = p.tokenize(content)
    assert len(atoms) == 1
    assert atoms[0].charge == "NEUTRAL"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_five_char_inline_segment_is_kept() -> None:
    """An inline segment of exactly 5 chars is kept (kills L495 `>=` -> `>`)."""
    assert len(p.tokenize("hello")) == 1


# ── _build_scope_mask (L649, L654, L656, L661) ───────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_scope_mask_exits_straight_quote() -> None:
    """After a closing straight quote, following chars are outside scope
    (kills L649 `in_straight_quote = False` -> True)."""
    mask = p._build_scope_mask('"a" b')
    assert mask[4] is False


@pytest.mark.unit
@pytest.mark.subsys_map
def test_scope_mask_enters_curly_quote() -> None:
    """A char inside a curly quote is in scope (kills L654 `in_curly_quote = True` -> False)."""
    mask = p._build_scope_mask("“a” b")
    assert mask[1] is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_scope_mask_marks_closing_curly() -> None:
    """The closing curly-quote char is itself in scope (kills L656 `mask[i] = True` -> False)."""
    mask = p._build_scope_mask("“a”")
    assert mask[2] is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_scope_mask_parens_all_in_scope() -> None:
    """Every char of a `(...)` group is in scope (kills L661 `and` -> `or`, which
    would decrement paren depth on non-paren chars)."""
    assert p._build_scope_mask("(ab)") == [True, True, True, True]


# ── _segment_structure_aware (L1091) ─────────────────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_list_atom_is_not_sentence_split() -> None:
    """A list-format atom stays whole even with two sentences (kills L1091 `and` -> `or`,
    which would sentence-split non-prose formats)."""
    atom = _atom("First sentence here. Second sentence now.", fmt="list")
    result = p._segment_structure_aware([atom])
    assert len(result) == 1


# ── _scan_charged_for_compound_markers (L1269) ───────────────────────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_charged_atom_is_scanned_for_opposite_markers() -> None:
    """A charged atom is scanned for opposite-direction markers (kills L1269 `==` -> `!=`,
    which would skip every charged atom)."""
    atom = _atom("mention it but never delete it", cv=1, charge="DIRECTIVE")
    p._scan_charged_for_compound_markers([atom])
    assert atom.embedded_charge_markers == ["constraint:never"]


# ── whole-fence atom line must account for frontmatter offset ───


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fence_atom_line_uses_frontmatter_line_offset() -> None:
    content = "---\na: 1\nb: 2\nc: 3\n---\n\nSome intro text.\n\n```python\nprint('hi')\n```\n"
    atoms = p.tokenize(content)
    fence_atoms = [a for a in atoms if a.format == "code_block"]
    assert len(fence_atoms) == 1
    assert fence_atoms[0].line == 9


# ── a neutral whole-fence block must not be promoted to AMBIGUOUS ───


@pytest.mark.unit
@pytest.mark.subsys_map
def test_neutral_shell_fence_stays_neutral_not_ambiguous() -> None:
    content = "```\nmake -C build all\nset -euo pipefail\ndo ./deploy.sh\n```\n"
    atoms = p.tokenize(content)
    assert len(atoms) == 1
    assert atoms[0].format == "code_block"
    assert atoms[0].charge == "NEUTRAL"


# ── an indented (4-space) code block must yield a neutral atom ───


@pytest.mark.unit
@pytest.mark.subsys_map
def test_indented_code_block_yields_single_neutral_atom() -> None:
    content = "Intro text here.\n\n    def f():\n        return 1\n\nMore text after.\n"
    atoms = p.tokenize(content)
    code_atoms = [a for a in atoms if a.format == "code_block"]
    assert len(code_atoms) == 1
    assert code_atoms[0].charge == "NEUTRAL"
    assert "def f():" in code_atoms[0].text
    assert code_atoms[0].line == 3


# ── integration: a real rule file's yaml/markdown fences must not be
# gutted by the body-YAML blanker ───


@pytest.mark.unit
@pytest.mark.subsys_map
def test_real_rule_file_yaml_fence_survives_body_blanking() -> None:
    path = Path(__file__).resolve().parents[2] / "framework" / "rules" / "claude" / "path-scope-declared" / "rule.md"
    content = path.read_text(encoding="utf-8")
    atoms = p.tokenize(content)
    code_atoms = [a for a in atoms if a.format == "code_block"]
    assert any("paths: src/**/*.py" in a.text for a in code_atoms)


# ── code spans and fence bodies are read from the markdown parse ──────


@pytest.mark.unit
@pytest.mark.subsys_map
def test_command_reference_led_by_a_double_backtick_span_is_structural() -> None:
    """A command reference opens with a code span however many backticks delimit it."""
    assert p._is_structural("``git commit -m `x` `` - the commit command") is True
    assert p._is_structural("``make test`` | the test command", "prose") is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_unmatched_backtick_is_not_a_version_note() -> None:
    """A lone backtick before a digit is text, not a code span holding a version."""
    assert p._is_structural("`3 files must be kept in sync") is False
    assert p._is_structural("`3.10` or later") is True
    assert p._is_structural("~3.10 is required") is True


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fence_is_markdown_sample_reads_atx_headings_from_the_parse() -> None:
    assert p._fence_is_markdown_sample("## Audit: {agent}\n\nfindings\n") is True
    assert p._fence_is_markdown_sample("title\n---\nbody\n") is False
    assert p._fence_is_markdown_sample("    # indented comment\n") is False
    assert p._fence_is_markdown_sample("#hashtag\n") is False


@pytest.mark.unit
@pytest.mark.subsys_map
def test_classify_strip_unwraps_double_backtick_spans_and_keeps_unmatched_backticks() -> None:
    from reporails_cli.core.mapper.classify import _strip_md_for_classify

    assert _strip_md_for_classify("Use ``a`b`` and `c` now") == "Use a`b and c now"
    assert _strip_md_for_classify("a ` stray backtick") == "a ` stray backtick"


def _line_of(atoms: list[Atom], needle: str) -> int:
    return next(a.line for a in atoms if needle in a.text)


@pytest.mark.unit
@pytest.mark.subsys_map
def test_atom_lines_follow_a_code_span_that_runs_onto_the_next_line() -> None:
    src = "# Docs\n\nRun `make\nbuild` first.\nNever edit main.py here.\nAlways read [the guide](a.md) first.\n"
    atoms = p.tokenize(src)
    assert _line_of(atoms, "Never edit") == 5
    assert _line_of(atoms, "Always read") == 6


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "link",
    [
        '[the guide](docs/a.md\n"Guide")',
        "[the\nguide](docs/a.md)",
        '[the\nguide](docs/a.md\n"Guide")',
        "<https://x.com/a\nb>",
    ],
)
def test_atom_lines_follow_a_link_that_runs_onto_the_next_line(link: str) -> None:
    src = f"# Project\n\nSee {link} and run setup.py once.\nNever edit **setup.py** by hand.\n"
    atoms = p.tokenize(src)
    assert _line_of(atoms, "Never edit") == src.split("\n").index("Never edit **setup.py** by hand.") + 1


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("sep", ["\x0c", chr(0x2028)])
def test_fence_lines_keep_their_numbers_past_a_line_separator(sep: str) -> None:
    src = f"# Docs\n\n```text\nNever edit main.py{sep}here now.\nAlways run the tests first.\n```\n"
    atoms = p.tokenize(src)
    assert _line_of(atoms, "Always run") == 5
