"""Fence-handling cascade in the atomizer.

A fence whose tag declares code, or whose untagged body parses as JSON / TOML /
Python, stays a single neutral `code_block` atom. A text or untagged fence whose
lines carry an instruction is read line-by-line so the instruction is scored; a
text fence with no instruction stays a neutral block.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.parse import tokenize


def _fence_atoms(atoms):
    return [a for a in atoms if a.format == "code_block"]


def _charges(atoms):
    return [a.charge for a in _fence_atoms(atoms)]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_tagged_code_stays_one_neutral_block() -> None:
    md = "```python\ndef f(x):\n    return x + 1\n```\n"
    atoms = _fence_atoms(tokenize(md))
    assert len(atoms) == 1
    assert atoms[0].charge == "NEUTRAL"
    assert atoms[0].plain_text == "code_block:python"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_diagram_tag_stays_neutral() -> None:
    md = "```mermaid\ngraph TD\n  A-->B\n```\n"
    assert _charges(tokenize(md)) == ["NEUTRAL"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_untagged_json_body_stays_neutral() -> None:
    md = '```\n{"key": "value", "n": 42}\n```\n'
    assert _charges(tokenize(md)) == ["NEUTRAL"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_untagged_toml_body_stays_neutral() -> None:
    md = '```\ntitle = "cfg"\nport = 8080\n```\n'
    assert _charges(tokenize(md)) == ["NEUTRAL"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_untagged_directive_is_atomized_and_charged() -> None:
    md = "```\nDo not skim the file.\nAlways read it in full.\n```\n"
    charges = _charges(tokenize(md))
    assert "CONSTRAINT" in charges
    assert "DIRECTIVE" in charges
    assert "NEUTRAL" not in charges


@pytest.mark.unit
@pytest.mark.subsys_map
def test_text_tagged_prohibition_is_charged() -> None:
    md = "```text\nNever commit secrets to the repo.\n```\n"
    atoms = _fence_atoms(tokenize(md))
    assert [a.charge for a in atoms] == ["CONSTRAINT"]
    assert atoms[0].charge_value < 0


@pytest.mark.unit
@pytest.mark.subsys_map
def test_untagged_plain_prose_stays_neutral_block() -> None:
    md = "```\nThis is just an example output line here.\n```\n"
    assert _charges(tokenize(md)) == ["NEUTRAL"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fenced_directive_keeps_code_block_format() -> None:
    # A recovered fenced instruction stays flagged as fenced, so downstream
    # amplitude keeps the container in view rather than seeing bare prose.
    md = "```\nDo not delete the config.\n```\n"
    atoms = _fence_atoms(tokenize(md))
    assert atoms and all(a.format == "code_block" for a in atoms)
    assert atoms[0].charge == "CONSTRAINT"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fenced_directive_line_numbers_track_the_block() -> None:
    md = "# Heading\n\nIntro line of prose here.\n\n```\nAlways verify the output.\n```\n"
    atoms = [a for a in tokenize(md) if a.format == "code_block"]
    assert atoms
    # The instruction sits on the line after the opening fence, not line 0.
    assert atoms[0].line >= 6


# ── emphasis-wrapped fenced prohibition is scored, not neutralized ─────────
# The gate and the emitted atom must classify a fenced line identically, off a
# markdown-STRIPPED plain form, so an emphasis-wrapped fenced prohibition (`**never** …`) scores
# CONSTRAINT on every bold/italic/backtick-wrapped fence.


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    "body",
    [
        "**never** touch the production database",
        "*never* commit secrets to the repository",
        "`never` run the migration against prod",
        "**do not** skip the review step here",
    ],
)
def test_emphasis_wrapped_fenced_prohibition_is_charged(body: str) -> None:
    md = f"```\n{body}\n```\n"
    atoms = _fence_atoms(tokenize(md))
    assert [a.charge for a in atoms] == ["CONSTRAINT"]
    assert atoms[0].charge_value == -1


@pytest.mark.unit
@pytest.mark.subsys_map
def test_fenced_atom_plain_text_is_markdown_stripped() -> None:
    # The display `text` keeps the literal fenced markdown; the `plain_text` fed
    # to classify/embed is stripped, so `**never**` classifies as the word it is.
    md = "```\n**never** touch prod\n```\n"
    atom = _fence_atoms(tokenize(md))[0]
    assert atom.text == "**never** touch prod"
    assert atom.plain_text == "never touch prod"


# ── an explicit ```markdown / ```md tag is a demo surface, not a directive ─


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("tag", ["markdown", "md"])
def test_markdown_tagged_demo_is_not_scored_as_directive(tag: str) -> None:
    # A rule/doc file demonstrating an anti-pattern inside a ```markdown fence
    # must NOT emit a live CONSTRAINT/DIRECTIVE atom. The tag
    # marks declared markup, so the block stays one non-directive atom (the
    # embedded-marker scanner may tag it AMBIGUOUS, as it does any code fence
    # carrying charge words — it is excluded from directive diagnostics).
    md = f"```{tag}\nNever commit secrets to the repository.\n```\n"
    atoms = _fence_atoms(tokenize(md))
    assert len(atoms) == 1
    assert atoms[0].charge not in ("CONSTRAINT", "DIRECTIVE", "IMPERATIVE")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_untagged_and_text_fenced_directive_still_scored() -> None:
    # Coverage preserved: the dominant untagged case and a `text`-tagged directive
    # still score, so tightening `markdown`/`md` drops no real coverage.
    for md in [
        "```\nNever commit secrets to the repository.\n```\n",
        "```text\nNever commit secrets to the repository.\n```\n",
    ]:
        assert _charges(tokenize(md)) == ["CONSTRAINT"]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_tree_diagram_text_fence_stays_one_neutral_block() -> None:
    # A layout tree in a `text` fence: its rows open with box-drawing glyphs and
    # carry file names, not instructions. `├── test-procedure.md` must not charge
    # as a "test" imperative and become a remediation target.
    md = (
        "## Layout\n\n```text\ntests/skills/\n├── CLAUDE.md            # this file\n"
        "└── <skill>/             # one directory per skill under test\n    ├── test-procedure.md\n"
        "    └── fixture/\n```\n"
    )
    atoms = [a for a in tokenize(md) if a.kind != "heading"]
    assert len(atoms) == 1
    assert (atoms[0].format, atoms[0].charge) == ("code_block", "NEUTRAL")


@pytest.mark.unit
@pytest.mark.subsys_map
def test_arrow_flow_diagram_fence_stays_one_neutral_block() -> None:
    md = (
        "## Workflow\n\n```\nLead spawns team for build:\n  Research Analyst -> discovers components (parallel)\n"
        "  Prompt Engineer -> writes instructions\n```\n"
    )
    atoms = [a for a in tokenize(md) if a.kind != "heading"]
    assert [(a.format, a.charge) for a in atoms] == [("code_block", "NEUTRAL")]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_untagged_shell_snippet_stays_one_neutral_block() -> None:
    # An untagged fence holding a shell loop: `for` / `echo` / `done` lines are shell,
    # not imperatives to the model. The loop-3 head listed such lines as targets.
    md = (
        "Run this loop:\n\n```\nfor agent in $(uv run python -c \"print('x')\"); do\n"
        '  echo "=== Auditing $agent ==="\n  # invoke /audit-agent $agent\ndone\n```\n'
    )
    fenced = [a for a in tokenize(md) if a.format == "code_block"]
    assert len(fenced) == 1
    assert fenced[0].charge == "NEUTRAL"


@pytest.mark.unit
@pytest.mark.subsys_map
def test_untagged_text_fence_with_a_directive_is_still_read() -> None:
    # The shell gate must not swallow the channel-2 case: prose in an untagged fence.
    md = "```\nNever commit secrets to the repository.\nAlways run the tests first.\n```\n"
    fenced = [a for a in tokenize(md) if a.format == "code_block"]
    assert len(fenced) == 2
    assert {a.charge for a in fenced} != {"NEUTRAL"}


@pytest.mark.unit
@pytest.mark.subsys_map
def test_lowercase_imperative_fence_is_not_swallowed_as_shell() -> None:
    # `do not …` / `make sure …` open with words that are ALSO shell commands (`do`,
    # `make`), but as prose directives they carry no shell co-signal (no flag / path /
    # var / EOL loop keyword). The fence must be read line-by-line and scored, not
    # misclassified as a shell block and silently dropped from scoring.
    md = "```\ndo not edit CLAUDE.md directly\nmake sure every file is named\n```\n"
    fenced = [a for a in tokenize(md) if a.format == "code_block"]
    assert len(fenced) == 2
    assert {a.charge for a in fenced} != {"NEUTRAL"}


@pytest.mark.unit
@pytest.mark.subsys_map
def test_shell_gate_ignores_spaced_pipe_in_table_and_prose() -> None:
    # REGRESSION: a ' | ' spaced pipe (every markdown table row, and prose) must not
    # signal a shell line — otherwise a fenced table matched _SHELL_LINE_RE on every row and the
    # whole fence was read as a neutral shell block, silencing every directive in it.
    from reporails_cli.core.mapper.parse import _fence_looks_like_shell

    assert _fence_looks_like_shell("| Always commit | before push |\n| Never force | to main |") is False
    assert _fence_looks_like_shell("Use the A | B pattern here") is False
    # A real piped command still reads as shell (via its leading command word / operators).
    assert _fence_looks_like_shell("cat run.sh | grep x\nfor f in *; do echo $f; done") is True


@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize("tag", ["", "text"])
def test_markdown_document_sample_stays_one_neutral_block(tag: str) -> None:
    # A report template the agent prints, in a fence with no markdown tag: its heading lines
    # mark a markdown document, the same demonstration surface a ```markdown fence is.
    # `## Audit: {agent}` must not charge as an "Audit" imperative, and no template line may
    # become a finding target.
    md = (
        f"Print a structured report:\n\n```{tag}\n## Audit: {{agent}} ({{date}})\n\n"
        "### Possibly stale (in matrix, NOT found in docs)\n"
        "- plugins: No documentation found for plugin support\n```\n"
    )
    fenced = [a for a in tokenize(md) if a.format == "code_block"]
    assert len(fenced) == 1
    assert fenced[0].charge not in ("CONSTRAINT", "DIRECTIVE", "IMPERATIVE")
