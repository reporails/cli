"""Deterministic prose sentence splitter.

Splits prose into whole sentences at sentence boundaries only — never at inline
commas, colons, or dashes, and never inside an identifier whose period is not a
terminator. Corpus-derived boundary cases live in `test_prose_split_corpus.py`.
"""

from __future__ import annotations

import pytest

from reporails_cli.core.mapper.prose_split import split_prose_sentences


@pytest.mark.unit
@pytest.mark.subsys_map
def test_splits_at_sentence_boundaries() -> None:
    out = split_prose_sentences("Read the file. Do not skip it. Always verify.")
    assert out == ["Read the file.", "Do not skip it.", "Always verify."]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_does_not_split_at_comma_colon_or_dash() -> None:
    text = "Use `ails check` to validate: it runs the full pipeline, end to end — no exceptions."
    assert split_prose_sentences(text) == [text]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_abbreviations_do_not_split() -> None:
    out = split_prose_sentences("Read the config, e.g. config.yml, first. Then run it.")
    assert out == ["Read the config, e.g. config.yml, first.", "Then run it."]


@pytest.mark.unit
@pytest.mark.subsys_map
def test_single_sentence_returns_one_unit() -> None:
    assert split_prose_sentences("A whole single sentence with no boundary") == [
        "A whole single sentence with no boundary"
    ]


# Each row is a boundary class the previous splitter got wrong on measured
# corpus. They go red the moment that behaviour returns.
@pytest.mark.unit
@pytest.mark.subsys_map
@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A period inside an identifier is not a terminator.
        (
            ".claude/rules/, .claude/agents/reviewer.md, .claude/hooks/ are all read.",
            [".claude/rules/, .claude/agents/reviewer.md, .claude/hooks/ are all read."],
        ),
        ("See .ails/backbone.yml for the topology.", ["See .ails/backbone.yml for the topology."]),
        (
            "Do NOT read .env, .env.*, credentials*, or *.key files.",
            ["Do NOT read .env, .env.*, credentials*, or *.key files."],
        ),
        (
            "Narrow to (OSError, yaml.YAMLError, json.JSONDecodeError).",
            ["Narrow to (OSError, yaml.YAMLError, json.JSONDecodeError)."],
        ),
        ("Use pathlib.Path instead of string concatenation.", ["Use pathlib.Path instead of string concatenation."]),
        (
            "normalize(vectors, axis) applies scale(v) to every row.",
            ["normalize(vectors, axis) applies scale(v) to every row."],
        ),
        # A path or filename that genuinely ENDS a sentence still splits.
        (
            "Entries migrate via scripts/pre-release-check.sh. Do not write them directly.",
            ["Entries migrate via scripts/pre-release-check.sh.", "Do not write them directly."],
        ),
        # `etc.` ends a sentence before a capital, continues before lowercase.
        (
            "Rules, skills, agents, etc. The surfaces key adjusts the globs.",
            ["Rules, skills, agents, etc.", "The surfaces key adjusts the globs."],
        ),
        (
            "Use tokens (var(--bg), var(--font), etc.) and nothing else.",
            ["Use tokens (var(--bg), var(--font), etc.) and nothing else."],
        ),
        # An unclosed bracket must not swallow every later boundary.
        (
            "The gate refuses a duplicate id (see the validator. The valid path is a fresh slug.",
            ["The gate refuses a duplicate id (see the validator.", "The valid path is a fresh slug."],
        ),
        # A quoted question used mid-sentence is not a boundary; a closing quote
        # that ends a sentence is.
        (
            'Ask "will this test catch it?" before writing it. Tests catch bugs.',
            ['Ask "will this test catch it?" before writing it.', "Tests catch bugs."],
        ),
        (
            'Do not address outputs to "the reader." Do not conflate the two roles.',
            ['Do not address outputs to "the reader."', "Do not conflate the two roles."],
        ),
        # A multi-sentence quotation carries one instruction per sentence.
        (
            '"Run the linter before pushing. Fix every error it reports."',
            ['"Run the linter before pushing.', 'Fix every error it reports."'],
        ),
    ],
)
def test_boundary_regressions(text: str, expected: list[str]) -> None:
    assert split_prose_sentences(text) == expected


@pytest.mark.unit
@pytest.mark.subsys_map
def test_code_tokens_let_a_lowercase_identifier_open_a_sentence() -> None:
    # Without the token set the lowercase `pytest` reads as a continuation; with
    # it the atom has said `pytest` is a code identifier, so the boundary is real.
    text = "The suite reported PASS. pytest exits non-zero on failure."
    assert split_prose_sentences(text, ["pytest"]) == [
        "The suite reported PASS.",
        "pytest exits non-zero on failure.",
    ]
    assert split_prose_sentences(text) == ["The suite reported PASS. pytest exits non-zero on failure."]
    # An ordinary lowercase word is still a continuation, not a new sentence.
    prose = "The suite reported PASS. pytest exits non-zero on failure."
    assert split_prose_sentences(prose, ["ruff"]) == [prose]
