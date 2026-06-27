"""Unit tests for heal mechanical fixers — backtick-wrap link-context guard."""

from __future__ import annotations

import pytest

from reporails_cli.core.heal.mechanical_fixers import fix_unformatted_code
from reporails_cli.core.platform.dto.ruleset import Atom


def _atom(line: int, text: str, tokens: list[str]) -> Atom:
    return Atom(
        line=line,
        text=text,
        kind="paragraph",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity=0.0,
        unformatted_code=tokens,
        file_path="CLAUDE.md",
    )


class TestBacktickWrapSkipsMarkdownLinks:
    """Regression: heal wrapped tokens inside link labels/targets, producing
    invalid GFM like [`X`](`X`)."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_token_only_inside_link_left_untouched(self) -> None:
        lines = ["See [ENGINE.md](ENGINE.md) for details.\n"]
        atoms = [_atom(1, lines[0], ["ENGINE.md"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "See [ENGINE.md](ENGINE.md) for details.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_occurrence_outside_link_wrapped_link_untouched(self) -> None:
        lines = ["Run ENGINE.md checks; see [ENGINE.md](docs/ENGINE.md).\n"]
        atoms = [_atom(1, lines[0], ["ENGINE.md"])]

        fix_unformatted_code(atoms, lines)

        assert lines[0] == "Run `ENGINE.md` checks; see [ENGINE.md](docs/ENGINE.md).\n"

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_plain_token_still_wrapped(self) -> None:
        lines = ["Use pyproject.toml for config.\n"]
        atoms = [_atom(1, lines[0], ["pyproject.toml"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Use `pyproject.toml` for config.\n"
        assert len(fixes) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_idempotent_on_already_wrapped(self) -> None:
        lines = ["Use `pyproject.toml` for config.\n"]
        atoms = [_atom(1, lines[0], ["pyproject.toml"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Use `pyproject.toml` for config.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_token_only_as_substring_left_untouched(self) -> None:
        """Regression: the substring fallback wrapped a token mid-word (`npm` inside
        `npmrc`), corrupting prose. A token with no word-boundaried occurrence outside
        a link must be left unchanged, not wrapped mid-word."""
        lines = ["Edit your npmrc file by hand.\n"]
        atoms = [_atom(1, lines[0], ["npm"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Edit your npmrc file by hand.\n"
        assert fixes == []
