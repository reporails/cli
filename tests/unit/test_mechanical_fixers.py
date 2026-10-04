"""Unit tests for heal mechanical fixers — backtick-wrap link-context guard."""

from __future__ import annotations

from pathlib import Path

import pytest

from reporails_cli.core.heal.mechanical_fixers import (
    apply_mechanical_fixes,
    fix_bold_on_constraints,
    fix_italic_constraints,
    fix_unformatted_code,
)
from reporails_cli.core.mapper.annotate import check_specificity
from reporails_cli.core.platform.dto.ruleset import Atom, RulesetMap


def _atom(line: int, text: str, tokens: list[str], fmt: str = "prose") -> Atom:
    return Atom(
        line=line,
        text=text,
        kind="paragraph",
        charge="NEUTRAL",
        charge_value=0,
        modality="none",
        specificity="abstract",
        unformatted_code=tokens,
        file_path="CLAUDE.md",
        format=fmt,
    )


def _constraint_atom(line: int, text: str, fmt: str = "prose", kind: str = "paragraph") -> Atom:
    return Atom(
        line=line,
        text=text,
        kind=kind,
        charge="CONSTRAINT",
        charge_value=-1,
        modality="none",
        specificity="abstract",
        bold_tokens=check_specificity(text)[4],
        file_path="CLAUDE.md",
        format=fmt,
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


class TestBacktickWrapCoversFullRelativePath:
    """Regression: the detector's `unformatted_code` token is a path's basename
    (`\\w+.ext` stops at `/`), so wrapping only the token backticked the basename —
    `tests/unit/`test_parser.py`` — instead of the full relative path."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_basename_token_wraps_the_full_relative_path(self) -> None:
        lines = ["Run tests/unit/test_parser.py to check the parser.\n"]
        atoms = [_atom(1, lines[0], ["test_parser.py"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Run `tests/unit/test_parser.py` to check the parser.\n"
        assert len(fixes) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_idempotent_on_already_wrapped_full_path(self) -> None:
        lines = ["Run `tests/unit/test_parser.py` to check the parser.\n"]
        atoms = [_atom(1, lines[0], ["test_parser.py"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Run `tests/unit/test_parser.py` to check the parser.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_plain_basename_with_no_path_prefix_unaffected(self) -> None:
        lines = ["Use pyproject.toml for config.\n"]
        atoms = [_atom(1, lines[0], ["pyproject.toml"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Use `pyproject.toml` for config.\n"
        assert len(fixes) == 1


class TestBacktickWrapHandlesTildeAndUrls:
    """Regression: the leftward path-run extension stopped at `~`, so
    `Edit ~/.claude/settings.json` became `Edit ~`/.claude/settings.json``, and a
    bare URL (`https://host/x.py`) got `https:` plus a backticked `//host/x.py`
    span — wrapping part of a URL breaks it instead of formatting it."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_tilde_path_wrapped_whole(self) -> None:
        lines = ["Edit ~/.claude/settings.json by hand.\n"]
        atoms = [_atom(1, lines[0], ["settings.json"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Edit `~/.claude/settings.json` by hand.\n"
        assert len(fixes) == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_tilde_path_idempotent_apply_twice(self) -> None:
        lines = ["Edit ~/.claude/settings.json by hand.\n"]
        atoms = [_atom(1, lines[0], ["settings.json"])]

        fix_unformatted_code(atoms, lines)
        second_fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Edit `~/.claude/settings.json` by hand.\n"
        assert second_fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_url_token_left_unwrapped(self) -> None:
        lines = ["Fetch https://host/x.py for the script.\n"]
        atoms = [_atom(1, lines[0], ["x.py"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Fetch https://host/x.py for the script.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_url_token_idempotent_apply_twice(self) -> None:
        lines = ["Fetch https://host/x.py for the script.\n"]
        atoms = [_atom(1, lines[0], ["x.py"])]

        fix_unformatted_code(atoms, lines)
        second_fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Fetch https://host/x.py for the script.\n"
        assert second_fixes == []


class TestBacktickWrapLeavesImportReferencesAlone:
    """Regression: wrapping an `@path` reference in backticks hides it from
    `extract_imports` (it strips inline code spans before scanning), so a broken
    import's `CORE:S:0024` finding silently disappears once heal "fixes" it."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_unresolved_import_reference_left_unwrapped(self) -> None:
        lines = ["See @docs/setup.md for the routine.\n"]
        atoms = [_atom(1, lines[0], ["setup.md"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "See @docs/setup.md for the routine.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_a_plain_path_next_to_an_import_still_wraps(self) -> None:
        """Regression guard: the import-span skip must not swallow an unrelated
        code token elsewhere on the same line."""
        lines = ["See @docs/setup.md, then edit pyproject.toml.\n"]
        atoms = [_atom(1, lines[0], ["setup.md", "pyproject.toml"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "See @docs/setup.md, then edit `pyproject.toml`.\n"
        assert len(fixes) == 1


class TestBacktickWrapLeavesUrlWithPortAlone:
    """Regression: a URL carrying a port number (`https://host:8080/x.py`) stopped
    the leftward path-run extension at the port's `:`, not the scheme's, so the
    guard for a bare scheme+`//` never triggered and the URL got split — the
    scheme left bare, the remainder backticked."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_url_with_port_left_unwrapped(self) -> None:
        lines = ["Fetch https://host:8080/x.py before you start.\n"]
        atoms = [_atom(1, lines[0], ["x.py"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Fetch https://host:8080/x.py before you start.\n"
        assert fixes == []


class TestBacktickWrapSkipsProseNames:
    """Regression: the code-shape and known-token heuristics catch capitalised
    product names (`JavaScript`, `DevTools`, `PyPI`) and a bare `git` used as an
    ordinary word — none of them a file, command or identifier this project
    defines — and backtick-wrap them as if they were code."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_prose_product_names_left_unwrapped(self) -> None:
        lines = ["Read the JavaScript guide, open DevTools, then check PyPI.\n"]
        atoms = [_atom(1, lines[0], ["javascript", "DevTools", "PyPI"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Read the JavaScript guide, open DevTools, then check PyPI.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_git_used_as_a_word_left_unwrapped(self) -> None:
        lines = ["This works similar to a git diff.\n"]
        atoms = [_atom(1, lines[0], ["git"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "This works similar to a git diff.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_real_code_names_still_wrap(self) -> None:
        """Do not narrow detection: a real file, path or identifier still gets
        backtick-wrapped — only the curated prose-name set is skipped."""
        lines = ["Use pyproject.toml for config.\n"]
        atoms = [_atom(1, lines[0], ["pyproject.toml"])]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "Use `pyproject.toml` for config.\n"
        assert len(fixes) == 1


class TestBacktickWrapSkipsTableRows:
    """Regression: backtick-wrapping a table cell changes its length, breaking the
    row's column padding."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_table_row_token_left_unwrapped(self) -> None:
        lines = ["| Setting | pyproject.toml | Notes |\n"]
        atoms = [_atom(1, lines[0], ["pyproject.toml"], fmt="table")]

        fixes = fix_unformatted_code(atoms, lines)

        assert lines[0] == "| Setting | pyproject.toml | Notes |\n"
        assert fixes == []


class TestItalicConstraintSkipsAlreadyEmphasisedUnderscoreBold:
    """Regression: a line already bold via underscore (`__Never__ commit
    secrets.`) was nested inside a new italic wrap (`*__Never__ commit
    secrets.*`) because the guard only recognised `**star**` bold."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_underscore_bold_left_unwrapped(self) -> None:
        lines = ["__Never__ commit secrets.\n"]
        atoms = [_constraint_atom(1, lines[0])]

        fixes = fix_italic_constraints(atoms, lines)

        assert lines[0] == "__Never__ commit secrets.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_plain_constraint_still_wraps(self) -> None:
        lines = ["Never skip the tests.\n"]
        atoms = [_constraint_atom(1, lines[0])]

        fixes = fix_italic_constraints(atoms, lines)

        assert lines[0] == "*Never skip the tests.*\n"
        assert len(fixes) == 1


class TestItalicConstraintSkipsWholeBullets:
    """Regression: a bulleted prohibition was italicised whole — heavier styling
    than the line warrants — instead of being left as written."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_list_item_constraint_left_unwrapped(self) -> None:
        lines = ["- Never commit credentials to the repo.\n"]
        atoms = [_constraint_atom(1, lines[0], fmt="list")]

        fixes = fix_italic_constraints(atoms, lines)

        assert lines[0] == "- Never commit credentials to the repo.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_numbered_item_constraint_left_unwrapped(self) -> None:
        lines = ["1. Never commit credentials to the repo.\n"]
        atoms = [_constraint_atom(1, lines[0], fmt="numbered")]

        fixes = fix_italic_constraints(atoms, lines)

        assert lines[0] == "1. Never commit credentials to the repo.\n"
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_table_row_constraint_left_unwrapped(self) -> None:
        lines = ["| a | Never do X | c |\n"]
        atoms = [_constraint_atom(1, lines[0], fmt="table")]

        fixes = fix_italic_constraints(atoms, lines)

        assert lines[0] == "| a | Never do X | c |\n"
        assert fixes == []


class TestItalicConstraintWrapsTheSentence:
    """A prohibition is wrapped as its own sentence, never as the raw line: a plain
    directive next to it stays plain, and a sentence broken over two lines is one run."""

    @staticmethod
    def _heal(raw: list[str], atoms: list[Atom]) -> tuple[list[str], list]:
        lines = list(raw)
        return lines, fix_italic_constraints(atoms, lines)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_directive_before_the_prohibition_stays_outside_the_italic(self) -> None:
        raw = ["Run `uv run pytest` before every commit. Never skip the `ruff` check on generated files.\n"]
        atoms = [_constraint_atom(1, "Never skip the `ruff` check on generated files.")]

        lines, fixes = self._heal(raw, atoms)

        assert lines == ["Run `uv run pytest` before every commit. *Never skip the `ruff` check on generated files.*\n"]
        assert [f.fix_type for f in fixes] == ["italic_constraint"]
        assert fixes[0].before == raw[0].rstrip()
        assert fixes[0].after == lines[0].rstrip()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_sentence_broken_over_two_lines_is_one_italic_run(self) -> None:
        raw = ["Keep the changelog current and never\n", "rewrite published entries in `CHANGELOG.md` after release.\n"]
        atoms = [_constraint_atom(1, "and never")]

        lines, fixes = self._heal(raw, atoms)

        assert lines == [
            "*Keep the changelog current and never\n",
            "rewrite published entries in `CHANGELOG.md` after release.*\n",
        ]
        assert len(fixes) == 1
        assert fixes[0].line == 1
        assert fixes[0].before == "".join(raw).rstrip()
        assert fixes[0].after == "".join(lines).rstrip()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_second_pass_changes_nothing(self) -> None:
        raw = [
            "Run it before every commit. Never skip the check.\n",
            "\n",
            "Keep the changelog current and never\n",
            "rewrite published entries after release.\n",
        ]
        atoms = [_constraint_atom(1, "Never skip the check."), _constraint_atom(3, "and never")]
        lines, first = self._heal(raw, atoms)
        again = list(lines)

        second = fix_italic_constraints(atoms, again)

        assert len(first) == 2
        assert second == []
        assert again == lines

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_each_prohibition_sentence_on_a_line_is_wrapped_on_its_own(self) -> None:
        raw = ["Keep it short. Never push to main. Do not force.\n"]
        atoms = [_constraint_atom(1, "Never push to main."), _constraint_atom(1, "Do not force.")]

        lines, fixes = self._heal(raw, atoms)

        assert lines == ["Keep it short. *Never push to main.* *Do not force.*\n"]
        assert len(fixes) == 1
        assert fixes[0].before == raw[0].rstrip()

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_blockquote_sentence_keeps_its_quote_marker(self) -> None:
        raw = ["> Never delete the cache\n", "> by hand.\n"]
        atoms = [_constraint_atom(1, "Never delete the cache by hand.", fmt="blockquote")]

        lines, _ = self._heal(raw, atoms)

        assert lines == ["> *Never delete the cache\n", "> by hand.*\n"]

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        "raw",
        [
            ["Run it, e.g. now. Never skip it.\n"],  # abbreviation: the sentence start is unclear
            ["*Do not pad. Do not repeat.*\n"],  # one emphasis run across two sentences
            ["Keep it short. *Never pad.*\n"],
        ],
    )
    def test_unclear_sentence_boundary_is_left_as_written(self, raw: list[str]) -> None:
        atoms = [_constraint_atom(1, "Never skip it." if "skip" in raw[0] else "Do not repeat.")]

        lines, fixes = self._heal(raw, atoms)

        assert lines == raw
        assert fixes == []


class TestItalicConstraintSkipsUnderscoreEmphasis:
    """Underscore emphasis counts like the star forms; a `snake_case_name` is not emphasis."""

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        "line",
        [
            "__Never__ commit secrets.",
            "_Do not skip tests._",
            "Do not skip _tests_ before release.",
            "Never commit __secrets__ to the repo.",
        ],
    )
    def test_underscore_emphasis_is_left_alone(self, line: str) -> None:
        lines = [line + "\n"]

        fixes = fix_italic_constraints([_constraint_atom(1, line)], lines)

        assert lines == [line + "\n"]
        assert fixes == []

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_snake_case_name_is_not_taken_for_emphasis(self) -> None:
        lines = ["Never rename my_snake_case_name now.\n"]

        fixes = fix_italic_constraints([_constraint_atom(1, lines[0].strip())], lines)

        assert lines == ["*Never rename my_snake_case_name now.*\n"]
        assert len(fixes) == 1


class TestCodeTokenKeepsUnderscoreCloser:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_trailing_underscore_closer_stays_outside_the_code_span(self) -> None:
        lines = ["_Do not skip tests._\n"]

        fix_unformatted_code([_atom(1, lines[0].strip(), ["tests._"])], lines)

        assert lines == ["_Do not skip `tests`._\n"]


class TestCodeTokenNeverSplitsAUrl:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize(
        ("line", "tokens"),
        [
            ("Fetch https://host:8080/x.py before you start.", ["8080/x.py", "x.py"]),
            ("Fetch https://user@host/x.py before you start.", ["host/x.py", "x.py"]),
            ("Fetch https://host/~me/x.py before you start.", ["me/x.py", "x.py"]),
            ("Fetch https://host/a%20b/x.py before you start.", ["b/x.py", "x.py"]),
            ("Fetch [the file](https://host/x.py) or <https://host/y.py> now.", ["x.py", "y.py"]),
            ("Fetch https://host/x.py before you start.", ["x.py"]),
        ],
    )
    def test_token_inside_a_url_is_left_unwrapped(self, line: str, tokens: list[str]) -> None:
        for token in tokens:
            lines = [line + "\n"]

            fixes = fix_unformatted_code([_atom(1, line, [token])], lines)

            assert lines == [line + "\n"], token
            assert fixes == []


class TestBoldToItalicLeavesLabelsAlone:
    """A bold label stays bold whether its colon sits inside or after the bold."""

    @staticmethod
    def _run(line: str) -> tuple[str, int]:
        lines = [line]
        fixes = fix_bold_on_constraints([_constraint_atom(1, line)], lines)
        return lines[0], len(fixes)

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_label_with_colon_inside_bold_stays(self) -> None:
        text, count = self._run("**EXCLUDE:**\n")
        assert text == "**EXCLUDE:**\n"
        assert count == 0

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_label_with_trailing_text_keeps_its_label(self) -> None:
        text, count = self._run("**Security note:** Never store the key.\n")
        assert text == "**Security note:** Never store the key.\n"
        assert count == 0

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_label_with_colon_after_bold_stays(self) -> None:
        text, count = self._run("**Label**: do not store the key.\n")
        assert text == "**Label**: do not store the key.\n"
        assert count == 0

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_non_label_bold_still_becomes_italic(self) -> None:
        text, count = self._run("Do not commit the **vault** file.\n")
        assert text == "Do not commit the *vault* file.\n"
        assert count == 1

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    def test_label_and_second_bold_term_changes_only_the_second(self) -> None:
        text, count = self._run("**Reason:** do not commit the **vault** file.\n")
        assert text == "**Reason:** do not commit the *vault* file.\n"
        assert count == 1


def _map_of(*atoms: Atom) -> RulesetMap:
    return RulesetMap(
        schema_version="1", embedding_model="m", generated_at="2026-01-01T00:00:00Z", files=(), atoms=atoms
    )


_SETTINGS = '{\n  "hooks": {\n    "SessionStart": [\n      {"command": "$CLAUDE_PROJECT_DIR/hook.sh"}\n    ]\n  }\n}\n'


def _project_with_settings(root: Path) -> tuple[Path, Path, RulesetMap]:
    md = root / "CLAUDE.md"
    md.write_text("Run build.sh before committing.\n", encoding="utf-8")
    settings = root / ".claude" / "settings.json"
    settings.parent.mkdir()
    settings.write_text(_SETTINGS, encoding="utf-8")
    prose = _atom(1, "Run build.sh before committing.", ["build.sh"]).model_copy(update={"file_path": str(md)})
    wiring = _atom(3, '"SessionStart": [', ["SessionStart"]).model_copy(update={"file_path": str(settings)})
    return md, settings, _map_of(prose, wiring)


class TestConfigFilesGetNoFix:
    """A machine-config file is not instruction text, so no fixer edits it."""

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    @pytest.mark.parametrize("dry_run", [True, False])
    def test_only_the_markdown_file_is_fixed(self, tmp_path: Path, dry_run: bool) -> None:
        md, settings, ruleset = _project_with_settings(tmp_path)
        fixes = apply_mechanical_fixes(ruleset, tmp_path, dry_run=dry_run)
        assert {f.file_path for f in fixes} == {str(md)}
        assert settings.read_text(encoding="utf-8") == _SETTINGS

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_an_allowed_config_file_still_gets_no_fix(self, tmp_path: Path) -> None:
        _md, settings, ruleset = _project_with_settings(tmp_path)
        assert apply_mechanical_fixes(ruleset, tmp_path, allowed_files={settings.resolve()}) == []
        assert settings.read_text(encoding="utf-8") == _SETTINGS


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_the_remedy_brief_offers_no_fix_for_a_config_file(tmp_path: Path) -> None:
    from reporails_cli.interfaces.mcp.remedy_brief import mechanical_fixes_for

    md, settings, ruleset = _project_with_settings(tmp_path)
    assert mechanical_fixes_for([(settings, ruleset, None, ([], []))], tmp_path) == []
    assert [f["file"] for f in mechanical_fixes_for([(md, ruleset, None, ([], []))], tmp_path)] == ["CLAUDE.md"]


class TestLibraryNameInProseIsWrappedOnlyWhenBackticked:
    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("name", ["FastAPI", "WebSocket"])
    def test_a_name_never_backticked_in_the_file_is_left_alone(self, name: str) -> None:
        lines = [f"The service is built with {name} for streaming.\n"]
        original = list(lines)

        assert fix_unformatted_code([_atom(1, lines[0], [name])], lines) == []
        assert lines == original

    @pytest.mark.unit
    @pytest.mark.subsys_lint
    @pytest.mark.parametrize("name", ["FastAPI", "WebSocket"])
    def test_a_name_backticked_elsewhere_in_the_file_is_wrapped(self, name: str) -> None:
        lines = [f"The service is built with {name} for streaming.\n", f"Start the `{name}` app first.\n"]
        atoms = [_atom(1, lines[0], [name]), _atom(2, lines[1], []).model_copy(update={"named_tokens": [name]})]

        assert len(fix_unformatted_code(atoms, lines)) == 1
        assert lines[0] == f"The service is built with `{name}` for streaming.\n"


class TestFixersReadPlacesFromTheMarkdownParse:
    """Code, links and plain paragraphs are located by the markdown parse, not by a line prefix."""

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_token_inside_a_longer_code_span_is_not_wrapped_again(self) -> None:
        lines = ["Use `run build.sh now` then build.sh again.\n"]

        fixes = fix_unformatted_code([_atom(1, lines[0], ["build.sh"])], lines)

        assert len(fixes) == 1
        assert lines[0] == "Use `run build.sh now` then `build.sh` again.\n"

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_token_in_the_label_of_a_reference_link_is_left_alone(self) -> None:
        lines = ["See [the build.sh guide][guide] now.\n", "\n", "[guide]: https://example.com/guide\n"]
        original = list(lines)

        assert fix_unformatted_code([_atom(1, lines[0], ["build.sh"])], lines) == []
        assert lines == original

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_token_in_a_link_reference_definition_is_left_alone(self) -> None:
        lines = ["See [guide].\n", "\n", "[guide]: docs/build.sh\n"]
        original = list(lines)

        assert fix_unformatted_code([_atom(3, lines[2], ["build.sh"])], lines) == []
        assert lines == original

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_constraint_inside_a_longer_fence_is_left_alone(self) -> None:
        lines = ["````\n", "```\n", "Never edit this.\n", "```\n", "````\n"]
        original = list(lines)

        assert fix_italic_constraints([_constraint_atom(3, lines[2])], lines) == []
        assert lines == original

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_constraint_inside_a_tilde_fence_is_left_alone(self) -> None:
        lines = ["~~~~\n", "Never edit this.\n", "~~~~\n"]
        original = list(lines)

        assert fix_italic_constraints([_constraint_atom(2, lines[1])], lines) == []
        assert lines == original

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_constraint_in_an_indented_code_block_is_left_alone(self) -> None:
        lines = ["Example:\n", "\n", "    Never edit this.\n"]
        original = list(lines)

        assert fix_italic_constraints([_constraint_atom(3, lines[2])], lines) == []
        assert lines == original

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_prose_constraint_below_a_fence_is_still_wrapped(self) -> None:
        lines = ["~~~~\n", "code\n", "~~~~\n", "\n", "Never skip the tests.\n"]

        assert len(fix_italic_constraints([_constraint_atom(5, lines[4])], lines)) == 1
        assert lines[4] == "*Never skip the tests.*\n"

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_full_stop_inside_a_double_backtick_span_is_not_a_sentence_end(self) -> None:
        lines = ["Never run ``a. b`` in prod.\n"]

        assert len(fix_italic_constraints([_constraint_atom(1, lines[0])], lines)) == 1
        assert lines[0] == "*Never run ``a. b`` in prod.*\n"


class TestBoldLineWholeAfterItsContainerMarkers:
    """A line that is bold from end to end is left alone wherever its text starts: after a quote's
    `>`, a list marker of any kind or a quote inside a list item. A line outside inline text (a fence)
    has no emphasis to change."""

    @staticmethod
    def _run(*lines: str) -> list[str]:
        out = [line + "\n" for line in lines]
        atoms = [_constraint_atom(n + 1, line) for n, line in enumerate(lines)]
        fix_bold_on_constraints(atoms, out)
        return [line.rstrip("\n") for line in out]

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    @pytest.mark.parametrize(
        "line",
        [
            "> **Secrets must not be committed**",
            "> > **Secrets must not be committed**",
            "- > **Secrets must not be committed**",
            ">- **Secrets must not be committed**",
            "1) **Secrets must not be committed**",
            "-\t**Secrets must not be committed**",
            "+ **Secrets must not be committed**",
            "10. **Secrets must not be committed**",
        ],
    )
    def test_whole_bold_line_stays(self, line: str) -> None:
        assert self._run(line) == [line]

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_bold_in_a_fenced_line_is_not_emphasis(self) -> None:
        lines = ["```", "- Do not push **now**", "```"]
        assert self._run(*lines) == lines

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_part_of_a_list_line_still_becomes_italic(self) -> None:
        assert self._run("- Do not push **now**") == ["- Do not push *now*"]


class TestItalicWrapSkipsAQuotesMarkers:
    @pytest.mark.unit
    @pytest.mark.subsys_heal
    @pytest.mark.parametrize("marker", ["> ", ">   ", ">\t", "> > "])
    def test_wrap_opens_after_the_quote_markers(self, marker: str) -> None:
        lines = [f"{marker}Never commit secrets,\n", f"{marker}and do not push to main.\n"]
        fixes = fix_italic_constraints([_constraint_atom(1, "Never commit secrets, and do not push to main.")], lines)
        assert len(fixes) == 1
        assert lines == [f"{marker}*Never commit secrets,\n", f"{marker}and do not push to main.*\n"]


class TestBoldToItalicChangesTheRunsTheAtomNames:
    """The bold fix rewrites the bold runs of the markdown parse that the atom's `bold_tokens` name."""

    @staticmethod
    def _run(line: str) -> str:
        lines = [line + "\n"]
        fix_bold_on_constraints([_constraint_atom(1, line)], lines)
        return lines[0].rstrip("\n")

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    @pytest.mark.parametrize(
        ("line", "after"),
        [
            ("Never log __the token__ here", "Never log *the token* here"),
            ("Never log **a** and **b** here", "Never log *a* and *b* here"),
            ("Never log `**the token**` here", "Never log `**the token**` here"),
            ("Never log ***the token*** here", "Never log ***the token*** here"),
            ("Never log **the *token* here**", "Never log **the *token* here**"),
            ("Never log \\**the token\\** here", "Never log \\**the token\\** here"),
            ("- Never log **the token**: it leaks", "- Never log **the token**: it leaks"),
            ("**Rule** \u2014 never log **Rule**", "**Rule** \u2014 never log *Rule*"),
        ],
    )
    def test_only_a_run_the_parse_pairs_and_the_atom_names_changes(self, line: str, after: str) -> None:
        assert self._run(line) == after

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    @pytest.mark.parametrize(
        ("line", "after"),
        [
            (
                "Never pass `**kwargs` and `**opts` through the helper.",
                "Never pass `**kwargs` and `**opts` through the helper.",
            ),
            ("Never edit [**z**](http://a.b/**z**) and **y**.", "Never edit [*z*](http://a.b/**z**) and *y*."),
            ("Never write `**x**` and then **x** again.", "Never write `**x**` and then *x* again."),
            ("Never touch the __database__ directly.", "Never touch the *database* directly."),
            ("Never wrap ***both*** here.", "Never wrap ***both*** here."),
        ],
    )
    def test_code_and_link_targets_are_never_rewritten_and_a_second_run_changes_nothing(
        self, line: str, after: str
    ) -> None:
        once = self._run(line)
        assert once == after
        assert self._run(once) == once

    @pytest.mark.unit
    @pytest.mark.subsys_heal
    def test_a_run_another_fixer_put_backticks_in_still_changes(self) -> None:
        line = "**Skills do not load `CLAUDE.md` files.** Others do."
        atom = _constraint_atom(1, "**Skills do not load CLAUDE.md files.** Others do.")
        lines = [line + "\n"]
        fix_bold_on_constraints([atom], lines)
        assert lines[0] == "*Skills do not load `CLAUDE.md` files.* Others do.\n"


class TestItalicWrapReadsTheParsedParagraph:
    @pytest.mark.unit
    @pytest.mark.subsys_heal
    @pytest.mark.parametrize(
        ("line", "sentence", "after"),
        [
            # a glob star pair inside the sentence would pair with the wrap's closing mark
            (
                "Never edit src/*.py or tests/*.py.",
                "Never edit src/*.py or tests/*.py.",
                "Never edit src/*.py or tests/*.py.",
            ),
            # a sentence inside a bold run, or holding the edge of one, is left whole
            ("**Never do x. Always do y.**", "Never do x.", "**Never do x. Always do y.**"),
            ("Never do *x. Always* do y.", "Never do *x.", "Never do *x. Always* do y."),
            # a star that is no delimiter pairs nothing
            ("Never multiply 2 * 3 here.", "Never multiply 2 * 3 here.", "*Never multiply 2 * 3 here.*"),
            ("Use `a*b`. Never push.", "Never push.", "Use `a*b`. *Never push.*"),
            # an emphasis run of another sentence is left as it is
            ("Run *fast*. Never push.", "Never push.", "Run *fast*. *Never push.*"),
        ],
    )
    def test_the_wrap_keeps_what_the_paragraph_reads(self, line: str, sentence: str, after: str) -> None:
        lines = [line + "\n"]
        fix_italic_constraints([_constraint_atom(1, sentence)], lines)
        assert lines == [after + "\n"]


def _heal_file(path: Path, line: int, text: str, tokens: list[str]) -> None:
    from reporails_cli.core.heal.mechanical_fixers import _fix_one_file

    _fix_one_file(path, [_atom(line, text, tokens)], {"format"}, False)


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_keeps_each_lines_own_ending(tmp_path: Path) -> None:
    """A CRLF, LF and lone-CR line each keep their ending after a fix."""
    f = tmp_path / "CLAUDE.md"
    f.write_bytes(b"# T\r\nRun pyproject.toml here.\r\nplain\nmore\rtext\n")
    _heal_file(f, 2, "Run pyproject.toml here.", ["pyproject.toml"])
    assert f.read_bytes() == b"# T\r\nRun `pyproject.toml` here.\r\nplain\nmore\rtext\n"


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize("sep", [chr(0x2028), chr(0x2029), "\x0c", "\x85", "\x1c", "\x0b"])
def test_heal_counts_only_newlines_as_lines(tmp_path: Path, sep: str) -> None:
    """A Unicode line separator in an earlier line does not shift the fixed line."""
    f = tmp_path / "CLAUDE.md"
    f.write_bytes(f"# T{sep}x\nRun pyproject.toml here.\n".encode())
    _heal_file(f, 2, "Run pyproject.toml here.", ["pyproject.toml"])
    assert f.read_bytes() == f"# T{sep}x\nRun `pyproject.toml` here.\n".encode()


def _tokenized(md: str) -> list[Atom]:
    from reporails_cli.core.mapper.parse import tokenize

    atoms = tokenize(md)
    for a in atoms:
        a.file_path = "CLAUDE.md"
    return atoms


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_the_format_fixer_reads_the_file_once_however_many_tokens_it_wraps(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.heal import mechanical_fixers as mf

    md = "\n".join(
        f"Edit src/app/main{i}.py and run_checks{i}() before you start working on the parser.\n" for i in range(12)
    )
    calls: list[int] = []
    real = mf.line_spans
    monkeypatch.setattr(mf, "line_spans", lambda content: calls.append(1) or real(content))
    lines = md.splitlines(keepends=True)
    fixes = fix_unformatted_code(_tokenized(md), lines)
    assert len(fixes) >= 12
    assert len(calls) == 1


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_the_bold_fixer_reads_the_file_once(monkeypatch: pytest.MonkeyPatch) -> None:
    from reporails_cli.core.heal import mechanical_fixers as mf

    texts = [f"Never log **the token{i}** or **the secret{i}** here" for i in range(8)]
    lines = [t + "\n" for t in texts]
    calls: list[int] = []
    real = mf.line_spans
    monkeypatch.setattr(mf, "line_spans", lambda content: calls.append(1) or real(content))
    fixes = fix_bold_on_constraints([_constraint_atom(n + 1, t) for n, t in enumerate(texts)], lines)
    assert len(fixes) == 8
    assert lines[3] == "Never log *the token3* or *the secret3* here\n"
    assert len(calls) == 1


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_a_token_inside_an_inline_html_attribute_is_left_alone_and_a_second_heal_changes_nothing() -> None:
    md = 'Show <img src="logo.png"> and edit logo.png before you start working on the parser.\n'
    lines = md.splitlines(keepends=True)
    fix_unformatted_code(_tokenized(md), lines)
    healed = "".join(lines)
    assert '<img src="logo.png">' in healed
    assert "`logo.png`" in healed  # the occurrence in prose is still wrapped
    again = healed.splitlines(keepends=True)
    assert fix_unformatted_code(_tokenized(healed), again) == []
    assert "".join(again) == healed


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    ("line", "token", "expected"),
    [
        ("See `src`/main.py now\n", "main.py", "See `src`/`main.py` now\n"),
        ("Run `c`~/x_y now.\n", "x_y", "Run `c`~/`x_y` now.\n"),
    ],
)
def test_a_wrap_never_starts_touching_a_backtick(line: str, token: str, expected: str) -> None:
    from reporails_cli.core.mapper.structure import line_spans

    lines = [line]
    fix_unformatted_code([_atom(1, line, [token])], lines)
    assert lines == [expected]
    assert line_spans("".join(lines)) == line_spans(expected)


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    ("line", "token"),
    [
        ("Never `c`**b***a* here", "b"),
        ("Never **c d**__u__ here", "c d"),
    ],
)
def test_a_bold_run_touching_another_emphasis_run_is_left_alone(line: str, token: str) -> None:
    lines = [line + "\n"]
    fixes = fix_bold_on_constraints([_constraint_atom(1, line)], lines)
    assert fixes == []
    assert lines == [line + "\n"]


@pytest.mark.unit
@pytest.mark.subsys_heal
@pytest.mark.parametrize(
    "line",
    [
        "See `src`/main.py now and run `c`~/x_y_z today.\n",
        "Edit `a`/b.py and `c`/d.py then `e`~/f_g next to **x**y_z.\n",
        "Read `a`**b.py** and a/b_c.py after `e`/h.py.\n",
    ],
)
def test_the_wrap_bookkeeping_agrees_with_a_fresh_parse(line: str) -> None:
    from reporails_cli.core.mapper.structure import line_spans

    lines = [line]
    tokens = [t for t in ("main.py", "x_y_z", "b.py", "d.py", "f_g", "b_c.py", "h.py") if t in line]
    fix_unformatted_code([_atom(1, line, tokens)], lines)
    assert line_spans("".join(lines)) == line_spans(lines[0])


@pytest.mark.unit
@pytest.mark.subsys_heal
def test_heal_leaves_a_file_that_is_not_utf8_unchanged(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    from reporails_cli.core.heal.mechanical_fixers import _fix_one_file

    raw = b"# Title\n\nNever use **rm -rf** on caf\xe9 files.\n"
    path = tmp_path / "CLAUDE.md"
    path.write_bytes(raw)
    with caplog.at_level("WARNING"):
        assert _fix_one_file(path, [], {"format", "bold"}, dry_run=False) == []
    assert path.read_bytes() == raw
    assert "not UTF-8" in caplog.text
