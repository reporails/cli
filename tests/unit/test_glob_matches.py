"""One glob matcher: `**` spans zero or more directories, anchored or trailing-segment matching."""

from __future__ import annotations

import pytest

from reporails_cli.core.platform.contract.glob_pattern import GLOB_CHARS, glob_matches


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("path", "pattern", "anchored", "expected"),
    [
        (".claude/agents/a/b/c.md", ".claude/agents/**/*.md", True, True),
        (".claude/agents/c.md", ".claude/agents/**/*.md", True, True),
        (".claude/agents/c.txt", ".claude/agents/**/*.md", True, False),
        ("pkg/.claude/agents/c.md", ".claude/agents/**/*.md", True, False),
        ("pkg/.claude/CLAUDE.md", ".claude/CLAUDE.md", True, False),
        (".claude/CLAUDE.md", ".claude/CLAUDE.md", True, True),
        ("pkg/AGENTS.md", "AGENTS.md", False, True),
        ("AGENTS.md", "**/AGENTS.md", False, True),
        ("a/b/AGENTS.md", "**/AGENTS.md", False, True),
        ("AGENTS.md.bak", "AGENTS.md", False, False),
        (".gemini/extensions", ".gemini/extensions/**", True, False),
        (".gemini/extensions/x/y.json", ".gemini/extensions/**", True, True),
        ("/etc/codex/skills/a/SKILL.md", "/etc/codex/skills/**/*.md", True, True),
        ("/home/me/.claude/CLAUDE.md", "/home/me/.claude/CLAUDE.md", False, True),
        ("x/CLAUDE.md", "/home/me/.claude/CLAUDE.md", False, False),
        ("a.md", "", False, False),
    ],
)
def test_glob_matches(path: str, pattern: str, anchored: bool, expected: bool) -> None:
    assert glob_matches(path, pattern, anchored=anchored) is expected


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("src/a/b.tsx", "src/**/*.{ts,tsx}", True),
        ("src/a/b.ts", "src/**/*.{ts,tsx}", True),
        ("src/a/b.js", "src/**/*.{ts,tsx}", False),
        ("src/x.md", "src/{x}.md", False),
        ("src/{x}.md", "src/{x}.md", True),
        ("src/{{x}}.md", "src/{{x}}.md", True),
    ],
)
def test_glob_matches_expands_a_brace_group_with_a_comma(path: str, pattern: str, expected: bool) -> None:
    assert glob_matches(path, pattern) is expected


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_brace_alternatives_expand_only_a_comma_group() -> None:
    from reporails_cli.core.platform.contract.glob_pattern import brace_alternatives

    assert brace_alternatives("*.{ts,tsx}") == ("*.ts", "*.tsx")
    assert brace_alternatives("{a,b}/{c,d}") == ("a/c", "a/d", "b/c", "b/d")
    assert brace_alternatives("{x}") == ("{x}",)
    assert brace_alternatives("{{x}}") == ("{{x}}",)


def _reference_match(parts: tuple[str, ...], pattern: tuple[str, ...]) -> bool:
    """The plain recursive reading of a glob: `**` spans zero or more segments, a trailing one at least one."""
    from fnmatch import fnmatchcase

    if not pattern:
        return not parts
    head, rest = pattern[0], pattern[1:]
    if head == "**":
        if not rest:
            return bool(parts)
        return any(_reference_match(parts[skip:], rest) for skip in range(len(parts) + 1))
    return bool(parts) and fnmatchcase(parts[0], head) and _reference_match(parts[1:], rest)


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_the_matcher_agrees_with_the_plain_recursive_reading_on_every_small_case() -> None:
    from itertools import product

    segments = ("a", "b", "*", "[ab]", "**")
    names = ("a", "b", "ab")
    patterns = [p for size in range(1, 5) for p in product(segments, repeat=size)]
    paths = [p for size in range(0, 4) for p in product(names, repeat=size)]
    for pattern in patterns:
        for parts in paths:
            expected = _reference_match(parts, pattern)
            assert glob_matches("/".join(parts), "/".join(pattern), anchored=True) is expected, (parts, pattern)


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("x/a/b/y", "**/a/b/**", True),
        ("a/x/b/y", "**/a/b/**", False),
        ("a/b", "**/a/b/**", False),
        ("a/b/a/b/c", "a/**/a/b/c", True),
        ("[a]/x", "[[]a]/*", True),
        ("a/x", "[[]a]/*", False),
        ("ab", "?", False),
        ("a", "?", True),
    ],
)
def test_runs_between_double_stars_escaped_brackets_and_single_characters(
    path: str, pattern: str, expected: bool
) -> None:
    assert _reference_match(tuple(path.split("/")), tuple(pattern.split("/"))) is expected
    assert glob_matches(path, pattern, anchored=True) is expected


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_prefix_matching_agrees_with_testing_every_leading_part_on_every_small_case() -> None:
    from itertools import product

    segments = ("a", "b", "*", "[ab]", "**")
    names = ("a", "b", "ab")
    patterns = [p for size in range(1, 4) for p in product(segments, repeat=size)]
    paths = [p for size in range(0, 4) for p in product(names, repeat=size)]
    for pattern in patterns:
        glob = "/".join(pattern)
        for parts in paths:
            expected = any(glob_matches("/".join(parts[:k]), glob, anchored=True) for k in range(1, len(parts) + 1))
            assert glob_matches("/".join(parts), glob, anchored=True, prefix=True) is expected, (parts, pattern)


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_a_brace_in_a_segment_without_a_comma_is_read_literally() -> None:
    assert frozenset("*?[{") == GLOB_CHARS
    assert glob_matches("a{x}b/c", "a{x}b/c", anchored=True)
    assert not glob_matches("axb/c", "a{x}b/c", anchored=True)
    assert glob_matches("{x}", "{x}")
    assert not glob_matches("x", "{x}")


@pytest.mark.unit
@pytest.mark.subsys_classify
@pytest.mark.parametrize(
    "text", ["plain", "[slug]", "a*b", "a?b", "{a,b}", "a,b", "{x}", "[!x]", "a]b", "[{]", "a-b.c"]
)
def test_escaped_text_matches_only_itself(text: str) -> None:
    from reporails_cli.core.platform.contract.glob_pattern import escape_glob

    assert glob_matches(text, escape_glob(text), anchored=True)
    assert glob_matches(f"p/{text}/x", "**/" + escape_glob(text) + "/**", anchored=True)
    for other in ("plain", "slug", "axb", "a", "b", "x", "a,b", "{a,b}", "!", "{"):
        assert glob_matches(other, escape_glob(text), anchored=True) is (other == text)


@pytest.mark.unit
@pytest.mark.subsys_classify
def test_an_escaped_brace_does_not_open_a_group() -> None:
    from reporails_cli.core.platform.contract.glob_pattern import brace_alternatives

    assert brace_alternatives("**/[{]a,b}") == ("**/[{]a,b}",)
    assert glob_matches("{a,b}", "**/[{]a,b}", anchored=True)
    assert not glob_matches("a", "**/[{]a,b}", anchored=True)
    assert glob_matches("x/y.ts", "x/*.{ts,tsx}", anchored=True)
